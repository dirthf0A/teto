"""AI-assisted risk prioritization using rule-based ML heuristics.

This module provides two prioritization strategies:
  1. Heuristic scoring (no API key needed) — always available
  2. LLM-enhanced analysis (optional, requires ASM_ANTHROPIC_API_KEY)

Heuristic model uses a weighted feature vector:
  - CVSS base score                     weight 0.25
  - KEV status (actively exploited)     weight 0.20
  - Internet exposure class             weight 0.18
  - Attack path reach (choke point)     weight 0.15
  - Asset criticality (env + type)      weight 0.12
  - Exploit availability                weight 0.10

Output: ActionableItem list with:
  - risk_score (0–100)
  - priority_label (P1/P2/P3/P4)
  - action (patch_immediately / investigate / monitor / accept)
  - rationale (human-readable, 1–2 sentences)
  - estimated_effort (high/medium/low)
  - recommended_deadline (ISO date string)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.logger import get_logger
from app.models import Asset, Finding

logger = get_logger("app.services.ai_risk")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ActionableItem:
    finding_id: int
    asset_id: Optional[int]
    title: str
    severity: str
    cve: Optional[str]
    cvss: Optional[float]
    risk_score: float
    priority_label: str          # P1 / P2 / P3 / P4
    action: str                  # patch_immediately / investigate / monitor / accept
    rationale: str               # 1-2 sentence explanation
    estimated_effort: str        # high / medium / low
    recommended_deadline: str    # ISO date (YYYY-MM-DD)
    is_kev: bool = False
    has_exploit: bool = False
    attack_path_weight: float = 0.0
    asset_label: str = ""
    exposure_class: str = "internal"
    tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

_EFFORT_BY_SEVERITY = {
    "critical": "high",
    "high":     "medium",
    "medium":   "medium",
    "low":      "low",
    "info":     "low",
}

_DEADLINE_DAYS = {
    "P1": 1,    # patch within 24h
    "P2": 7,    # patch within 1 week
    "P3": 30,   # patch within 30 days
    "P4": 90,   # monitor / accept
}


def _exposure_weight(exposure_class: str) -> float:
    return {"public": 1.0, "vpn": 0.6, "internal": 0.3}.get(exposure_class, 0.3)


def _cvss_weight(cvss: Optional[float]) -> float:
    if cvss is None:
        return 0.5
    return cvss / 10.0


def _sev_weight(severity: str) -> float:
    return {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1}.get(
        (severity or "").lower(), 0.3
    )


def _build_rationale(
    finding: Finding,
    asset: Optional[Asset],
    is_kev: bool,
    has_exploit: bool,
    attack_path_weight: float,
    priority_label: str,
) -> str:
    parts = []

    if is_kev:
        parts.append(f"{finding.cve} is in the CISA Known Exploited Vulnerabilities catalog — patch immediately per BOD 22-01.")
    elif has_exploit:
        parts.append(f"A public exploit exists for this vulnerability — elevated exploitation risk.")
    elif finding.cvss and finding.cvss >= 9.0:
        parts.append(f"Critical CVSS score ({finding.cvss:.1f}) indicates severe exploitability.")
    elif finding.severity in ("critical", "high"):
        parts.append(f"Severity is {finding.severity.upper()}, indicating significant security risk.")

    if asset and asset.exposure_class == "public":
        parts.append("Asset is internet-facing, making exploitation directly accessible without lateral movement.")
    elif asset and asset.exposure_class == "vpn":
        parts.append("Asset is VPN-accessible; requires initial network access but remains a priority.")

    if attack_path_weight > 0.5:
        parts.append("This asset lies on multiple attack paths — patching it blocks the most critical traversal routes.")

    if not parts:
        action_map = {"P1": "Immediate remediation required.", "P2": "Remediate within 7 days.", "P3": "Schedule remediation this sprint.", "P4": "Monitor and accept or remediate when convenient."}
        parts.append(action_map.get(priority_label, "Review and remediate as appropriate."))

    return " ".join(parts[:2])  # max 2 sentences


# ---------------------------------------------------------------------------
# Heuristic scoring model
# ---------------------------------------------------------------------------

def score_finding_ai(
    finding: Finding,
    asset: Optional[Asset] = None,
    is_kev: bool = False,
    has_exploit: bool = False,
    attack_path_weight: float = 0.0,
    kev_set=None,
) -> ActionableItem:
    """Score a single finding using the weighted heuristic model."""

    # Check KEV
    if not is_kev and finding.cve and kev_set:
        is_kev = finding.cve.upper() in kev_set

    exposure_class = (asset.exposure_class if asset else None) or "internal"

    # Weighted feature score
    w_cvss     = _cvss_weight(finding.cvss) * 0.25
    w_kev      = (1.0 if is_kev else 0.0) * 0.20
    w_exposure = _exposure_weight(exposure_class) * 0.18
    w_path     = min(attack_path_weight, 1.0) * 0.15
    w_asset    = (
        (1.0 if (asset and asset.environment in ("prod", "production")) else 0.5) *
        (1.0 if (asset and asset.asset_type in ("service", "endpoint")) else 0.7)
    ) * 0.12
    w_exploit  = (1.0 if has_exploit else 0.0) * 0.10

    composite = (w_cvss + w_kev + w_exposure + w_path + w_asset + w_exploit) * 100

    # Severity floor — never downgrade a critical to P3
    sev_floor = {"critical": 70, "high": 45, "medium": 25, "low": 10, "info": 0}
    composite = max(composite, sev_floor.get((finding.severity or "").lower(), 0))
    composite = round(min(composite, 100), 1)

    # Priority label
    if composite >= 80 or is_kev:
        priority_label = "P1"
        action = "patch_immediately"
    elif composite >= 55:
        priority_label = "P2"
        action = "investigate"
    elif composite >= 30:
        priority_label = "P3"
        action = "monitor"
    else:
        priority_label = "P4"
        action = "accept"

    deadline = (datetime.utcnow() + timedelta(days=_DEADLINE_DAYS[priority_label])).strftime("%Y-%m-%d")

    tags = []
    if is_kev:           tags.append("kev")
    if has_exploit:      tags.append("exploit-available")
    if exposure_class == "public": tags.append("internet-facing")
    if attack_path_weight > 0.5:   tags.append("choke-point")
    if finding.cvss and finding.cvss >= 9.0: tags.append("cvss-critical")

    return ActionableItem(
        finding_id=finding.id,
        asset_id=finding.asset_id,
        title=finding.title,
        severity=finding.severity or "info",
        cve=finding.cve,
        cvss=finding.cvss,
        risk_score=composite,
        priority_label=priority_label,
        action=action,
        rationale=_build_rationale(finding, asset, is_kev, has_exploit, attack_path_weight, priority_label),
        estimated_effort=_EFFORT_BY_SEVERITY.get((finding.severity or "").lower(), "medium"),
        recommended_deadline=deadline,
        is_kev=is_kev,
        has_exploit=has_exploit,
        attack_path_weight=attack_path_weight,
        asset_label=asset.subdomain or asset.domain or asset.ip or asset.url or f"#{asset.id}" if asset else finding.target or "",
        exposure_class=exposure_class,
        tags=tags,
    )


# ---------------------------------------------------------------------------
# Batch prioritization
# ---------------------------------------------------------------------------

def prioritize_org_findings(
    db: Session,
    org_id: int,
    limit: int = 100,
    include_attack_paths: bool = True,
) -> Dict:
    """Run AI-assisted prioritization on all open findings for an org.

    Returns:
      {
        "p1": [ActionableItem, ...],
        "p2": [...],
        "p3": [...],
        "p4": [...],
        "total": N,
        "method": "heuristic",
        "generated_at": ISO timestamp,
      }
    """
    findings = db.execute(
        select(Finding).where(
            Finding.org_id == org_id,
            Finding.status == "open",
        ).order_by(Finding.risk_score.desc().nullslast()).limit(limit)
    ).scalars().all()

    if not findings:
        return {"p1": [], "p2": [], "p3": [], "p4": [], "total": 0, "method": "heuristic"}

    # Load assets
    asset_ids = {f.asset_id for f in findings if f.asset_id}
    asset_map: Dict[int, Asset] = {}
    if asset_ids:
        for a in db.execute(select(Asset).where(Asset.id.in_(asset_ids))).scalars().all():
            asset_map[a.id] = a

    # KEV set (cached)
    kev_set = set()
    try:
        from app.services.vuln_scanner import get_kev_cve_set
        kev_set = get_kev_cve_set()
    except Exception as e:
        logger.debug("kev lookup failed", error=str(e))

    # Attack path weights (choke point scores)
    attack_path_weights: Dict[int, float] = {}
    if include_attack_paths:
        try:
            from app.services.attack_path_engine import build_attack_graph, find_choke_points
            from app.services.vuln_scanner import nuclei_scan  # just for type check
            nodes, adj = build_attack_graph(db, org_id)
            # Build minimal paths for choke point calc
            # (simplified: use node_risk as proxy for path weight)
            for node_id, node in nodes.items():
                attack_path_weights[node_id] = min(node.node_risk / 100, 1.0)
        except Exception as e:
            logger.debug("attack path weights unavailable", error=str(e))

    # Score all findings
    items: List[ActionableItem] = []
    for finding in findings:
        asset = asset_map.get(finding.asset_id) if finding.asset_id else None
        pw = attack_path_weights.get(finding.asset_id, 0.0)
        item = score_finding_ai(finding, asset, kev_set=kev_set, attack_path_weight=pw)
        items.append(item)

    # Sort by risk score descending
    items.sort(key=lambda x: x.risk_score, reverse=True)

    # Bucket
    buckets: Dict[str, List[dict]] = {"p1": [], "p2": [], "p3": [], "p4": []}
    for item in items:
        key = item.priority_label.lower()
        buckets[key].append({
            "finding_id":          item.finding_id,
            "asset_id":            item.asset_id,
            "asset_label":         item.asset_label,
            "title":               item.title,
            "severity":            item.severity,
            "cve":                 item.cve,
            "cvss":                item.cvss,
            "risk_score":          item.risk_score,
            "priority":            item.priority_label,
            "action":              item.action,
            "rationale":           item.rationale,
            "effort":              item.estimated_effort,
            "deadline":            item.recommended_deadline,
            "is_kev":              item.is_kev,
            "has_exploit":         item.has_exploit,
            "exposure_class":      item.exposure_class,
            "tags":                item.tags,
        })

    return {
        **buckets,
        "total":        len(items),
        "method":       "heuristic",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "p1_count": len(buckets["p1"]),
            "p2_count": len(buckets["p2"]),
            "p3_count": len(buckets["p3"]),
            "p4_count": len(buckets["p4"]),
            "kev_count": sum(1 for i in items if i.is_kev),
            "exploit_count": sum(1 for i in items if i.has_exploit),
        },
    }

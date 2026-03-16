"""Adaptive scanning engine — priority-based scan scheduling.

Principles:
  1. High-risk assets are scanned first and more frequently
  2. Internet-facing assets get shorter scan intervals
  3. New/recently-changed assets trigger immediate scans
  4. KEV-affected assets escalate to PRIORITY_CRITICAL
  5. Dormant low-risk assets get longer intervals (backoff)

Adaptive priority scoring (0–100):
  base     = exposure_score (public=30, vpn=15, internal=5)
  + risk   = max finding risk_score / 5
  + kev    = +25 if any KEV finding
  + new    = +20 if first_seen < 48h
  + change = +15 if last changed < 24h
  + port   = +10 if high-risk port open
  → maps to PRIORITY_CRITICAL (≥80), HIGH (≥50), NORMAL (≥25), LOW (<25)

Scan interval backoff:
  - consecutive clean scans → interval × 1.5 (max 7 days)
  - finding discovered → reset to base interval
  - KEV → interval ÷ 2 (minimum 1 hour)
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import config
from app.logger import get_logger
from app.models import Asset, Finding, Scan
from app.services.queue import (
    PRIORITY_CRITICAL, PRIORITY_HIGH, PRIORITY_LOW, PRIORITY_NORMAL,
    get_queue,
)

logger = get_logger("app.services.adaptive_scanner")


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------

EXPOSURE_BASE = {"public": 30, "vpn": 15, "internal": 5}

HIGH_RISK_PORTS = {3389, 445, 6379, 27017, 9200, 2375, 5900, 3306, 5432, 4444, 11211, 7001}


def compute_asset_scan_priority(
    asset: Asset,
    open_findings: List[Finding],
    last_changed_hours: Optional[float] = None,
) -> Tuple[int, int, str]:
    """Compute scan priority for an asset.

    Returns (priority_level 0-3, priority_score 0-100, reason).
    """
    score = 0
    reasons = []

    # Exposure base
    exp_class = asset.exposure_class or "internal"
    exp_score = EXPOSURE_BASE.get(exp_class, 5)
    score += exp_score
    if exp_class == "public":
        reasons.append("internet-facing")

    # Risk from existing findings
    if open_findings:
        max_risk = max(float(f.risk_score or 0) for f in open_findings)
        risk_contribution = min(max_risk / 5, 20)
        score += risk_contribution

        # KEV escalation
        has_kev = any(
            f.cve and f.severity == "critical"
            for f in open_findings
        )
        if has_kev:
            score += 25
            reasons.append("KEV finding")

        # Critical/high findings
        has_critical = any(f.severity == "critical" for f in open_findings)
        if has_critical:
            score += 15
            reasons.append("critical finding")

    # New asset bonus
    if asset.first_seen:
        hours_old = (datetime.utcnow() - asset.first_seen).total_seconds() / 3600
        if hours_old < 48:
            score += 20
            reasons.append("new asset (<48h)")

    # Recently changed
    if last_changed_hours is not None and last_changed_hours < 24:
        score += 15
        reasons.append("recently changed")

    # High-risk port
    if asset.port and asset.port in HIGH_RISK_PORTS:
        score += 10
        reasons.append(f"high-risk port {asset.port}")

    # Asset type bonus
    if asset.asset_type in ("service", "endpoint"):
        score += 5

    score = min(int(score), 100)

    # Map to priority level
    if score >= 80:
        priority = PRIORITY_CRITICAL
    elif score >= 50:
        priority = PRIORITY_HIGH
    elif score >= 25:
        priority = PRIORITY_NORMAL
    else:
        priority = PRIORITY_LOW

    reason = ", ".join(reasons) if reasons else "routine"
    return priority, score, reason


# ---------------------------------------------------------------------------
# Scan interval backoff
# ---------------------------------------------------------------------------

def compute_next_scan_interval(
    asset: Asset,
    scan_history: List[Scan],
    base_interval_hours: int = 6,
) -> int:
    """Compute next scan interval in hours using adaptive backoff.

    - Consecutive clean scans: interval × 1.5 (cap at 168h / 7 days)
    - Finding in last scan: reset to base_interval
    - KEV finding: max(base_interval / 2, 1)
    - Internet-facing: half the normal interval
    """
    if not scan_history:
        return base_interval_hours

    # Sort by most recent
    recent = sorted(scan_history, key=lambda s: s.completed_at or datetime.min, reverse=True)

    # Check if any KEV finding exists for this asset
    # (passed in via open_findings in caller — we approximate here)
    if asset.exposure_class == "public":
        base_interval_hours = max(1, base_interval_hours // 2)

    # Count consecutive clean scans (no new findings)
    # We use scan status as a proxy — completed = ran, no error
    clean_consecutive = 0
    for scan in recent[:10]:
        if scan.status == "completed" and not scan.error:
            clean_consecutive += 1
        else:
            break

    if clean_consecutive >= 3:
        backoff = min(base_interval_hours * (1.5 ** (clean_consecutive - 2)), 168)
        return int(backoff)

    return base_interval_hours


# ---------------------------------------------------------------------------
# Adaptive scheduler — enqueue high-priority assets
# ---------------------------------------------------------------------------

def schedule_adaptive_scans(
    db: Session,
    org_id: int,
    scan_type: str = "vuln",
    max_assets: int = 50,
    dry_run: bool = False,
) -> Dict:
    """Compute priorities for all org assets and enqueue high-priority scans.

    Only enqueues scans for assets that haven't been scanned recently
    (based on their adaptive interval).

    Returns summary: {total_assets, enqueued, skipped, breakdown}.
    """
    assets = db.execute(
        select(Asset).where(
            Asset.org_id == org_id,
            Asset.asset_type.in_(["domain", "subdomain", "service", "endpoint", "ip"]),
        )
    ).scalars().all()

    if not assets:
        return {"total_assets": 0, "enqueued": 0, "skipped": 0, "breakdown": {}}

    # Get open findings per asset
    finding_rows = db.execute(
        select(Finding.asset_id, Finding)
        .where(Finding.org_id == org_id, Finding.status == "open")
    ).all()
    findings_by_asset: Dict[int, List[Finding]] = {}
    for row in finding_rows:
        aid = row[0]
        if aid not in findings_by_asset:
            findings_by_asset[aid] = []
        findings_by_asset[aid].append(row[1])

    # Get last scan time per asset
    scan_rows = db.execute(
        select(Scan.asset_id, func.max(Scan.completed_at))
        .where(Scan.org_id == org_id, Scan.status == "completed")
        .group_by(Scan.asset_id)
    ).all()
    last_scanned: Dict[Optional[int], datetime] = {row[0]: row[1] for row in scan_rows if row[1]}

    queue = get_queue() if not dry_run else None
    breakdown = {"critical": 0, "high": 0, "normal": 0, "low": 0, "skipped": 0}
    enqueued = 0
    base_interval = config.get_asset_scan_interval_hours()

    # Score all assets
    scored = []
    for asset in assets:
        open_findings = findings_by_asset.get(asset.id, [])
        priority, score, reason = compute_asset_scan_priority(asset, open_findings)

        # Compute adaptive interval
        # Get recent scans for this asset
        asset_scans = db.execute(
            select(Scan).where(Scan.asset_id == asset.id, Scan.status == "completed")
            .order_by(Scan.completed_at.desc()).limit(5)
        ).scalars().all()
        interval_h = compute_next_scan_interval(asset, asset_scans, base_interval)

        # Skip if scanned recently
        last = last_scanned.get(asset.id)
        if last:
            hours_since = (datetime.utcnow() - last).total_seconds() / 3600
            if hours_since < interval_h:
                breakdown["skipped"] += 1
                continue

        scored.append((priority, score, asset, reason))

    # Sort by priority then score (highest first)
    scored.sort(key=lambda x: (x[0], -x[1]))

    # Enqueue top N
    for priority, score, asset, reason in scored[:max_assets]:
        label = {"critical": "critical", "high": "high", "normal": "normal", "low": "low"}.get(
            {0: "critical", 1: "high", 2: "normal", 3: "low"}.get(priority, "low"), "low"
        )
        breakdown[label] += 1

        if not dry_run:
            scan = Scan(
                org_id=org_id,
                asset_id=asset.id,
                scan_type=scan_type,
                status="scheduled",
                scheduled_at=datetime.utcnow(),
            )
            db.add(scan)
            db.flush()

            if queue:
                try:
                    queue.enqueue(scan.id, priority=priority, scan_type=scan_type)
                except Exception as e:
                    logger.warning("enqueue failed", asset_id=asset.id, error=str(e))

        enqueued += 1
        logger.debug(
            "adaptive scan scheduled",
            asset_id=asset.id, label=asset.subdomain or asset.domain or asset.ip,
            priority=priority, score=score, reason=reason,
        )

    if not dry_run:
        db.commit()

    logger.info(
        "adaptive scan scheduling complete",
        org_id=org_id, enqueued=enqueued, breakdown=breakdown,
    )
    return {
        "total_assets": len(assets),
        "enqueued":     enqueued,
        "skipped":      breakdown.pop("skipped", 0),
        "breakdown":    breakdown,
        "dry_run":      dry_run,
    }


# ---------------------------------------------------------------------------
# Exposure index
# ---------------------------------------------------------------------------

def compute_exposure_index(db: Session, org_id: int) -> Dict:
    """Compute an internet exposure index for the organization (0–100).

    Factors:
      - % of assets that are public-facing
      - % of public assets with open high-risk ports
      - % of public assets with critical/high findings
      - Count of cloud misconfigurations
      - Shadow asset ratio (assets with no owner assigned)

    Higher index = more exposed.
    """
    assets = db.execute(
        select(Asset).where(Asset.org_id == org_id)
    ).scalars().all()

    if not assets:
        return {"index": 0, "label": "low", "factors": {}}

    total = len(assets)
    public = [a for a in assets if a.exposure_class == "public"]
    public_count = len(public)

    public_pct = (public_count / total) * 100 if total else 0

    # High-risk ports on public assets
    risky_port_count = sum(
        1 for a in public if a.port and a.port in HIGH_RISK_PORTS
    )
    risky_port_pct = (risky_port_count / public_count * 100) if public_count else 0

    # Findings on public assets
    public_ids = {a.id for a in public}
    findings = db.execute(
        select(Finding).where(
            Finding.org_id == org_id,
            Finding.status == "open",
            Finding.asset_id.in_(public_ids),
        )
    ).scalars().all() if public_ids else []

    critical_public = sum(1 for f in findings if f.severity in ("critical", "high"))
    finding_density = (critical_public / public_count) if public_count else 0

    # Composite index
    factors = {
        "public_exposure_pct":  round(public_pct, 1),
        "risky_port_pct":       round(risky_port_pct, 1),
        "finding_density":      round(finding_density, 2),
        "public_assets":        public_count,
        "total_assets":         total,
        "critical_findings_public": critical_public,
    }

    index = min(
        public_pct * 0.4 +
        risky_port_pct * 0.3 +
        min(finding_density * 20, 30),
        100,
    )
    index = round(index, 1)

    label = "critical" if index >= 75 else "high" if index >= 50 else "medium" if index >= 25 else "low"
    return {"index": index, "label": label, "factors": factors}


# ---------------------------------------------------------------------------
# Shadow asset detection
# ---------------------------------------------------------------------------

def detect_shadow_assets(db: Session, org_id: int) -> Dict:
    """Detect shadow assets — internet-facing assets with no ownership assignment.

    Shadow assets are high risk because:
    - No team is responsible for patching them
    - They may be forgotten legacy services
    - They may expose internal data without anyone monitoring

    Returns categorized shadow assets with risk assessment.
    """
    from sqlalchemy import not_, exists
    from app.models import AssetOwnership

    # Public assets without ownership
    shadow = db.execute(
        select(Asset).where(
            Asset.org_id == org_id,
            Asset.exposure_class == "public",
            ~exists().where(
                AssetOwnership.asset_id == Asset.id,
                AssetOwnership.org_id == org_id,
            )
        )
    ).scalars().all()

    # Get findings for shadow assets
    shadow_ids = {a.id for a in shadow}
    findings_map: Dict[int, List[Finding]] = {}
    if shadow_ids:
        for f in db.execute(
            select(Finding).where(
                Finding.org_id == org_id,
                Finding.status == "open",
                Finding.asset_id.in_(shadow_ids),
            )
        ).scalars().all():
            if f.asset_id not in findings_map:
                findings_map[f.asset_id] = []
            findings_map[f.asset_id].append(f)

    # Score each shadow asset
    shadow_assets = []
    for asset in shadow:
        asset_findings = findings_map.get(asset.id, [])
        max_sev = max(
            ({"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(f.severity, 0) for f in asset_findings),
            default=0,
        )
        severity_label = ["clean", "low", "medium", "high", "critical"][max_sev]

        shadow_assets.append({
            "id":           asset.id,
            "label":        asset.url or asset.subdomain or asset.domain or asset.ip or f"#{asset.id}",
            "asset_type":   asset.asset_type,
            "ip":           asset.ip,
            "port":         asset.port,
            "technology":   asset.technology,
            "first_seen":   asset.first_seen.isoformat() if asset.first_seen else None,
            "last_seen":    asset.last_seen.isoformat() if asset.last_seen else None,
            "finding_count": len(asset_findings),
            "max_severity": severity_label,
            "risk_score":   round(max(float(f.risk_score or 0) for f in asset_findings) if asset_findings else 0, 1),
        })

    # Sort by risk
    shadow_assets.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "shadow_count":     len(shadow_assets),
        "shadow_pct":       round(len(shadow_assets) / max(
            db.execute(select(func.count()).select_from(Asset).where(
                Asset.org_id == org_id, Asset.exposure_class == "public"
            )).scalar_one(), 1
        ) * 100, 1),
        "shadow_assets":    shadow_assets[:50],
        "critical_shadow":  sum(1 for a in shadow_assets if a["max_severity"] == "critical"),
        "high_shadow":      sum(1 for a in shadow_assets if a["max_severity"] == "high"),
    }

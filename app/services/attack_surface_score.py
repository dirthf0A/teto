"""Attack Surface Score Engine.

Computes a single composite score (0-100) that quantifies the security
posture of an organization's attack surface at a point in time.

Score formula:
  base = 100
  deductions:
    - each exposed public service:   -2 (cap 20)
    - each critical vulnerability:   -8 (cap 40)
    - each high vulnerability:       -4 (cap 20)
    - each public cloud bucket:      -10 (cap 20)
    - each high-risk open port:      -5 (cap 15)
    - external domain count factor:  up to -5

  bonuses (reduce deductions):
    - findings remediated this month: +1 per 5 fixed (cap +10)
    - low exposure ratio:             up to +5

Higher score = worse posture (more attack surface).
Score label: 0-25=low  26-50=medium  51-75=high  76-100=critical

Trend is computed by comparing scores across consecutive scans.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import func as sa_func
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AttackSurfaceScore, Finding, Scan


# ── Score computation ──────────────────────────────────────────────────────

HIGH_RISK_PORTS = {21, 22, 23, 445, 1433, 2375, 3306, 3389, 5432,
                   5900, 5985, 6379, 8888, 9200, 11211, 27017}


def compute_score(db: Session, org_id: int, domain: Optional[str] = None,
                  scan_id: Optional[int] = None) -> AttackSurfaceScore:
    """Compute and persist attack surface score for an org/domain."""

    # Gather raw data
    asset_q = select(Asset).where(Asset.org_id == org_id)
    if domain:
        asset_q = asset_q.where(
            (Asset.domain == domain) | (Asset.subdomain.contains(domain))
        )
    assets = db.execute(asset_q).scalars().all()

    finding_q = select(Finding).where(
        Finding.org_id == org_id, Finding.status == "open"
    )
    findings = db.execute(finding_q).scalars().all()

    # Count contributors
    total_assets = len(assets)
    exposed_services = sum(
        1 for a in assets
        if a.exposure_class == "public" and a.asset_type in ("service", "subdomain", "endpoint")
    )
    critical_vulns = sum(1 for f in findings if f.severity == "critical")
    high_vulns = sum(1 for f in findings if f.severity == "high")
    public_buckets = sum(
        1 for a in assets
        if a.asset_type == "cloud" and a.service in ("s3", "gcs", "azure-storage")
    )
    open_high_risk_ports = sum(
        1 for a in assets
        if a.port and a.port in HIGH_RISK_PORTS and a.exposure_class == "public"
    )
    external_domains = sum(1 for a in assets if a.asset_type == "external_domain")

    # Fixed this month (bonus)
    month_ago = datetime.utcnow() - timedelta(days=30)
    fixed_this_month = db.execute(
        select(sa_func.count()).select_from(Finding).where(
            Finding.org_id == org_id,
            Finding.status == "fixed",
            Finding.last_seen >= month_ago,
        )
    ).scalar_one()

    # Deductions
    d_services = min(exposed_services * 2, 20)
    d_critical  = min(critical_vulns * 8, 40)
    d_high      = min(high_vulns * 4, 20)
    d_buckets   = min(public_buckets * 10, 20)
    d_ports     = min(open_high_risk_ports * 5, 15)
    d_external  = min(external_domains // 10, 5)  # every 10 external domains = -1

    total_deductions = d_services + d_critical + d_high + d_buckets + d_ports + d_external

    # Bonuses
    b_fixed = min(fixed_this_month // 5, 10)
    b_low_exposure = 5 if (exposed_services == 0 and total_assets > 0) else 0

    total_bonuses = b_fixed + b_low_exposure

    raw_score = min(max(total_deductions - total_bonuses, 0), 100)
    final_score = round(raw_score, 2)

    breakdown = {
        "deductions": {
            "exposed_services": d_services,
            "critical_vulns": d_critical,
            "high_vulns": d_high,
            "public_buckets": d_buckets,
            "high_risk_ports": d_ports,
            "external_domains": d_external,
        },
        "bonuses": {
            "fixed_this_month": b_fixed,
            "low_exposure": b_low_exposure,
        },
        "raw": total_deductions,
        "net": final_score,
    }

    record = AttackSurfaceScore(
        org_id=org_id,
        scan_id=scan_id,
        domain=domain,
        score=final_score,
        total_assets=total_assets,
        exposed_services=exposed_services,
        critical_vulns=critical_vulns,
        high_vulns=high_vulns,
        public_buckets=public_buckets,
        open_high_risk_ports=open_high_risk_ports,
        breakdown=json.dumps(breakdown),
        computed_at=datetime.utcnow(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def score_label(score: float) -> str:
    if score >= 76: return "critical"
    if score >= 51: return "high"
    if score >= 26: return "medium"
    return "low"


def score_color(score: float) -> str:
    return {"critical": "#ef4444", "high": "#f97316",
            "medium": "#eab308", "low": "#22c55e"}.get(score_label(score), "#94a3b8")


def get_score_history(db: Session, org_id: int,
                      domain: Optional[str] = None, limit: int = 30) -> List[dict]:
    """Return historical scores for trend chart."""
    q = select(AttackSurfaceScore).where(AttackSurfaceScore.org_id == org_id)
    if domain:
        q = q.where(AttackSurfaceScore.domain == domain)
    records = db.execute(q.order_by(AttackSurfaceScore.computed_at.asc()).limit(limit)).scalars().all()
    return [
        {
            "id": r.id,
            "score": r.score,
            "label": score_label(r.score),
            "total_assets": r.total_assets,
            "exposed_services": r.exposed_services,
            "critical_vulns": r.critical_vulns,
            "high_vulns": r.high_vulns,
            "public_buckets": r.public_buckets,
            "open_high_risk_ports": r.open_high_risk_ports,
            "breakdown": json.loads(r.breakdown or "{}"),
            "computed_at": r.computed_at.isoformat() if r.computed_at else None,
            "scan_id": r.scan_id,
        }
        for r in records
    ]


def get_latest_score(db: Session, org_id: int,
                     domain: Optional[str] = None) -> Optional[dict]:
    """Return the most recent score record."""
    q = select(AttackSurfaceScore).where(AttackSurfaceScore.org_id == org_id)
    if domain:
        q = q.where(AttackSurfaceScore.domain == domain)
    record = db.execute(q.order_by(AttackSurfaceScore.computed_at.desc()).limit(1)).scalar_one_or_none()
    if not record:
        return None
    history = get_score_history(db, org_id, domain=domain, limit=12)
    trend = "stable"
    delta = 0.0
    if len(history) >= 2:
        delta = round(history[-1]["score"] - history[-2]["score"], 2)
        if delta > 3:   trend = "degrading"
        elif delta < -3: trend = "improving"
    return {
        "score": record.score,
        "label": score_label(record.score),
        "color": score_color(record.score),
        "total_assets": record.total_assets,
        "exposed_services": record.exposed_services,
        "critical_vulns": record.critical_vulns,
        "high_vulns": record.high_vulns,
        "public_buckets": record.public_buckets,
        "open_high_risk_ports": record.open_high_risk_ports,
        "breakdown": json.loads(record.breakdown or "{}"),
        "computed_at": record.computed_at.isoformat() if record.computed_at else None,
        "trend": trend,
        "delta": delta,
        "history": history,
    }

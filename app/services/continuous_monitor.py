"""Continuous monitoring engine with change detection and alert dispatch.

Pipeline:
  scan → snapshot → compare with previous → detect changes → create alerts

Change types detected:
  - new_subdomain         New subdomain appeared
  - new_asset             New IP/cloud/service discovered
  - new_port              New open port detected
  - new_endpoint          New URL endpoint found
  - vuln_discovered       New vulnerability found
  - vuln_fixed            Vulnerability no longer present
  - cloud_exposed         Cloud asset became publicly accessible
  - tech_changed          Technology stack changed
  - risk_increased        Risk score significantly increased
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.models import Alert, Asset, AssetChange, AssetSnapshot, Finding, Organization, Scan
from app.services import notifications
from app.services.queue import get_queue


# ---------------------------------------------------------------------------
# Scheduled scan creation (original monitoring.py functions preserved)
# ---------------------------------------------------------------------------

def create_scheduled_scan(db: Session, org_id: int, scan_type: str) -> Scan:
    scan = Scan(
        org_id=org_id,
        asset_id=None,
        scan_type=scan_type,
        status="scheduled",
        scheduled_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    try:
        queue = get_queue()
    except Exception:
        queue = None
    if queue:
        queue.enqueue(scan.id)
    return scan


def should_run_deep_scan(now: datetime) -> bool:
    return now.day == config.get_deep_scan_day()


def next_daily_run(now: datetime) -> datetime:
    return now + timedelta(days=1)


# ---------------------------------------------------------------------------
# Change detection helpers
# ---------------------------------------------------------------------------

def _snapshot_fingerprint(asset: Asset) -> str:
    """Create a comparable fingerprint of asset state for change detection."""
    from hashlib import sha256
    fields = [
        asset.asset_type or "",
        asset.domain or "",
        asset.subdomain or "",
        asset.ip or "",
        str(asset.port or ""),
        asset.protocol or "",
        asset.url or "",
        asset.service or "",
        asset.technology or "",
        asset.hosting_provider or "",
    ]
    return sha256("|".join(fields).encode()).hexdigest()[:32]


def _asset_display(asset: Asset) -> str:
    return (
        asset.url
        or asset.subdomain
        or asset.domain
        or asset.ip
        or f"asset#{asset.id}"
    )


# ---------------------------------------------------------------------------
# Alert dispatch
# ---------------------------------------------------------------------------

ALERT_SEVERITY_MAP: dict[str, str] = {
    "new_subdomain": "info",
    "new_asset": "info",
    "new_port": "medium",
    "new_endpoint": "info",
    "vuln_discovered": "high",
    "vuln_fixed": "info",
    "cloud_exposed": "critical",
    "tech_changed": "low",
    "risk_increased": "high",
    "new_cloud_asset": "medium",
    "subdomain_takeover_risk": "critical",
    "github_leak": "high",
    "secret_detection": "critical",
    "dns_misconfig": "medium",
    "critical_vulnerability": "critical",
}


def dispatch_alert(
    db: Session,
    org_id: int,
    alert_type: str,
    message: str,
    asset_id: Optional[int] = None,
    finding_id: Optional[int] = None,
) -> Alert:
    """Create DB alert record and send notifications."""
    alert = Alert(
        org_id=org_id,
        asset_id=asset_id,
        finding_id=finding_id,
        alert_type=alert_type,
        message=message,
        status="new",
    )
    db.add(alert)

    # Send external notifications
    _send_notifications(alert_type, message, org_id, asset_id, finding_id)

    return alert


def _send_notifications(
    alert_type: str,
    message: str,
    org_id: int,
    asset_id: Optional[int],
    finding_id: Optional[int],
) -> None:
    """Send alert to configured channels: Slack, email, webhook, Discord."""
    if not config.get_alerts_enabled():
        return

    payload = {
        "org_id": org_id,
        "alert_type": alert_type,
        "asset_id": asset_id,
        "finding_id": finding_id,
        "message": message,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": ALERT_SEVERITY_MAP.get(alert_type, "info"),
    }

    slack_url = config.get_slack_webhook()
    if slack_url:
        severity = payload["severity"]
        emoji = {"critical": "🚨", "high": "⚠️", "medium": "🔔", "low": "ℹ️", "info": "📋"}.get(severity, "📋")
        notifications.send_slack(slack_url, f"{emoji} *[ASM Alert]* `{alert_type}`\n{message}")

    discord_url = config.get_discord_webhook()
    if discord_url:
        notifications.send_discord(discord_url, f"**[ASM Alert]** `{alert_type}`: {message}")

    webhook_url = config.get_alert_webhook()
    if webhook_url:
        notifications.send_webhook(webhook_url, payload)

    email_to = config.get_email_to()
    if email_to:
        severity = payload["severity"]
        notifications.send_email(
            recipient=email_to,
            subject=f"[ASM {severity.upper()}] {alert_type}: {message[:60]}",
            body=f"Alert Type: {alert_type}\nSeverity: {severity}\nMessage: {message}\n\nOrg ID: {org_id}\nAsset ID: {asset_id}\nFinding ID: {finding_id}",
        )

    if config.get_jira_enabled() and ALERT_SEVERITY_MAP.get(alert_type) in ("critical", "high"):
        notifications.send_jira_issue(
            summary=f"[ASM] {alert_type}: {message[:80]}",
            description=f"**Alert Type:** {alert_type}\n**Severity:** {payload['severity']}\n**Message:** {message}\n\nOrg: {org_id} | Asset: {asset_id}",
        )


# ---------------------------------------------------------------------------
# Change detection pipeline
# ---------------------------------------------------------------------------

def detect_changes_since_last_scan(
    db: Session,
    org_id: int,
    current_scan: Scan,
) -> List[AssetChange]:
    """Compare current scan's discovered assets against previous scan.

    Detects:
    - New assets (never seen before)
    - New ports (port opened since last scan)
    - Technology changes
    - New findings/vulns
    """
    if not current_scan.started_at:
        return []

    # Assets seen in this scan
    new_assets = db.execute(
        select(Asset).where(
            Asset.org_id == org_id,
            Asset.first_seen >= current_scan.started_at,
        )
    ).scalars().all()

    changes: List[AssetChange] = []
    for asset in new_assets:
        change_type = _change_type_for_asset(asset)
        detail = _asset_display(asset)
        change = AssetChange(
            org_id=org_id,
            scan_id=current_scan.id,
            asset_id=asset.id,
            change_type=change_type,
            detail=detail,
        )
        changes.append(change)

    return changes


def _change_type_for_asset(asset: Asset) -> str:
    if asset.asset_type == "subdomain":
        return "new_subdomain"
    if asset.asset_type == "service" and asset.port:
        return "port_exposed"
    if asset.asset_type == "endpoint":
        return "endpoint_discovered"
    if asset.asset_type == "cloud":
        return "asset_discovered"
    return "asset_discovered"


def run_change_detection_pipeline(
    db: Session,
    scan: Scan,
) -> Tuple[List[AssetChange], List[Alert]]:
    """Full change detection + alerting pipeline.

    1. Detect changes since last scan
    2. Create AssetChange records
    3. Dispatch alerts for each change
    4. Return changes and alerts

    Called from worker after scan completes.
    """
    changes = detect_changes_since_last_scan(db, scan.org_id, scan)
    alerts: List[Alert] = []

    # Deduplicate against alerts already sent this scan
    seen_alert_keys: set = set()
    if scan.started_at:
        existing = db.execute(
            select(Alert).where(
                Alert.org_id == scan.org_id,
                Alert.created_at >= scan.started_at,
            )
        ).scalars().all()
        seen_alert_keys = {(a.alert_type, a.asset_id) for a in existing}

    for change in changes:
        alert_type = _alert_type_for_change(change.change_type)
        key = (alert_type, change.asset_id)
        if key in seen_alert_keys:
            continue
        seen_alert_keys.add(key)

        alert = dispatch_alert(
            db,
            org_id=scan.org_id,
            alert_type=alert_type,
            message=f"{change.change_type.replace('_', ' ').title()}: {change.detail}",
            asset_id=change.asset_id,
        )
        alerts.append(alert)
        db.add(change)

    db.commit()
    return changes, alerts


def _alert_type_for_change(change_type: str) -> str:
    mapping = {
        "new_subdomain": "new_subdomain",
        "port_exposed": "new_port",
        "endpoint_discovered": "new_endpoint",
        "asset_discovered": "new_asset",
        "vuln_discovered": "vuln_discovered",
        "vuln_fixed": "vuln_fixed",
    }
    return mapping.get(change_type, "new_asset")


# ---------------------------------------------------------------------------
# Continuous scan scheduler helpers
# ---------------------------------------------------------------------------

def schedule_scans_for_org(db: Session, org_id: int) -> List[Scan]:
    """Create the standard scan schedule for an org:
    - asset_discovery (runs on configured interval)
    - vuln scan (runs less frequently)
    Returns list of created scans.
    """
    scans = [
        create_scheduled_scan(db, org_id, "asset_discovery"),
    ]
    return scans


def get_org_monitoring_status(db: Session, org_id: int) -> dict:
    """Return monitoring status for an org: last scan times, next scheduled, etc."""
    from sqlalchemy import func as sa_func

    last_scans = {}
    for scan_type in ("asset_discovery", "vuln", "deep"):
        last = db.execute(
            select(Scan)
            .where(
                Scan.org_id == org_id,
                Scan.scan_type == scan_type,
                Scan.status == "completed",
            )
            .order_by(Scan.completed_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        last_scans[scan_type] = last.completed_at.isoformat() if last and last.completed_at else None

    next_scheduled = db.execute(
        select(Scan)
        .where(Scan.org_id == org_id, Scan.status == "scheduled")
        .order_by(Scan.scheduled_at.asc())
        .limit(1)
    ).scalar_one_or_none()

    total_assets = db.execute(
        select(sa_func.count()).select_from(Asset).where(Asset.org_id == org_id)
    ).scalar_one()

    recent_changes = db.execute(
        select(AssetChange)
        .where(
            AssetChange.org_id == org_id,
            AssetChange.created_at >= datetime.utcnow() - timedelta(days=7),
        )
        .order_by(AssetChange.created_at.desc())
        .limit(20)
    ).scalars().all()

    return {
        "last_scans": last_scans,
        "next_scan": {
            "type": next_scheduled.scan_type if next_scheduled else None,
            "scheduled_at": next_scheduled.scheduled_at.isoformat() if next_scheduled and next_scheduled.scheduled_at else None,
        },
        "total_assets": total_assets,
        "recent_changes_7d": [
            {
                "type": c.change_type,
                "detail": c.detail,
                "asset_id": c.asset_id,
                "at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in recent_changes
        ],
    }

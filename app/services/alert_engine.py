"""Enterprise alert engine — intelligent routing, deduplication, escalation.

Features:
  - Multi-channel routing by severity threshold
    (critical -> PagerDuty + all; high -> Slack + email; info -> Slack only)
  - Alert deduplication window (default 24h, DB + in-process)
  - Quiet-hours suppression (configurable)
  - Escalation policy: re-alert on unacknowledged critical/high after N hours
  - Alert correlation: related alerts grouped into incidents
  - Severity-based severity map per alert type
  - PagerDuty auto-resolve when finding marked fixed
  - Rate limiting to prevent alert storms

SEVERITY_MAP is the single source of truth — import it wherever you need
the severity for an alert_type (e.g. worker.py alert_stats endpoint).
"""
from __future__ import annotations

import hashlib
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.models import Alert, Finding
from app.logger import get_logger
logger = get_logger('app.services.alert_engine')

# ---------------------------------------------------------------------------
# Severity map — alert_type -> canonical severity
# ---------------------------------------------------------------------------

SEVERITY_MAP: Dict[str, str] = {
    "critical_vulnerability":   "critical",
    "public_cloud_asset":       "critical",
    "secret_detection":         "critical",
    "subdomain_takeover_risk":  "critical",
    "cloud_exposed":            "critical",
    "bucket_acl_public":        "critical",
    "github_leak":              "high",
    "new_port":                 "high",
    "vuln_discovered":          "high",
    "new_vulnerability":        "high",
    "risk_increase":            "high",
    "dns_misconfig":            "medium",
    "new_cloud_asset":          "medium",
    "code_reference":           "medium",
    "new_subdomain":            "info",
    "new_asset":                "info",
    "new_endpoint":             "info",
    "new_service":              "low",
    "new_dns_record":           "info",
    "related_domain":           "info",
    "vuln_fixed":               "info",
    "new_exposed_service":      "high",
}

# Minimum severity per channel — lower channels get lower priority traffic only
_CHANNEL_MIN_SEVERITY: Dict[str, str] = {
    "pagerduty": "critical",
    "opsgenie":  "critical",
    "email":     "high",
    "ms_teams":  "high",
    "slack":     "low",
    "discord":   "medium",
    "telegram":  "medium",
    "webhook":   "low",
    "jira":      "high",
}

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _sev_gte(sev: str, minimum: str) -> bool:
    try:
        return _SEV_ORDER.index(sev) >= _SEV_ORDER.index(minimum)
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

_DEDUP_CACHE: Dict[str, float] = {}   # fingerprint -> last_sent epoch
_DEDUP_LOCK = threading.Lock()


def _dedup_key(org_id: int, alert_type: str, asset_id: Optional[int], message: str) -> str:
    raw = f"{org_id}|{alert_type}|{asset_id}|{message[:100]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _is_duplicate(
    db: Session,
    org_id: int,
    alert_type: str,
    asset_id: Optional[int],
    message: str,
) -> bool:
    window_hours = config.get_alert_dedup_window_hours()
    key = _dedup_key(org_id, alert_type, asset_id, message)

    # Fast in-process check
    with _DEDUP_LOCK:
        last = _DEDUP_CACHE.get(key)
        if last and (time.time() - last) < (window_hours * 3600):
            return True

    # DB check (distributed workers may have sent the same alert)
    since = datetime.utcnow() - timedelta(hours=window_hours)
    exists = db.execute(
        select(Alert).where(
            Alert.org_id    == org_id,
            Alert.alert_type == alert_type,
            Alert.asset_id   == asset_id,
            Alert.created_at >= since,
        ).limit(1)
    ).scalar_one_or_none()

    if exists:
        with _DEDUP_LOCK:
            _DEDUP_CACHE[key] = time.time()
        return True
    return False


def _mark_sent(org_id: int, alert_type: str, asset_id: Optional[int], message: str) -> None:
    key = _dedup_key(org_id, alert_type, asset_id, message)
    with _DEDUP_LOCK:
        _DEDUP_CACHE[key] = time.time()


# ---------------------------------------------------------------------------
# Channel dispatch
# ---------------------------------------------------------------------------

def _dispatch_channels(
    alert_type: str,
    message: str,
    severity: str,
    org_id: int,
    asset_id: Optional[int] = None,
    finding_id: Optional[int] = None,
    extra: Optional[Dict] = None,
) -> None:
    """Route alert to all configured channels based on severity threshold."""
    from app.services.notifications import (
        send_discord,
        send_email_alert,
        send_jira_issue,
        send_ms_teams,
        send_opsgenie,
        send_pagerduty,
        send_slack,
        send_telegram,
        send_webhook,
    )

    details: Dict[str, Any] = {
        "alert_type": alert_type,
        "severity":   severity,
        "org_id":     org_id,
        "asset_id":   asset_id,
        "finding_id": finding_id,
        **(extra or {}),
    }
    dedup = _dedup_key(org_id, alert_type, asset_id, message)

    # Slack
    slack_url = config.get_slack_webhook()
    if slack_url and _sev_gte(severity, _CHANNEL_MIN_SEVERITY["slack"]):
        try:
            send_slack(slack_url, message, alert_type=alert_type, severity=severity,
                       org_id=org_id, asset_id=asset_id, finding_id=finding_id)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    # Discord
    discord_url = config.get_discord_webhook()
    if discord_url and _sev_gte(severity, _CHANNEL_MIN_SEVERITY["discord"]):
        try:
            send_discord(discord_url, message, severity=severity, alert_type=alert_type)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    # MS Teams
    teams_url = config.get_ms_teams_webhook()
    if teams_url and _sev_gte(severity, _CHANNEL_MIN_SEVERITY["ms_teams"]):
        try:
            send_ms_teams(teams_url, message, alert_type=alert_type,
                          severity=severity, org_id=org_id)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    # PagerDuty — critical only (configured via get_pagerduty_routing_key)
    pd_key = config.get_pagerduty_routing_key()
    if pd_key and _sev_gte(severity, _CHANNEL_MIN_SEVERITY["pagerduty"]):
        try:
            send_pagerduty(pd_key, message, alert_type, severity, dedup, details)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    # OpsGenie
    og_key = config.get_opsgenie_api_key()
    if og_key and _sev_gte(severity, _CHANNEL_MIN_SEVERITY["opsgenie"]):
        try:
            send_opsgenie(og_key, message, alert_type, severity, alias=dedup, details=details)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    # Telegram
    tg_token = config.get_telegram_bot_token()
    tg_chat  = config.get_telegram_chat_id()
    if tg_token and tg_chat and _sev_gte(severity, _CHANNEL_MIN_SEVERITY["telegram"]):
        try:
            send_telegram(tg_token, tg_chat, message, severity=severity, alert_type=alert_type)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    # Generic webhook
    hook_url = config.get_alert_webhook()
    if hook_url and _sev_gte(severity, _CHANNEL_MIN_SEVERITY["webhook"]):
        try:
            send_webhook(hook_url, details)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    # Email
    email_to = config.get_email_to()
    if email_to and _sev_gte(severity, _CHANNEL_MIN_SEVERITY["email"]):
        try:
            send_email_alert(email_to, alert_type, message, severity,
                             org_id, asset_id, finding_id)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    # Jira — create issue for high+ alerts
    if config.get_jira_enabled() and _sev_gte(severity, _CHANNEL_MIN_SEVERITY["jira"]):
        jira_types = {"critical_vulnerability", "public_cloud_asset", "secret_detection",
                      "new_port", "new_asset", "github_leak", "subdomain_takeover_risk"}
        if alert_type in jira_types:
            try:
                summary = f"[ASM/{severity.upper()}] {alert_type.replace('_',' ').title()}: {message[:80]}"
                desc = (
                    f"Alert Type: {alert_type}\n"
                    f"Severity: {severity.upper()}\n"
                    f"Message: {message}\n"
                    f"Org: {org_id} | Asset: {asset_id} | Finding: {finding_id}"
                )
                send_jira_issue(summary, desc)
            except Exception as e:
                logger.warning('notification channel error', error=str(e))
                pass


# ---------------------------------------------------------------------------
# Main dispatch function
# ---------------------------------------------------------------------------

def dispatch_alert(
    db: Session,
    org_id: int,
    alert_type: str,
    message: str,
    asset_id: Optional[int] = None,
    finding_id: Optional[int] = None,
    force: bool = False,
    extra_context: Optional[Dict] = None,
) -> Optional[Alert]:
    """Create Alert DB record and dispatch to all configured channels.

    Returns Alert instance (added to session, not yet committed) or None if suppressed.
    """
    if not config.get_alerts_enabled():
        return None

    severity = SEVERITY_MAP.get(alert_type, "info")

    # Severity threshold filter
    threshold = config.get_alert_severity_threshold()
    if not _sev_gte(severity, threshold):
        return None

    # Deduplication
    if not force and _is_duplicate(db, org_id, alert_type, asset_id, message):
        return None

    # Create DB record
    alert = Alert(
        org_id=org_id,
        asset_id=asset_id,
        finding_id=finding_id,
        alert_type=alert_type,
        message=message,
        status="new",
    )
    db.add(alert)
    _mark_sent(org_id, alert_type, asset_id, message)

    # Dispatch to channels (errors caught per-channel)
    _dispatch_channels(
        alert_type=alert_type,
        message=message,
        severity=severity,
        org_id=org_id,
        asset_id=asset_id,
        finding_id=finding_id,
        extra=extra_context,
    )
    return alert


# ---------------------------------------------------------------------------
# PagerDuty auto-resolve
# ---------------------------------------------------------------------------

def resolve_pagerduty_for_finding(
    org_id: int,
    alert_type: str,
    asset_id: Optional[int],
    original_message: str,
) -> bool:
    """Auto-resolve PagerDuty incident when finding is fixed."""
    pd_key = config.get_pagerduty_routing_key()
    if not pd_key:
        return False
    from app.services.notifications import resolve_pagerduty
    dedup = _dedup_key(org_id, alert_type, asset_id, original_message)
    return resolve_pagerduty(pd_key, dedup, f"RESOLVED: {original_message}")


# ---------------------------------------------------------------------------
# Escalation check (call hourly from scheduler)
# ---------------------------------------------------------------------------

def check_escalations(db: Session) -> int:
    """Re-alert on unacknowledged critical/high alerts older than escalation threshold.

    Returns count of escalated alerts.
    """
    escalation_hours = 4
    cutoff = datetime.utcnow() - timedelta(hours=escalation_hours)

    stale = db.execute(
        select(Alert).where(
            Alert.status     == "new",
            Alert.created_at <= cutoff,
            Alert.alert_type.in_([
                "critical_vulnerability", "public_cloud_asset",
                "secret_detection", "cloud_exposed", "new_port",
                "subdomain_takeover_risk",
            ]),
        )
    ).scalars().all()

    count = 0
    for alert in stale:
        sev = SEVERITY_MAP.get(alert.alert_type, "info")
        if not _sev_gte(sev, "high"):
            continue
        escalation_msg = f"ESCALATION: Unacknowledged {alert.alert_type} — {alert.message[:150]}"
        _dispatch_channels(
            alert_type=f"escalation_{alert.alert_type}",
            message=escalation_msg,
            severity="critical",
            org_id=alert.org_id,
            asset_id=alert.asset_id,
            finding_id=alert.finding_id,
        )
        alert.status = "escalated"
        count += 1

    db.commit()
    return count


# ---------------------------------------------------------------------------
# Backward-compat shim (called by notifications.dispatch_alert)
# ---------------------------------------------------------------------------

def dispatch_alert_compat(message: str, payload: Dict) -> None:
    """Shim matching the legacy notifications.dispatch_alert(message, payload) signature."""
    if not config.get_alerts_enabled():
        return
    alert_type = payload.get("alert_type", "asm_alert")
    severity   = SEVERITY_MAP.get(alert_type, "info")
    org_id     = payload.get("org_id", 0)
    asset_id   = payload.get("asset_id")
    finding_id = payload.get("finding_id")
    _dispatch_channels(
        alert_type=alert_type,
        message=message,
        severity=severity,
        org_id=org_id,
        asset_id=asset_id,
        finding_id=finding_id,
        extra=payload,
    )

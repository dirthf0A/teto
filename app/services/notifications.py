"""Notification delivery — all channels in one place.

Channels supported:
  Email (SMTP / STARTTLS)
  Slack (rich attachments)
  Discord (embeds)
  Microsoft Teams (MessageCard)
  PagerDuty (Events API v2 — trigger / resolve)
  OpsGenie (Alert API v2)
  Telegram (Bot API)
  Jira (Create issue)
  Generic webhook (JSON POST)

All send functions return None on success and silently swallow errors
so a broken channel never crashes the scan pipeline.

Use dispatch_alert() for the unified entrypoint — it reads config and
routes to all enabled channels with severity-based filtering.
"""
from __future__ import annotations

import base64
import json
import smtplib
from app.logger import get_logger
logger = get_logger('app.services.notifications')
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

from app import config


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_SEV_COLOR = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#22c55e",
    "info":     "#64748b",
}
_SEV_EMOJI = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]",
    "medium":   "[MEDIUM]",
    "low":      "[LOW]",
    "info":     "[INFO]",
}


def _sev_gte(sev: str, minimum: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(sev) >= _SEVERITY_ORDER.index(minimum)
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _post_json(url: str, payload: Dict, headers: Optional[Dict] = None) -> bool:
    h = {"Content-Type": "application/json", "User-Agent": "ASMPlatform/2.0"}
    if headers:
        h.update(headers)
    try:
        data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, headers=h, method="POST")
        with urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def send_email(
    recipient: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
) -> None:
    host = config.get_smtp_host()
    if not host:
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = config.get_email_from() or "asm@example.com"
        msg["To"] = recipient
        msg.attach(MIMEText(body_text, "plain"))
        if body_html:
            msg.attach(MIMEText(body_html, "html"))

        srv = smtplib.SMTP(host, config.get_smtp_port(), timeout=10)
        if config.get_smtp_tls():
            srv.starttls()
        u, p = config.get_smtp_username(), config.get_smtp_password()
        if u and p:
            srv.login(u, p)
        srv.send_message(msg)
        srv.quit()
    except Exception as e:
        logger.warning('notification channel error', error=str(e))
        pass


def send_email_alert(
    recipient: str,
    alert_type: str,
    message: str,
    severity: str,
    org_id: int,
    asset_id: Optional[int] = None,
    finding_id: Optional[int] = None,
) -> None:
    color = _SEV_COLOR.get(severity, "#64748b")
    badge = _SEV_EMOJI.get(severity, "[INFO]")
    html = f"""
<html><body style="font-family:Arial,sans-serif;background:#f8fafc;padding:20px">
  <div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)">
    <div style="background:{color};padding:16px 20px;color:#fff">
      <h2 style="margin:0;font-size:18px">{badge} ASM Alert — {alert_type.replace('_',' ').title()}</h2>
      <p style="margin:4px 0 0;font-size:13px;opacity:.9">Severity: {severity.upper()}</p>
    </div>
    <div style="padding:20px">
      <p style="font-size:15px;color:#1e293b"><strong>Message:</strong><br>{message}</p>
      <table style="font-size:13px;color:#64748b;width:100%;border-collapse:collapse">
        <tr><td style="padding:4px 0;border-bottom:1px solid #f1f5f9"><b>Org</b></td><td>{org_id}</td></tr>
        {'<tr><td style="padding:4px 0;border-bottom:1px solid #f1f5f9"><b>Asset</b></td><td>' + str(asset_id) + '</td></tr>' if asset_id else ''}
        {'<tr><td style="padding:4px 0"><b>Finding</b></td><td>' + str(finding_id) + '</td></tr>' if finding_id else ''}
      </table>
    </div>
  </div>
</body></html>
"""
    text = f"{badge} [{severity.upper()}] {alert_type}: {message}\nOrg={org_id} Asset={asset_id} Finding={finding_id}"
    send_email(recipient, f"[ASM {severity.upper()}] {alert_type.replace('_',' ').title()}", text, html)


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

def send_slack(
    webhook_url: str,
    message: str,
    alert_type: str = "asm_alert",
    severity: str = "info",
    org_id: int = 0,
    asset_id: Optional[int] = None,
    finding_id: Optional[int] = None,
) -> bool:
    color = _SEV_COLOR.get(severity, "#64748b")
    badge = _SEV_EMOJI.get(severity, "[INFO]")
    fields = [
        {"title": "Alert Type", "value": f"`{alert_type}`", "short": True},
        {"title": "Severity",   "value": severity.upper(),  "short": True},
        {"title": "Org",        "value": str(org_id),       "short": True},
    ]
    if asset_id:
        fields.append({"title": "Asset", "value": str(asset_id), "short": True})
    if finding_id:
        fields.append({"title": "Finding", "value": str(finding_id), "short": True})

    payload = {
        "attachments": [{
            "color": color,
            "fallback": f"{badge} [{severity.upper()}] {message}",
            "title": f"{badge} {alert_type.replace('_',' ').title()}",
            "text": message,
            "fields": fields,
            "footer": "Teto ASM",
            "ts": int(__import__("time").time()),
        }]
    }
    return _post_json(webhook_url, payload)


# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------

def send_discord(webhook_url: str, message: str, severity: str = "info",
                 alert_type: str = "asm_alert") -> bool:
    badge = _SEV_EMOJI.get(severity, "[INFO]")
    color_int = int(_SEV_COLOR.get(severity, "#64748b").lstrip("#"), 16)
    payload = {
        "embeds": [{
            "title": f"{badge} {alert_type.replace('_',' ').title()}",
            "description": message,
            "color": color_int,
        }]
    }
    return _post_json(webhook_url, payload)


# ---------------------------------------------------------------------------
# Microsoft Teams
# ---------------------------------------------------------------------------

def send_ms_teams(webhook_url: str, message: str, alert_type: str = "asm_alert",
                  severity: str = "info", org_id: int = 0) -> bool:
    badge = _SEV_EMOJI.get(severity, "[INFO]")
    payload = {
        "@type":    "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": _SEV_COLOR.get(severity, "#64748b").lstrip("#"),
        "summary":  f"ASM Alert: {alert_type}",
        "sections": [{
            "activityTitle": f"{badge} **{alert_type.replace('_',' ').title()}**",
            "activitySubtitle": f"Severity: **{severity.upper()}** | Org: {org_id}",
            "activityText": message,
            "facts": [
                {"name": "Alert Type", "value": alert_type},
                {"name": "Severity",   "value": severity.upper()},
            ],
        }],
    }
    return _post_json(webhook_url, payload)


# ---------------------------------------------------------------------------
# PagerDuty
# ---------------------------------------------------------------------------

def send_pagerduty(
    routing_key: str,
    message: str,
    alert_type: str,
    severity: str,
    dedup_key: str,
    details: Optional[Dict] = None,
    action: str = "trigger",
) -> bool:
    pg_sev = {"critical": "critical", "high": "error", "medium": "warning",
              "low": "info", "info": "info"}.get(severity, "warning")
    payload = {
        "routing_key":  routing_key,
        "event_action": action,
        "dedup_key":    dedup_key,
        "payload": {
            "summary":  f"[ASM] {alert_type}: {message[:200]}",
            "severity": pg_sev,
            "source":   "teto-asm",
            "custom_details": details or {},
        },
    }
    return _post_json("https://events.pagerduty.com/v2/enqueue", payload)


def resolve_pagerduty(routing_key: str, dedup_key: str, message: str) -> bool:
    return send_pagerduty(routing_key, message, "resolved", "info", dedup_key, action="resolve")


# ---------------------------------------------------------------------------
# OpsGenie
# ---------------------------------------------------------------------------

def send_opsgenie(
    api_key: str,
    message: str,
    alert_type: str,
    severity: str,
    alias: str,
    details: Optional[Dict] = None,
) -> bool:
    og_priority = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P5"}
    payload = {
        "message":  f"[ASM] {alert_type}: {message[:130]}",
        "alias":    alias,
        "description": message,
        "priority": og_priority.get(severity, "P3"),
        "tags":     ["asm", "security", severity],
        "details":  details or {},
        "source":   "teto-asm",
    }
    return _post_json(
        "https://api.opsgenie.com/v2/alerts",
        payload,
        headers={"Authorization": f"GenieKey {api_key}"},
    )


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

def send_telegram(bot_token: str, chat_id: str, message: str,
                  severity: str = "info", alert_type: str = "asm_alert") -> bool:
    badge = _SEV_EMOJI.get(severity, "[INFO]")
    text = (
        f"{badge} <b>ASM Alert</b> — <code>{alert_type}</code>\n"
        f"<b>Severity:</b> {severity.upper()}\n"
        f"<b>Message:</b> {message[:400]}"
    )
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    return _post_json(url, {"chat_id": chat_id, "text": text, "parse_mode": "HTML"})


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------

def send_jira_issue(summary: str, description: str) -> bool:
    base  = config.get_jira_base()
    email = config.get_jira_email()
    token = config.get_jira_token()
    proj  = config.get_jira_project()
    itype = config.get_jira_issue_type()
    if not (base and email and token and proj):
        return False
    url = f"{base.rstrip('/')}/rest/api/3/issue"
    payload = {
        "fields": {
            "project":     {"key": proj},
            "summary":     summary,
            "description": description,
            "issuetype":   {"name": itype},
        }
    }
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    return _post_json(url, payload, headers={"Authorization": f"Basic {auth}"})


# ---------------------------------------------------------------------------
# Generic webhook
# ---------------------------------------------------------------------------

def send_webhook(url: str, payload: Dict) -> bool:
    return _post_json(url, payload)


# ---------------------------------------------------------------------------
# Unified dispatch (called by alert_engine.py)
# ---------------------------------------------------------------------------

def dispatch_alert(message: str, payload: Dict[str, Any]) -> None:
    """Dispatch alert to all configured channels.

    Delegates to alert_engine for rich formatting when available,
    falls back to direct channel calls.
    """
    try:
        from app.services.alert_engine import dispatch_alert_compat
        dispatch_alert_compat(message, payload)
        return
    except Exception as e:
        logger.warning('unexpected error', error=str(e))
        pass

    if not config.get_alerts_enabled():
        return

    alert_type = payload.get("alert_type", "asm_alert")
    severity   = payload.get("severity", "info")

    slack = config.get_slack_webhook()
    if slack:
        try:
            send_slack(slack, message, alert_type=alert_type, severity=severity)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    discord = config.get_discord_webhook()
    if discord:
        try:
            send_discord(discord, message, severity=severity, alert_type=alert_type)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    webhook = config.get_alert_webhook()
    if webhook:
        try:
            send_webhook(webhook, payload)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

    email_to = config.get_email_to()
    if email_to:
        try:
            send_email(email_to, f"[ASM] {alert_type}", message)
        except Exception as e:
            logger.warning('notification channel error', error=str(e))
            pass

"""SIEM / Threat Intelligence export adapters.

Supports:
  Splunk HEC     — HTTP Event Collector (JSON events)
  Elastic/SIEM   — Elasticsearch Bulk API (ECS-formatted)
  Loki           — Grafana Loki push API (log streams)
  Generic SIEM   — Configurable webhook with CEF or LEEF format
  CSV/NDJSON     — File exports for offline analysis

Event schema follows OCSF (Open Cybersecurity Schema Framework) conventions.

Config env vars:
  ASM_SPLUNK_HEC_URL        e.g. https://splunk.corp.com:8088/services/collector
  ASM_SPLUNK_HEC_TOKEN      Splunk HEC token
  ASM_SPLUNK_INDEX          optional, default: asm
  ASM_ELASTIC_URL           e.g. https://elastic.corp.com:9200
  ASM_ELASTIC_INDEX         optional, default: asm-findings
  ASM_ELASTIC_API_KEY       base64 encoded Elastic API key
  ASM_LOKI_URL              e.g. http://loki:3100/loki/api/v1/push
  ASM_SIEM_WEBHOOK_URL      generic webhook URL
  ASM_SIEM_FORMAT           cef | leef | json (default json)
"""
from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.logger import get_logger
from app.models import Alert, Asset, Finding

logger = get_logger("app.services.siem_export")


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _splunk_url() -> Optional[str]:
    return getattr(config, "get_splunk_hec_url", lambda: None)() or \
           __import__("os").getenv("ASM_SPLUNK_HEC_URL")

def _splunk_token() -> Optional[str]:
    return getattr(config, "get_splunk_hec_token", lambda: None)() or \
           __import__("os").getenv("ASM_SPLUNK_HEC_TOKEN")

def _splunk_index() -> str:
    return __import__("os").getenv("ASM_SPLUNK_INDEX", "asm")

def _elastic_url() -> Optional[str]:
    return __import__("os").getenv("ASM_ELASTIC_URL")

def _elastic_index() -> str:
    return __import__("os").getenv("ASM_ELASTIC_INDEX", "asm-findings")

def _elastic_api_key() -> Optional[str]:
    return __import__("os").getenv("ASM_ELASTIC_API_KEY")

def _loki_url() -> Optional[str]:
    return __import__("os").getenv("ASM_LOKI_URL")

def _siem_webhook_url() -> Optional[str]:
    return __import__("os").getenv("ASM_SIEM_WEBHOOK_URL")

def _siem_format() -> str:
    return __import__("os").getenv("ASM_SIEM_FORMAT", "json").lower()


# ---------------------------------------------------------------------------
# OCSF event builder
# ---------------------------------------------------------------------------

def _finding_to_ocsf(finding: Finding, asset: Optional[Asset] = None) -> Dict[str, Any]:
    """Convert Finding model to OCSF Detection Finding event."""
    now_iso = datetime.now(timezone.utc).isoformat()
    activity_name = "Create" if finding.status == "open" else "Update"
    sev_id = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
        (finding.severity or "").lower(), 0
    )
    return {
        "class_uid":       2004,             # Detection Finding
        "class_name":      "Detection Finding",
        "category_uid":    2,               # Findings
        "category_name":   "Findings",
        "activity_id":     1,
        "activity_name":   activity_name,
        "time":            int(time.time() * 1000),
        "start_time":      finding.first_seen.isoformat() if finding.first_seen else now_iso,
        "end_time":        finding.last_seen.isoformat() if finding.last_seen else now_iso,
        "severity_id":     sev_id,
        "severity":        (finding.severity or "info").capitalize(),
        "status":          finding.status,
        "status_id":       1 if finding.status == "open" else 2,
        "message":         finding.title,
        "finding": {
            "uid":         str(finding.id),
            "title":       finding.title,
            "desc":        finding.description,
            "types":       [finding.tool or "scanner"],
            "product_uid": "teto-asm",
        },
        "vulnerabilities": [{
            "cve":         {"uid": finding.cve} if finding.cve else {},
            "cvss":        {"base_score": finding.cvss} if finding.cvss else {},
            "severity":    (finding.severity or "").capitalize(),
            "title":       finding.title,
        }] if finding.cve or finding.cvss else [],
        "evidences": [{"data": finding.evidence}] if finding.evidence else [],
        "remediation": {"desc": "Patch or mitigate according to vendor guidance."},
        "risk_score":  finding.risk_score,
        "risk_level":  finding.severity,
        "metadata": {
            "version":    "1.1.0",
            "product": {
                "name":   "Teto ASM",
                "vendor": "Teto",
            },
            "log_provider": "teto-asm",
        },
        "observables": [{
            "name":       "finding.uid",
            "type_id":    10,
            "value":      str(finding.id),
        }],
        # Target asset
        "dst_endpoint": {
            "hostname":   asset.subdomain or asset.domain if asset else finding.target,
            "ip":         asset.ip if asset else None,
            "port":       finding.port or (asset.port if asset else None),
            "url":        asset.url if asset else finding.target,
        } if (asset or finding.target) else {},
        # Teto extras
        "asm": {
            "org_id":     finding.org_id,
            "asset_id":   finding.asset_id,
            "scan_id":    finding.scan_id,
            "tool":       finding.tool,
            "target":     finding.target,
            "exposure_score": finding.exposure_score,
            "asset_importance": finding.asset_importance,
        },
    }


def _finding_to_cef(finding: Finding) -> str:
    """Convert Finding to Common Event Format (CEF) string."""
    sev_map = {"critical": 10, "high": 8, "medium": 6, "low": 3, "info": 1}
    sev = sev_map.get((finding.severity or "").lower(), 0)
    name = (finding.title or "").replace("|", "\\|")
    ext = (
        f"src={finding.target or ''} "
        f"spt={finding.port or ''} "
        f"cs1={finding.cve or ''} cs1Label=CVE "
        f"cs2={finding.severity or ''} cs2Label=Severity "
        f"cn1={finding.risk_score or 0} cn1Label=RiskScore "
        f"cs3={finding.tool or ''} cs3Label=Tool "
        f"cs4={finding.status} cs4Label=Status"
    )
    return f"CEF:0|Teto|ASM|2.0|{finding.id}|{name}|{sev}|{ext}"


def _finding_to_leef(finding: Finding) -> str:
    """Convert Finding to Log Event Extended Format (LEEF 2.0) string."""
    attrs = {
        "devTime":   finding.first_seen.isoformat() if finding.first_seen else datetime.utcnow().isoformat(),
        "severity":  finding.severity or "info",
        "riskScore": str(finding.risk_score or 0),
        "cve":       finding.cve or "",
        "target":    finding.target or "",
        "tool":      finding.tool or "",
        "status":    finding.status,
        "orgId":     str(finding.org_id),
    }
    attr_str = "\t".join(f"{k}={v}" for k, v in attrs.items())
    return f"LEEF:2.0|Teto|ASM|2.0|{finding.id}|{attr_str}"


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

def _post_json(url: str, data: Any, headers: Optional[Dict] = None) -> bool:
    from urllib.request import Request, urlopen
    h = {"Content-Type": "application/json", "User-Agent": "ASMPlatform/2.0"}
    if headers:
        h.update(headers)
    try:
        body = json.dumps(data).encode("utf-8")
        req = __import__("urllib.request", fromlist=["Request"]).Request(url, body, h, method="POST")
        with urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        logger.warning("SIEM HTTP post failed", url=url, error=str(e))
        return False


# ---------------------------------------------------------------------------
# Splunk HEC
# ---------------------------------------------------------------------------

def export_to_splunk(
    findings: List[Finding],
    asset_map: Optional[Dict[int, Asset]] = None,
    batch_size: int = 100,
) -> Dict[str, int]:
    """Export findings to Splunk HEC in batches."""
    url = _splunk_url()
    token = _splunk_token()
    if not url or not token:
        return {"skipped": len(findings), "reason": "splunk_not_configured"}

    index = _splunk_index()
    sent = 0
    failed = 0
    headers = {"Authorization": f"Splunk {token}"}

    for i in range(0, len(findings), batch_size):
        batch = findings[i: i + batch_size]
        events = []
        for f in batch:
            asset = asset_map.get(f.asset_id) if asset_map and f.asset_id else None
            events.append({
                "index":      index,
                "sourcetype": "teto:asm:finding",
                "source":     "teto-asm",
                "event":      _finding_to_ocsf(f, asset),
            })
        payload = "\n".join(json.dumps(e) for e in events)
        try:
            from urllib.request import Request, urlopen
            body = payload.encode("utf-8")
            req = Request(url, body, {**headers, "Content-Type": "application/json"}, method="POST")
            with urlopen(req, timeout=15) as resp:
                if 200 <= resp.status < 300:
                    sent += len(batch)
                else:
                    failed += len(batch)
        except Exception as e:
            logger.warning("splunk batch failed", error=str(e), batch_size=len(batch))
            failed += len(batch)

    logger.info("splunk export complete", sent=sent, failed=failed)
    return {"sent": sent, "failed": failed}


# ---------------------------------------------------------------------------
# Elasticsearch / Elastic SIEM
# ---------------------------------------------------------------------------

def export_to_elastic(
    findings: List[Finding],
    asset_map: Optional[Dict[int, Asset]] = None,
    batch_size: int = 200,
) -> Dict[str, int]:
    """Export findings to Elasticsearch using Bulk API."""
    url = _elastic_url()
    if not url:
        return {"skipped": len(findings), "reason": "elastic_not_configured"}

    index = _elastic_index()
    api_key = _elastic_api_key()
    headers: Dict[str, str] = {"Content-Type": "application/x-ndjson"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    sent = 0
    failed = 0

    for i in range(0, len(findings), batch_size):
        batch = findings[i: i + batch_size]
        lines = []
        for f in batch:
            asset = asset_map.get(f.asset_id) if asset_map and f.asset_id else None
            meta = {"index": {"_index": index, "_id": str(f.id)}}
            doc = _finding_to_ocsf(f, asset)
            lines.append(json.dumps(meta))
            lines.append(json.dumps(doc))
        body = "\n".join(lines) + "\n"
        try:
            from urllib.request import Request, urlopen
            req = Request(
                f"{url.rstrip('/')}/_bulk",
                body.encode("utf-8"),
                headers,
                method="POST",
            )
            with urlopen(req, timeout=20) as resp:
                result = json.loads(resp.read().decode())
                if result.get("errors"):
                    failed += sum(1 for item in result.get("items", []) if "error" in (item.get("index") or {}))
                    sent += len(batch) - failed
                else:
                    sent += len(batch)
        except Exception as e:
            logger.warning("elastic batch failed", error=str(e))
            failed += len(batch)

    logger.info("elastic export complete", sent=sent, failed=failed)
    return {"sent": sent, "failed": failed}


# ---------------------------------------------------------------------------
# Loki
# ---------------------------------------------------------------------------

def export_to_loki(findings: List[Finding]) -> Dict[str, int]:
    """Export findings as log streams to Grafana Loki."""
    url = _loki_url()
    if not url:
        return {"skipped": len(findings), "reason": "loki_not_configured"}

    # Group by severity label
    streams: Dict[str, List] = {}
    for f in findings:
        sev = f.severity or "info"
        key = f'{{"severity":"{sev}","source":"teto-asm","org_id":"{f.org_id}"}}'
        if key not in streams:
            streams[key] = []
        ts_ns = str(int((f.first_seen.timestamp() if f.first_seen else time.time()) * 1e9))
        streams[key].append([ts_ns, json.dumps({
            "finding_id":   f.id,
            "title":        f.title,
            "severity":     sev,
            "cve":          f.cve,
            "target":       f.target,
            "risk_score":   f.risk_score,
        })])

    payload = {"streams": [
        {"stream": json.loads(k), "values": v}
        for k, v in streams.items()
    ]}
    ok = _post_json(f"{url.rstrip('/')}/loki/api/v1/push", payload)
    sent = len(findings) if ok else 0
    logger.info("loki export complete", sent=sent, streams=len(streams))
    return {"sent": sent, "streams": len(streams)}


# ---------------------------------------------------------------------------
# Generic SIEM webhook
# ---------------------------------------------------------------------------

def export_to_webhook(
    findings: List[Finding],
    asset_map: Optional[Dict[int, Asset]] = None,
) -> Dict[str, int]:
    """Export findings to a generic SIEM webhook."""
    url = _siem_webhook_url()
    if not url:
        return {"skipped": len(findings), "reason": "webhook_not_configured"}

    fmt = _siem_format()
    sent = 0

    if fmt == "cef":
        for f in findings:
            if _post_json(url, {"cef": _finding_to_cef(f)}):
                sent += 1
    elif fmt == "leef":
        for f in findings:
            if _post_json(url, {"leef": _finding_to_leef(f)}):
                sent += 1
    else:  # json / ocsf
        for f in findings:
            asset = asset_map.get(f.asset_id) if asset_map and f.asset_id else None
            if _post_json(url, _finding_to_ocsf(f, asset)):
                sent += 1

    logger.info("webhook export complete", sent=sent, format=fmt)
    return {"sent": sent, "format": fmt}


# ---------------------------------------------------------------------------
# CSV / NDJSON file export
# ---------------------------------------------------------------------------

def findings_to_csv(findings: List[Finding]) -> str:
    """Serialize findings to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "org_id", "asset_id", "severity", "title", "cve",
        "cvss", "risk_score", "status", "target", "tool",
        "first_seen", "last_seen",
    ])
    for f in findings:
        writer.writerow([
            f.id, f.org_id, f.asset_id, f.severity, f.title,
            f.cve or "", f.cvss or "", f.risk_score or "",
            f.status, f.target or "", f.tool or "",
            f.first_seen.isoformat() if f.first_seen else "",
            f.last_seen.isoformat() if f.last_seen else "",
        ])
    return output.getvalue()


def findings_to_ndjson(
    findings: List[Finding],
    asset_map: Optional[Dict[int, Asset]] = None,
) -> str:
    """Serialize findings to NDJSON (one OCSF event per line)."""
    lines = []
    for f in findings:
        asset = asset_map.get(f.asset_id) if asset_map and f.asset_id else None
        lines.append(json.dumps(_finding_to_ocsf(f, asset)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DB-backed bulk export
# ---------------------------------------------------------------------------

def export_org_findings(
    db: Session,
    org_id: int,
    targets: List[str],
    since_hours: int = 24,
) -> Dict[str, Any]:
    """Export recent findings for an org to all configured SIEM targets.

    Returns summary of results per configured destination.
    """
    from datetime import timedelta
    since = datetime.utcnow() - timedelta(hours=since_hours)

    findings = db.execute(
        select(Finding).where(
            Finding.org_id == org_id,
            Finding.created_at >= since,
        ).order_by(Finding.id.desc()).limit(5000)
    ).scalars().all()

    if not findings:
        return {"findings": 0}

    asset_ids = {f.asset_id for f in findings if f.asset_id}
    asset_map: Dict[int, Asset] = {}
    if asset_ids:
        for a in db.execute(select(Asset).where(Asset.id.in_(asset_ids))).scalars().all():
            asset_map[a.id] = a

    results: Dict[str, Any] = {"findings": len(findings)}

    if _splunk_url():
        results["splunk"] = export_to_splunk(findings, asset_map)
    if _elastic_url():
        results["elastic"] = export_to_elastic(findings, asset_map)
    if _loki_url():
        results["loki"] = export_to_loki(findings)
    if _siem_webhook_url():
        results["webhook"] = export_to_webhook(findings, asset_map)

    logger.info("org SIEM export complete", org_id=org_id, **results)
    return results

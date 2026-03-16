"""Asset History & Timeline Engine — full lifecycle tracking for every asset.

Tracks and visualizes:
  - Asset discovery and disappearance
  - Port open/close events
  - Technology stack changes (before/after diff)
  - Vulnerability lifecycle (found → triaged → fixed)
  - Exposure class changes (internal → public)
  - Risk score trajectory over time
  - Ownership changes (hosting provider, ASN)
  - Screenshot diffs (if screenshot tool integrated)

Timeline event model:
  Every event has:
    - timestamp
    - event_type (one of 30+ types)
    - severity (for display color)
    - asset_id + asset_label
    - detail (human-readable)
    - before_state / after_state (for diff events)
    - source (which scan or tool produced it)
    - MITRE technique (if applicable)

Risk trajectory:
  We store risk score snapshots per scan and compute:
    - Delta: change since last snapshot
    - 30-day rolling risk score
    - Trend: improving / degrading / stable

Diff engine:
  Compares two asset snapshots field-by-field and emits structured diffs,
  including technology changes and open port changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func as sa_func
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetChange, AssetSnapshot, Finding, Scan
from app.logger import get_logger
logger = get_logger('app.services.asset_history')


# ── Event type catalog ─────────────────────────────────────────────────────

EVENT_TYPES = {
    # Discovery
    "asset_first_seen":      {"label": "Asset Discovered",         "icon": "🔍", "sev": "info"},
    "asset_disappeared":     {"label": "Asset No Longer Reachable","icon": "👻", "sev": "medium"},
    "asset_reappeared":      {"label": "Asset Reappeared",         "icon": "🔄", "sev": "low"},
    "subdomain_appeared":    {"label": "Subdomain Appeared",       "icon": "🌐", "sev": "info"},
    "subdomain_disappeared": {"label": "Subdomain Disappeared",    "icon": "🌐", "sev": "low"},
    # Network
    "port_opened":           {"label": "Port Opened",              "icon": "🔓", "sev": "medium"},
    "port_closed":           {"label": "Port Closed",              "icon": "🔒", "sev": "info"},
    "ip_changed":            {"label": "IP Address Changed",       "icon": "🔀", "sev": "medium"},
    "cdn_changed":           {"label": "CDN Provider Changed",     "icon": "☁️", "sev": "low"},
    "hosting_changed":       {"label": "Hosting Provider Changed", "icon": "🏢", "sev": "low"},
    # Security
    "vuln_found":            {"label": "Vulnerability Found",      "icon": "🐛", "sev": "high"},
    "vuln_fixed":            {"label": "Vulnerability Fixed",      "icon": "✅", "sev": "info"},
    "vuln_severity_up":      {"label": "Severity Escalated",       "icon": "⬆️", "sev": "critical"},
    "kev_added":             {"label": "CVE Added to CISA KEV",    "icon": "🚨", "sev": "critical"},
    "exploit_published":     {"label": "Public Exploit Available", "icon": "💀", "sev": "critical"},
    "secret_found":          {"label": "Secret Detected",         "icon": "🔑", "sev": "critical"},
    "takeover_risk":         {"label": "Takeover Risk Detected",  "icon": "⚠️", "sev": "critical"},
    # Exposure
    "exposure_increased":    {"label": "Exposure Increased",       "icon": "📡", "sev": "high"},
    "exposure_decreased":    {"label": "Exposure Decreased",       "icon": "🛡️", "sev": "info"},
    "bucket_exposed":        {"label": "Cloud Bucket Exposed",     "icon": "🪣", "sev": "critical"},
    # Technology
    "tech_added":            {"label": "Technology Added",         "icon": "⚙️", "sev": "low"},
    "tech_removed":          {"label": "Technology Removed",       "icon": "🗑️", "sev": "info"},
    "tech_version_changed":  {"label": "Technology Version Changed","icon":"🔧", "sev": "medium"},
    # Risk score
    "risk_spike":            {"label": "Risk Score Spiked",        "icon": "📈", "sev": "high"},
    "risk_improved":         {"label": "Risk Score Improved",      "icon": "📉", "sev": "info"},
    # Scan lifecycle
    "scan_started":          {"label": "Scan Started",             "icon": "🔬", "sev": "info"},
    "scan_completed":        {"label": "Scan Completed",           "icon": "✔️", "sev": "info"},
    # Threat intel
    "ti_malicious":          {"label": "Flagged as Malicious",     "icon": "🦠", "sev": "critical"},
    "ti_suspect":            {"label": "Threat Intel Suspect",     "icon": "⚠️", "sev": "high"},
    # Generic
    "change_detected":       {"label": "Change Detected",          "icon": "📌", "sev": "info"},
}


@dataclass
class TimelineEvent:
    id: str
    timestamp: str             # ISO format
    event_type: str
    label: str
    icon: str
    severity: str              # info / low / medium / high / critical
    asset_id: Optional[int]
    asset_label: str
    detail: str
    before_state: Optional[Dict] = None
    after_state: Optional[Dict] = None
    source: str = ""
    mitre_technique: Optional[str] = None
    finding_id: Optional[int] = None
    scan_id: Optional[int] = None
    extra: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "label": self.label,
            "icon": self.icon,
            "severity": self.severity,
            "asset_id": self.asset_id,
            "asset_label": self.asset_label,
            "detail": self.detail,
            "before_state": self.before_state,
            "after_state": self.after_state,
            "source": self.source,
            "mitre_technique": self.mitre_technique,
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "extra": self.extra,
        }


@dataclass
class RiskSnapshot:
    scan_id: int
    timestamp: str
    risk_score: float
    open_findings: int
    critical_findings: int
    exposure_class: str

    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "open_findings": self.open_findings,
            "critical_findings": self.critical_findings,
            "exposure_class": self.exposure_class,
        }


@dataclass
class AssetDiff:
    """Field-by-field diff between two asset states."""
    field: str
    before: Any
    after: Any
    change_type: str   # "added" | "removed" | "modified"

    def to_dict(self) -> Dict:
        return {"field": self.field, "before": self.before, "after": self.after, "type": self.change_type}


# ── Helpers ────────────────────────────────────────────────────────────────

def _asset_display(asset: Asset) -> str:
    return asset.url or asset.subdomain or asset.domain or asset.ip or f"asset#{asset.id}"


def _event_meta(event_type: str) -> Tuple[str, str, str]:
    meta = EVENT_TYPES.get(event_type, {"label": event_type.replace("_", " ").title(), "icon": "📌", "sev": "info"})
    return meta["label"], meta["icon"], meta["sev"]


def _make_event(
    event_type: str,
    asset: Optional[Asset],
    detail: str,
    timestamp: Optional[datetime] = None,
    finding_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    before: Optional[Dict] = None,
    after: Optional[Dict] = None,
    mitre: Optional[str] = None,
    source: str = "",
    extra: Optional[Dict] = None,
) -> TimelineEvent:
    import hashlib, time as _time
    label, icon, sev = _event_meta(event_type)
    ts = (timestamp or datetime.utcnow()).isoformat()
    raw_id = f"{event_type}|{asset.id if asset else 0}|{ts}|{detail[:40]}"
    evt_id = hashlib.sha256(raw_id.encode()).hexdigest()[:12]
    return TimelineEvent(
        id=evt_id,
        timestamp=ts,
        event_type=event_type,
        label=label,
        icon=icon,
        severity=sev,
        asset_id=asset.id if asset else None,
        asset_label=_asset_display(asset) if asset else "",
        detail=detail,
        before_state=before,
        after_state=after,
        source=source,
        mitre_technique=mitre,
        finding_id=finding_id,
        scan_id=scan_id,
        extra=extra or {},
    )


# ── Asset diff engine ──────────────────────────────────────────────────────

def diff_asset_states(before: Dict, after: Dict) -> List[AssetDiff]:
    """Compare two asset state dicts and return structured diffs."""
    diffs: List[AssetDiff] = []
    fields_to_track = [
        "ip", "port", "protocol", "service", "technology",
        "hosting_provider", "cdn", "country", "exposure_class", "asn",
    ]
    for f in fields_to_track:
        bv = before.get(f)
        av = after.get(f)
        if bv == av:
            continue
        if bv is None and av is not None:
            diffs.append(AssetDiff(field=f, before=None, after=av, change_type="added"))
        elif bv is not None and av is None:
            diffs.append(AssetDiff(field=f, before=bv, after=None, change_type="removed"))
        else:
            diffs.append(AssetDiff(field=f, before=bv, after=av, change_type="modified"))

    # Technology set diff
    before_techs = set(t.strip() for t in (before.get("technology") or "").split(",") if t.strip())
    after_techs  = set(t.strip() for t in (after.get("technology") or "").split(",") if t.strip())
    for added_tech in (after_techs - before_techs):
        diffs.append(AssetDiff(field="technology", before=None, after=added_tech, change_type="added"))
    for removed_tech in (before_techs - after_techs):
        diffs.append(AssetDiff(field="technology", before=removed_tech, after=None, change_type="removed"))

    return diffs


def snapshot_to_dict(snapshot: AssetSnapshot) -> Dict:
    return {
        "asset_type": snapshot.asset_type,
        "domain": snapshot.domain,
        "subdomain": snapshot.subdomain,
        "ip": snapshot.ip,
        "port": snapshot.port,
        "protocol": snapshot.protocol,
        "url": snapshot.url,
        "service": snapshot.service,
    }


# ── Core timeline functions ────────────────────────────────────────────────

def get_asset_timeline(
    db: Session,
    org_id: int,
    asset_id: int,
    days: int = 90,
    include_scan_events: bool = True,
) -> List[TimelineEvent]:
    """Full chronological timeline for a single asset.

    Combines:
    - AssetChange records
    - Finding lifecycle (found, severity changes, fixed)
    - Snapshot diffs (port opens, tech changes, IP changes)
    - Scan events (started, completed)
    """
    since = datetime.utcnow() - timedelta(days=days)
    events: List[TimelineEvent] = []

    asset = db.execute(select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)).scalar_one_or_none()
    if not asset:
        return []

    # 1. AssetChange records
    changes = db.execute(
        select(AssetChange).where(
            AssetChange.org_id == org_id,
            AssetChange.asset_id == asset_id,
            AssetChange.created_at >= since,
        ).order_by(AssetChange.created_at.asc())
    ).scalars().all()

    change_type_map = {
        "new_subdomain": "subdomain_appeared",
        "port_exposed":  "port_opened",
        "endpoint_discovered": "change_detected",
        "vuln_discovered": "vuln_found",
        "vuln_fixed":    "vuln_fixed",
        "asset_discovered": "asset_first_seen",
    }
    for ch in changes:
        etype = change_type_map.get(ch.change_type, "change_detected")
        events.append(_make_event(
            etype, asset, ch.detail or ch.change_type,
            timestamp=ch.created_at, scan_id=ch.scan_id, source="change_detector"
        ))

    # 2. Finding lifecycle
    findings = db.execute(
        select(Finding).where(
            Finding.org_id == org_id,
            Finding.asset_id == asset_id,
            Finding.first_seen >= since,
        ).order_by(Finding.first_seen.asc())
    ).scalars().all()

    for f in findings:
        # Found
        events.append(_make_event(
            "vuln_found", asset,
            f"{f.severity.upper()}: {f.title}",
            timestamp=f.first_seen,
            finding_id=f.id,
            scan_id=f.scan_id,
            source=f.tool or "scanner",
            extra={"cve": f.cve, "cvss": f.cvss, "severity": f.severity},
            after={"title": f.title, "severity": f.severity, "cvss": f.cvss, "cve": f.cve},
        ))
        # KEV special event
        if f.cve:
            try:
                from app.services.vuln_scanner import get_kev_cve_set
                kev = get_kev_cve_set()
                if f.cve.upper() in kev:
                    events.append(_make_event(
                        "kev_added", asset,
                        f"{f.cve} is in CISA Known Exploited Vulnerabilities — patch immediately",
                        timestamp=f.first_seen, finding_id=f.id, source="cisa_kev",
                        mitre="T1190",
                    ))
            except Exception as e:
                logger.debug('optional feature error', error=str(e))
                pass
        # Fixed
        if f.status == "fixed" and f.last_seen and f.last_seen >= since:
            events.append(_make_event(
                "vuln_fixed", asset,
                f"Fixed: {f.title}",
                timestamp=f.last_seen,
                finding_id=f.id,
                source="scanner",
            ))

    # 3. Snapshot diffs: detect IP changes, tech changes, port changes
    snapshots = db.execute(
        select(AssetSnapshot).where(
            AssetSnapshot.org_id == org_id,
            AssetSnapshot.asset_id == asset_id,
        ).order_by(AssetSnapshot.created_at.asc())
    ).scalars().all()

    for i in range(1, len(snapshots)):
        prev = snapshot_to_dict(snapshots[i-1])
        curr = snapshot_to_dict(snapshots[i])
        diffs = diff_asset_states(prev, curr)
        ts = snapshots[i].created_at

        for diff in diffs:
            if diff.field == "ip":
                events.append(_make_event("ip_changed", asset,
                    f"IP changed: {diff.before} → {diff.after}",
                    timestamp=ts, before=prev, after=curr, scan_id=snapshots[i].scan_id))
            elif diff.field == "hosting_provider":
                events.append(_make_event("hosting_changed", asset,
                    f"Hosting changed: {diff.before} → {diff.after}",
                    timestamp=ts, before=prev, after=curr))
            elif diff.field == "cdn":
                events.append(_make_event("cdn_changed", asset,
                    f"CDN changed: {diff.before} → {diff.after}", timestamp=ts))
            elif diff.field == "port" and diff.change_type == "added":
                events.append(_make_event("port_opened", asset,
                    f"Port {diff.after} opened",
                    timestamp=ts, after=curr, scan_id=snapshots[i].scan_id))
            elif diff.field == "exposure_class":
                etype = "exposure_increased" if diff.after in ("public",) else "exposure_decreased"
                events.append(_make_event(etype, asset,
                    f"Exposure changed: {diff.before} → {diff.after}", timestamp=ts))
            elif diff.field == "technology" and diff.change_type == "added":
                events.append(_make_event("tech_added", asset,
                    f"Technology detected: {diff.after}", timestamp=ts))
            elif diff.field == "technology" and diff.change_type == "removed":
                events.append(_make_event("tech_removed", asset,
                    f"Technology removed: {diff.before}", timestamp=ts))

    # 4. Asset first seen
    if asset.first_seen and asset.first_seen >= since:
        events.insert(0, _make_event(
            "asset_first_seen", asset,
            f"Asset first discovered: {_asset_display(asset)}",
            timestamp=asset.first_seen, source="discovery",
        ))

    # Sort chronologically
    events.sort(key=lambda e: e.timestamp)
    return events


def get_org_timeline(
    db: Session,
    org_id: int,
    days: int = 30,
    limit: int = 200,
    severity_filter: Optional[str] = None,
    event_type_filter: Optional[List[str]] = None,
) -> List[TimelineEvent]:
    """Org-wide timeline, optionally filtered by severity/event type."""
    since = datetime.utcnow() - timedelta(days=days)
    events: List[TimelineEvent] = []

    changes = db.execute(
        select(AssetChange).where(
            AssetChange.org_id == org_id,
            AssetChange.created_at >= since,
        ).order_by(AssetChange.created_at.desc()).limit(limit)
    ).scalars().all()

    # Cache asset lookups
    asset_ids = {c.asset_id for c in changes if c.asset_id}
    asset_map: Dict[int, Asset] = {}
    if asset_ids:
        for a in db.execute(select(Asset).where(Asset.id.in_(asset_ids))).scalars().all():
            asset_map[a.id] = a

    change_type_map = {
        "new_subdomain":     "subdomain_appeared",
        "port_exposed":      "port_opened",
        "vuln_discovered":   "vuln_found",
        "vuln_fixed":        "vuln_fixed",
        "asset_discovered":  "asset_first_seen",
        "endpoint_discovered": "change_detected",
    }

    for ch in changes:
        asset = asset_map.get(ch.asset_id) if ch.asset_id else None
        etype = change_type_map.get(ch.change_type, "change_detected")
        _, _, sev = _event_meta(etype)

        if severity_filter and sev != severity_filter:
            continue
        if event_type_filter and etype not in event_type_filter:
            continue

        events.append(_make_event(
            etype, asset, ch.detail or ch.change_type,
            timestamp=ch.created_at, scan_id=ch.scan_id
        ))

    return events


# ── Risk trajectory ────────────────────────────────────────────────────────

def get_risk_trajectory(
    db: Session,
    org_id: int,
    asset_id: Optional[int] = None,
    days: int = 90,
) -> List[RiskSnapshot]:
    """Return risk score over time, one snapshot per completed scan.

    If asset_id given: trajectry for that asset.
    Otherwise: org-wide aggregate risk trajectory.
    """
    since = datetime.utcnow() - timedelta(days=days)

    scans = db.execute(
        select(Scan).where(
            Scan.org_id == org_id,
            Scan.status == "completed",
            Scan.completed_at >= since,
        ).order_by(Scan.completed_at.asc())
    ).scalars().all()

    snapshots: List[RiskSnapshot] = []

    for scan in scans:
        if not scan.completed_at:
            continue

        if asset_id:
            findings = db.execute(
                select(Finding).where(
                    Finding.org_id == org_id,
                    Finding.asset_id == asset_id,
                    Finding.status == "open",
                    Finding.last_seen <= scan.completed_at,
                )
            ).scalars().all()
            risk_scores = [float(f.risk_score or 0) for f in findings if f.risk_score]
            risk = round(max(risk_scores) if risk_scores else 0.0, 2)
            asset = db.get(Asset, asset_id)
            exposure = asset.exposure_class if asset else "unknown"
        else:
            # Org aggregate: weighted average of all open finding risk scores at this point
            findings = db.execute(
                select(Finding).where(
                    Finding.org_id == org_id,
                    Finding.status == "open",
                    Finding.last_seen <= scan.completed_at,
                )
            ).scalars().all()
            risk_scores = [float(f.risk_score or 0) for f in findings if f.risk_score]
            if risk_scores:
                risk_scores_sorted = sorted(risk_scores, reverse=True)
                top_n = max(1, len(risk_scores_sorted) // 5)
                risk = round(
                    risk_scores_sorted[:top_n][0] * 0.5 +
                    sum(risk_scores_sorted[top_n:]) / max(len(risk_scores_sorted) - top_n, 1) * 0.5,
                    2
                )
            else:
                risk = 0.0
            exposure = "public"

        critical = sum(1 for f in findings if f.severity == "critical")
        snapshots.append(RiskSnapshot(
            scan_id=scan.id,
            timestamp=scan.completed_at.isoformat(),
            risk_score=risk,
            open_findings=len(findings),
            critical_findings=critical,
            exposure_class=exposure,
        ))

    return snapshots


def get_risk_trend(snapshots: List[RiskSnapshot]) -> Dict:
    """Compute trend direction and delta from a risk trajectory."""
    if len(snapshots) < 2:
        return {"trend": "stable", "delta": 0.0, "slope": 0.0}

    scores = [s.risk_score for s in snapshots]
    delta = round(scores[-1] - scores[0], 2)
    recent_delta = round(scores[-1] - scores[-2], 2)

    if recent_delta > 5:      trend = "degrading"
    elif recent_delta < -5:   trend = "improving"
    elif abs(delta) < 3:      trend = "stable"
    elif delta > 0:            trend = "degrading"
    else:                      trend = "improving"

    return {"trend": trend, "delta": delta, "recent_delta": recent_delta}


# ── History summary ────────────────────────────────────────────────────────

def get_asset_history_summary(db: Session, org_id: int, asset_id: int) -> Dict:
    """Complete history digest for a single asset."""
    asset = db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
    ).scalar_one_or_none()
    if not asset:
        return {}

    findings = db.execute(
        select(Finding).where(Finding.asset_id == asset_id, Finding.org_id == org_id)
    ).scalars().all()
    open_f = [f for f in findings if f.status == "open"]
    fixed_f = [f for f in findings if f.status == "fixed"]
    by_sev = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for f in open_f:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    all_changes = db.execute(
        select(AssetChange).where(AssetChange.asset_id == asset_id, AssetChange.org_id == org_id)
        .order_by(AssetChange.created_at.asc())
    ).scalars().all()

    # Risk trajectory (last 90d)
    trajectory = get_risk_trajectory(db, org_id, asset_id=asset_id, days=90)
    risk_trend = get_risk_trend(trajectory)

    # Technology history: extract unique techs ever seen
    tech_set: set = set()
    if asset.technology:
        for t in asset.technology.split(","):
            t = t.strip()
            if t:
                tech_set.add(t)

    # KEV status
    is_kev = any(f.cve for f in findings)
    if is_kev:
        cves = [f.cve for f in findings if f.cve]
        try:
            from app.services.vuln_scanner import get_kev_cve_set
            kev_set = get_kev_cve_set()
            is_kev = any(cve.upper() in kev_set for cve in cves)
        except Exception:
            is_kev = False

    return {
        "asset": {
            "id": asset.id,
            "type": asset.asset_type,
            "label": _asset_display(asset),
            "domain": asset.domain,
            "subdomain": asset.subdomain,
            "ip": asset.ip,
            "url": asset.url,
            "technology": asset.technology,
            "hosting_provider": asset.hosting_provider,
            "cdn": asset.cdn,
            "asn": asset.asn,
            "country": asset.country,
            "exposure_class": asset.exposure_class,
            "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
            "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        },
        "findings": {
            "total": len(findings),
            "open": len(open_f),
            "fixed": len(fixed_f),
            "by_severity": by_sev,
            "has_kev": is_kev,
            "kev_cves": [f.cve for f in findings if f.cve] if is_kev else [],
        },
        "changes": {
            "total": len(all_changes),
            "by_type": _count_by(all_changes, "change_type"),
            "latest_20": [
                {
                    "type": c.change_type,
                    "detail": c.detail,
                    "at": c.created_at.isoformat() if c.created_at else None,
                }
                for c in all_changes[-20:]
            ],
        },
        "risk": {
            "current": trajectory[-1].risk_score if trajectory else 0.0,
            "trend": risk_trend["trend"],
            "delta_90d": risk_trend["delta"],
            "trajectory": [s.to_dict() for s in trajectory[-30:]],  # last 30 snapshots
        },
        "technologies": sorted(tech_set),
        "snapshots_count": db.execute(
            select(sa_func.count()).select_from(AssetSnapshot)
            .where(AssetSnapshot.asset_id == asset_id)
        ).scalar_one(),
    }


def get_new_assets_since(db: Session, org_id: int, since: datetime) -> List[Dict]:
    """Assets first discovered after a given time."""
    assets = db.execute(
        select(Asset).where(Asset.org_id == org_id, Asset.first_seen >= since)
        .order_by(Asset.first_seen.desc())
    ).scalars().all()
    return [
        {
            "id": a.id,
            "asset_type": a.asset_type,
            "label": _asset_display(a),
            "domain": a.domain,
            "subdomain": a.subdomain,
            "ip": a.ip,
            "url": a.url,
            "service": a.service,
            "technology": a.technology,
            "hosting_provider": a.hosting_provider,
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "exposure_class": a.exposure_class,
        }
        for a in assets
    ]


def _count_by(items: list, attr: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        val = getattr(item, attr, "unknown") or "unknown"
        counts[val] = counts.get(val, 0) + 1
    return counts

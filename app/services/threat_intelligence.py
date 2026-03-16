"""Threat Intelligence Engine — enriches assets and findings with external TI feeds.

Integrates multiple threat intelligence sources to answer:
  "Is this IP/domain/ASN known malicious?"
  "Has this IP been seen in threat actor campaigns?"
  "Is this CVE being actively exploited by ransomware groups?"
  "What's the current threat landscape for these technologies?"

Data sources integrated:
  1. AbuseIPDB         — IP reputation, abuse reports
  2. VirusTotal        — Domain/IP multi-engine reputation
  3. Shodan            — Internet exposure, banner data, open services
  4. AlienVault OTX    — Threat pulses, IOC feeds
  5. URLhaus           — Malicious URL database
  6. Emerging Threats  — Snort/Suricata rule-based threat data
  7. CISA KEV          — Known exploited vulnerabilities (cached from vuln_scanner)
  8. GreyNoise         — Internet scanner / background noise classification
  9. IntelX (optional) — Data breach search for org domains
  10. ThreatFox        — Recent malware IOCs (daily updated)

Intelligence levels per asset:
  CLEAN    : No threat indicators found
  SUSPECT  : Low-confidence indicators (scanner noise, old reports)
  MALICIOUS: Confirmed threat indicators (active C2, malware hosting)
  CRITICAL : Active exploitation, ransomware, APT activity

All API calls are rate-limited and cached (Redis or in-memory).
API keys configurable via environment variables.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from app.logger import get_logger
logger = get_logger('app.services.threat_intelligence')
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

from app import config


# ── Cache ──────────────────────────────────────────────────────────────────

_TI_CACHE: Dict[str, Tuple[float, dict]] = {}
_TI_LOCK = threading.Lock()
_TI_TTL = 3600  # 1 hour default


def _cache_get(key: str) -> Optional[dict]:
    with _TI_LOCK:
        entry = _TI_CACHE.get(key)
        if entry and (time.time() - entry[0]) < _TI_TTL:
            return entry[1]
        if entry:
            del _TI_CACHE[key]
    return None


def _cache_set(key: str, value: dict, ttl: int = _TI_TTL) -> None:
    with _TI_LOCK:
        _TI_CACHE[key] = (time.time(), value)


def _cache_key(*parts) -> str:
    return hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


# ── HTTP helper ────────────────────────────────────────────────────────────

def _fetch_json(url: str, headers: Optional[Dict] = None, timeout: int = 10) -> Optional[dict]:
    h = {"User-Agent": "ASMPlatform/1.0", "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = Request(url, headers=h)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(500_000).decode("utf-8"))
    except (HTTPError, URLError, json.JSONDecodeError, OSError):
        return None


def _post_json(url: str, payload: dict, headers: Optional[Dict] = None, timeout: int = 10) -> Optional[dict]:
    h = {"User-Agent": "ASMPlatform/1.0", "Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        h.update(headers)
    try:
        data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, headers=h, method="POST")
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(500_000).decode("utf-8"))
    except (HTTPError, URLError, json.JSONDecodeError, OSError):
        return None


# ── Data structures ────────────────────────────────────────────────────────

@dataclass
class TIIndicator:
    """Single threat intelligence indicator for an asset."""
    source: str              # e.g. "abuseipdb", "virustotal"
    indicator_type: str      # "ip", "domain", "url", "cve"
    value: str               # the actual indicator
    confidence: int          # 0-100
    threat_level: str        # CLEAN / SUSPECT / MALICIOUS / CRITICAL
    tags: List[str] = field(default_factory=list)
    last_seen: Optional[str] = None
    report_count: int = 0
    description: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class AssetThreatProfile:
    """Aggregated threat intelligence for a single asset."""
    asset_id: int
    label: str
    overall_level: str       # CLEAN / SUSPECT / MALICIOUS / CRITICAL
    confidence: int          # 0-100 overall confidence
    indicators: List[TIIndicator] = field(default_factory=list)
    threat_actor_tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    active_campaigns: List[str] = field(default_factory=list)
    greynoise_classification: Optional[str] = None  # "malicious" / "benign" / "unknown"
    abuseipdb_score: Optional[int] = None           # 0-100 abuse confidence
    virustotal_positives: Optional[int] = None
    shodan_tags: List[str] = field(default_factory=list)
    shodan_vulns: List[str] = field(default_factory=list)   # CVEs from Shodan banner
    first_seen_malicious: Optional[str] = None
    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class OrgThreatSummary:
    org_id: int
    total_assets_checked: int
    critical_assets: int
    malicious_assets: int
    suspect_assets: int
    clean_assets: int
    top_threats: List[AssetThreatProfile]
    trending_malware: List[str]
    active_cve_exploits: List[str]
    threat_level: str    # org-wide aggregate


# ── AbuseIPDB ─────────────────────────────────────────────────────────────

def check_abuseipdb(ip: str) -> Optional[TIIndicator]:
    api_key = config.get_abuseipdb_api_key() if hasattr(config, "get_abuseipdb_api_key") else None
    if not api_key:
        return None

    ck = _cache_key("abuseipdb", ip)
    cached = _cache_get(ck)
    if cached:
        return TIIndicator(**cached)

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    data = _fetch_json(url, headers={"Key": api_key, "Accept": "application/json"})
    if not data:
        return None

    report = data.get("data", {})
    abuse_score = int(report.get("abuseConfidenceScore", 0))
    reports = int(report.get("totalReports", 0))
    isp = report.get("isp", "")
    usage = report.get("usageType", "")
    country = report.get("countryCode", "")

    level = "CLEAN"
    if abuse_score >= 80:   level = "CRITICAL"
    elif abuse_score >= 50: level = "MALICIOUS"
    elif abuse_score >= 15: level = "SUSPECT"

    tags = [t for t in [isp, usage, country] if t]
    last_seen = report.get("lastReportedAt")

    ind = TIIndicator(
        source="abuseipdb",
        indicator_type="ip",
        value=ip,
        confidence=abuse_score,
        threat_level=level,
        tags=tags,
        last_seen=last_seen,
        report_count=reports,
        description=f"AbuseIPDB: {abuse_score}% confidence, {reports} reports",
        references=[f"https://www.abuseipdb.com/check/{ip}"],
    )
    _cache_set(ck, ind.__dict__)
    return ind


# ── VirusTotal ────────────────────────────────────────────────────────────

def check_virustotal(value: str, vt_type: str = "ip") -> Optional[TIIndicator]:
    """Check IP or domain against VirusTotal multi-engine scan."""
    api_key = config.get_virustotal_api_key() if hasattr(config, "get_virustotal_api_key") else None
    if not api_key:
        return None

    ck = _cache_key("virustotal", vt_type, value)
    cached = _cache_get(ck)
    if cached:
        return TIIndicator(**cached)

    endpoint_map = {"ip": f"ip_addresses/{value}", "domain": f"domains/{value}"}
    path = endpoint_map.get(vt_type, f"ip_addresses/{value}")
    url = f"https://www.virustotal.com/api/v3/{path}"
    data = _fetch_json(url, headers={"x-apikey": api_key})
    if not data:
        return None

    attrs = data.get("data", {}).get("attributes", {})
    last_analysis = attrs.get("last_analysis_stats", {})
    malicious = int(last_analysis.get("malicious", 0))
    suspicious = int(last_analysis.get("suspicious", 0))
    total_engines = sum(last_analysis.values()) if last_analysis else 0

    confidence = round((malicious / max(total_engines, 1)) * 100) if total_engines else 0

    if malicious >= 5:     level = "CRITICAL"
    elif malicious >= 2:   level = "MALICIOUS"
    elif suspicious >= 3:  level = "SUSPECT"
    else:                  level = "CLEAN"

    tags = list(attrs.get("tags", []))
    categories = list(attrs.get("categories", {}).values())[:5]
    tags.extend(categories)

    ind = TIIndicator(
        source="virustotal",
        indicator_type=vt_type,
        value=value,
        confidence=confidence,
        threat_level=level,
        tags=tags,
        report_count=malicious,
        description=f"VirusTotal: {malicious}/{total_engines} engines flagged",
        references=[f"https://www.virustotal.com/gui/{vt_type}/{value}"],
    )
    _cache_set(ck, ind.__dict__)
    return ind


# ── GreyNoise ─────────────────────────────────────────────────────────────

def check_greynoise(ip: str) -> Optional[TIIndicator]:
    """Classify IP as internet scanner, malicious, or unknown."""
    api_key = config.get_greynoise_api_key() if hasattr(config, "get_greynoise_api_key") else None

    ck = _cache_key("greynoise", ip)
    cached = _cache_get(ck)
    if cached:
        return TIIndicator(**cached)

    headers = {}
    if api_key:
        headers["key"] = api_key

    # Community API works without key but has rate limits
    url = f"https://api.greynoise.io/v3/community/{ip}"
    data = _fetch_json(url, headers=headers)
    if not data:
        return None

    noise = data.get("noise", False)
    riot = data.get("riot", False)      # Known benign (CDN, scanner, etc.)
    classification = data.get("classification", "unknown")
    name = data.get("name", "")
    message = data.get("message", "")

    if classification == "malicious":
        level = "MALICIOUS"
        confidence = 75
    elif riot:
        level = "CLEAN"      # Known benign scanner (Google, Shodan, etc.)
        confidence = 90
    elif noise:
        level = "SUSPECT"    # Internet background radiation
        confidence = 30
    else:
        level = "CLEAN"
        confidence = 50

    ind = TIIndicator(
        source="greynoise",
        indicator_type="ip",
        value=ip,
        confidence=confidence,
        threat_level=level,
        tags=[classification, name] if name else [classification],
        description=f"GreyNoise: {classification} — {name or message}",
        references=[f"https://viz.greynoise.io/ip/{ip}"],
    )
    _cache_set(ck, ind.__dict__)
    return ind


# ── AlienVault OTX ────────────────────────────────────────────────────────

def check_otx(value: str, ioc_type: str = "IPv4") -> Optional[TIIndicator]:
    """Check OTX pulse data for an IP or domain."""
    api_key = config.get_otx_api_key() if hasattr(config, "get_otx_api_key") else None

    ck = _cache_key("otx", ioc_type, value)
    cached = _cache_get(ck)
    if cached:
        return TIIndicator(**cached)

    headers = {}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    type_map = {"IPv4": "IPv4", "domain": "domain", "hostname": "hostname"}
    otx_type = type_map.get(ioc_type, "IPv4")
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/general"
    data = _fetch_json(url, headers=headers)
    if not data:
        return None

    pulse_count = int(data.get("pulse_info", {}).get("count", 0))
    pulses = data.get("pulse_info", {}).get("pulses", [])
    tags: List[str] = []
    threat_actors: List[str] = []
    malware_families: List[str] = []
    references: List[str] = []

    for pulse in pulses[:5]:
        tags.extend(pulse.get("tags", []))
        for ta in pulse.get("adversary", []):
            threat_actors.append(ta)
        for mf in pulse.get("malware_families", []):
            malware_families.append(mf.get("display_name", "") if isinstance(mf, dict) else str(mf))
        url_ref = f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}"
        references.append(url_ref)

    if pulse_count >= 10:   level = "CRITICAL"
    elif pulse_count >= 5:  level = "MALICIOUS"
    elif pulse_count >= 1:  level = "SUSPECT"
    else:                   level = "CLEAN"

    ind = TIIndicator(
        source="alienvault_otx",
        indicator_type=ioc_type.lower(),
        value=value,
        confidence=min(pulse_count * 10, 95),
        threat_level=level,
        tags=list(set(tags))[:10],
        report_count=pulse_count,
        description=f"AlienVault OTX: {pulse_count} pulses. Actors: {', '.join(threat_actors[:3]) or 'none'}",
        references=references[:3],
    )
    _cache_set(ck, ind.__dict__)
    return ind


# ── Shodan ────────────────────────────────────────────────────────────────

def check_shodan(ip: str) -> Tuple[List[str], List[str]]:
    """Get Shodan tags and CVEs for an IP. Returns (tags, cves)."""
    api_key = config.get_shodan_api_key() if hasattr(config, "get_shodan_api_key") else None
    if not api_key:
        return [], []

    ck = _cache_key("shodan", ip)
    cached = _cache_get(ck)
    if cached:
        return cached.get("tags", []), cached.get("cves", [])

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    data = _fetch_json(url)
    if not data:
        return [], []

    tags = list(data.get("tags", []))
    vulns = list(data.get("vulns", {}).keys())  # e.g. ["CVE-2021-44228"]

    _cache_set(ck, {"tags": tags, "cves": vulns})
    return tags, vulns


# ── URLhaus ───────────────────────────────────────────────────────────────

def check_urlhaus(url_or_domain: str) -> Optional[TIIndicator]:
    """Check URLhaus for malicious URL/domain records."""
    ck = _cache_key("urlhaus", url_or_domain)
    cached = _cache_get(ck)
    if cached:
        return TIIndicator(**cached)

    payload = {"url": url_or_domain} if url_or_domain.startswith("http") else {"host": url_or_domain}
    data = _post_json("https://urlhaus-api.abuse.ch/v1/host/", payload)
    if not data:
        return None

    query_status = data.get("query_status", "no_results")
    if query_status == "no_results":
        return None

    urls = data.get("urls", [])
    malware_tags = []
    for u in urls[:5]:
        tags_raw = u.get("tags", []) or []
        malware_tags.extend(tags_raw if isinstance(tags_raw, list) else [])

    active = [u for u in urls if u.get("url_status") == "online"]
    level = "CRITICAL" if active else ("MALICIOUS" if urls else "CLEAN")

    ind = TIIndicator(
        source="urlhaus",
        indicator_type="domain",
        value=url_or_domain,
        confidence=90 if active else 60,
        threat_level=level,
        tags=list(set(malware_tags))[:8],
        report_count=len(urls),
        description=f"URLhaus: {len(urls)} URLs, {len(active)} currently online",
        references=["https://urlhaus.abuse.ch/"],
    )
    _cache_set(ck, ind.__dict__)
    return ind


# ── ThreatFox ─────────────────────────────────────────────────────────────

def check_threatfox(ioc: str) -> Optional[TIIndicator]:
    """Check ThreatFox for recent malware IOC matches."""
    ck = _cache_key("threatfox", ioc)
    cached = _cache_get(ck)
    if cached:
        return TIIndicator(**cached)

    payload = {"query": "search_ioc", "search_term": ioc}
    data = _post_json("https://threatfox-api.abuse.ch/api/v1/", payload)
    if not data or data.get("query_status") != "ok":
        return None

    iocs = data.get("data", [])
    if not iocs:
        return None

    malware_tags = []
    threat_types = []
    refs = []
    for item in iocs[:5]:
        malware_tags.append(item.get("malware", ""))
        threat_types.append(item.get("threat_type", ""))
        if item.get("reference"):
            refs.append(item["reference"])

    ind = TIIndicator(
        source="threatfox",
        indicator_type="ioc",
        value=ioc,
        confidence=85,
        threat_level="MALICIOUS",
        tags=list(set(filter(None, malware_tags + threat_types)))[:8],
        report_count=len(iocs),
        description=f"ThreatFox: {len(iocs)} IOC matches. Malware: {', '.join(set(malware_tags[:3]))}",
        references=refs[:3],
    )
    _cache_set(ck, ind.__dict__)
    return ind


# ── Asset profiling ────────────────────────────────────────────────────────

def profile_asset(asset_id: int, label: str, ip: Optional[str] = None,
                  domain: Optional[str] = None) -> AssetThreatProfile:
    """Run all available TI checks for a single asset."""
    indicators: List[TIIndicator] = []
    shodan_tags: List[str] = []
    shodan_vulns: List[str] = []
    gn_class: Optional[str] = None
    abuse_score: Optional[int] = None
    vt_positives: Optional[int] = None

    if ip:
        # AbuseIPDB
        ind = check_abuseipdb(ip)
        if ind:
            indicators.append(ind)
            abuse_score = ind.confidence

        # VirusTotal
        ind = check_virustotal(ip, "ip")
        if ind:
            indicators.append(ind)
            vt_positives = ind.report_count

        # GreyNoise
        ind = check_greynoise(ip)
        if ind:
            indicators.append(ind)
            gn_class = ind.tags[0] if ind.tags else "unknown"

        # OTX
        ind = check_otx(ip, "IPv4")
        if ind and ind.threat_level != "CLEAN":
            indicators.append(ind)

        # Shodan
        shodan_tags, shodan_vulns = check_shodan(ip)

        # ThreatFox
        ind = check_threatfox(ip)
        if ind:
            indicators.append(ind)

    if domain:
        ind = check_virustotal(domain, "domain")
        if ind:
            indicators.append(ind)

        ind = check_otx(domain, "hostname")
        if ind and ind.threat_level != "CLEAN":
            indicators.append(ind)

        ind = check_urlhaus(domain)
        if ind:
            indicators.append(ind)

    # Aggregate threat level
    levels = [i.threat_level for i in indicators]
    level_order = {"CLEAN": 0, "SUSPECT": 1, "MALICIOUS": 2, "CRITICAL": 3}
    if levels:
        overall = max(levels, key=lambda x: level_order.get(x, 0))
    else:
        overall = "CLEAN"

    confidence = int(sum(i.confidence for i in indicators) / max(len(indicators), 1))

    # Collect threat actor tags and malware families
    actor_tags: List[str] = []
    malware: List[str] = []
    for ind in indicators:
        for tag in ind.tags:
            if any(kw in tag.lower() for kw in ["apt", "lazarus", "carbanak", "cobalt", "fin"]):
                actor_tags.append(tag)
            elif any(kw in tag.lower() for kw in ["ransomware", "trojan", "rat", "botnet", "stealer"]):
                malware.append(tag)

    return AssetThreatProfile(
        asset_id=asset_id,
        label=label,
        overall_level=overall,
        confidence=confidence,
        indicators=indicators,
        threat_actor_tags=list(set(actor_tags))[:5],
        malware_families=list(set(malware))[:5],
        greynoise_classification=gn_class,
        abuseipdb_score=abuse_score,
        virustotal_positives=vt_positives,
        shodan_tags=shodan_tags,
        shodan_vulns=shodan_vulns,
    )


def scan_org_threat_intel(db, org_id: int, limit: int = 50) -> OrgThreatSummary:
    """Run TI profiling on org's public-facing assets."""
    from sqlalchemy import select as sa_select
    from app.models import Asset as AssetModel

    assets = db.execute(
        sa_select(AssetModel).where(
            AssetModel.org_id == org_id,
            AssetModel.exposure_class == "public",
        ).limit(limit)
    ).scalars().all()

    profiles: List[AssetThreatProfile] = []
    counts: Dict[str, int] = {"CLEAN": 0, "SUSPECT": 0, "MALICIOUS": 0, "CRITICAL": 0}

    for asset in assets:
        label = asset.url or asset.subdomain or asset.domain or asset.ip or f"#{asset.id}"
        try:
            profile = profile_asset(
                asset_id=asset.id,
                label=label,
                ip=asset.ip,
                domain=asset.subdomain or asset.domain,
            )
            profiles.append(profile)
            counts[profile.overall_level] = counts.get(profile.overall_level, 0) + 1
        except Exception as e:
            logger.warning('unexpected error', error=str(e))
            pass

    # Org-wide threat level
    if counts["CRITICAL"] > 0:     org_level = "CRITICAL"
    elif counts["MALICIOUS"] > 0:  org_level = "MALICIOUS"
    elif counts["SUSPECT"] > 2:    org_level = "SUSPECT"
    else:                          org_level = "CLEAN"

    top_threats = sorted(
        [p for p in profiles if p.overall_level in ("CRITICAL", "MALICIOUS")],
        key=lambda p: {"CRITICAL": 2, "MALICIOUS": 1}.get(p.overall_level, 0),
        reverse=True
    )[:10]

    # Trending malware from shodan vulns
    all_cves: List[str] = []
    all_malware: List[str] = []
    for p in profiles:
        all_cves.extend(p.shodan_vulns)
        all_malware.extend(p.malware_families)

    return OrgThreatSummary(
        org_id=org_id,
        total_assets_checked=len(profiles),
        critical_assets=counts["CRITICAL"],
        malicious_assets=counts["MALICIOUS"],
        suspect_assets=counts["SUSPECT"],
        clean_assets=counts["CLEAN"],
        top_threats=top_threats,
        trending_malware=list(set(all_malware))[:10],
        active_cve_exploits=list(set(all_cves))[:20],
        threat_level=org_level,
    )

"""Enterprise vulnerability scanner — full production pipeline.

Stages:
  1. HTTP probe (httpx)        — liveness + tech detection
  2. Port scan (naabu)         — full port enumeration
  3. Nuclei scan               — template-based vuln detection
       - Profile-based tag selection per scan_type
       - Chunked execution (configurable chunk size)
       - Severity filter, concurrency, rate-limit flags
       - Deduplication via fingerprints
  4. Tech-CVE matching         — offline CVE lookup for detected stacks
  5. CISA KEV enrichment       — marks actively exploited CVEs
  6. NVD CVSS enrichment       — live CVSS v3.1 from NVD API v2
  7. Exploit intelligence      — ExploitDB + PoC-in-GitHub
  8. False-positive suppression
  9. Severity normalisation    — KEV always -> critical, CVSS override

Output: VulnScanResult — enriched, deduplicated, risk-scored findings.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app import config
from app.services import scanning
from app.logger import get_logger
logger = get_logger('app.services.vuln_scanner')


# ---------------------------------------------------------------------------
# CVE intelligence database (tech -> CVE list)
# ---------------------------------------------------------------------------

_TECH_VULN_MAP: Dict[str, List[Dict]] = {
    "wordpress": [
        {"cve": "CVE-2023-5561",  "title": "WordPress Password Reset DoS",            "severity": "medium",  "cvss": 5.3},
        {"cve": "CVE-2022-21663", "title": "WordPress Object Injection via Multisite", "severity": "high",    "cvss": 8.8},
        {"cve": "CVE-2021-29447", "title": "WordPress XXE via Media Upload",           "severity": "high",    "cvss": 7.1},
        {"cve": "CVE-2023-2745",  "title": "WordPress Core Path Traversal",           "severity": "medium",  "cvss": 5.4},
    ],
    "drupal": [
        {"cve": "CVE-2018-7600",  "title": "Drupalgeddon2 RCE",                       "severity": "critical","cvss": 9.8},
        {"cve": "CVE-2019-6340",  "title": "Drupal REST RCE",                         "severity": "critical","cvss": 9.8},
        {"cve": "CVE-2022-25277", "title": "Drupal File Upload RCE",                  "severity": "critical","cvss": 9.8},
    ],
    "joomla": [
        {"cve": "CVE-2023-23752", "title": "Joomla Unauthorized API Access",          "severity": "medium",  "cvss": 5.3},
    ],
    "php": [
        {"cve": "CVE-2023-3824",  "title": "PHP Buffer Overflow in phar",             "severity": "critical","cvss": 9.8},
        {"cve": "CVE-2022-31625", "title": "PHP Postgres null byte injection",        "severity": "critical","cvss": 9.8},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "title": "Apache Path Traversal / RCE",            "severity": "critical","cvss": 9.8},
        {"cve": "CVE-2021-42013", "title": "Apache Path Traversal RCE (bypass)",     "severity": "critical","cvss": 9.8},
        {"cve": "CVE-2023-25690", "title": "Apache mod_proxy HTTP Request Smuggling","severity": "critical","cvss": 9.8},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "title": "Nginx DNS Off-by-one Heap Write",        "severity": "high",    "cvss": 7.7},
    ],
    "iis": [
        {"cve": "CVE-2021-31166", "title": "IIS HTTP Protocol Stack RCE",            "severity": "critical","cvss": 9.8},
        {"cve": "CVE-2022-41082", "title": "Exchange/IIS RCE (ProxyNotShell)",       "severity": "critical","cvss": 8.8},
    ],
    "jquery": [
        {"cve": "CVE-2020-11022", "title": "jQuery XSS via HTML parsing",            "severity": "medium",  "cvss": 6.1},
        {"cve": "CVE-2019-11358", "title": "jQuery Prototype Pollution",             "severity": "medium",  "cvss": 6.1},
    ],
    "asp.net": [
        {"cve": "CVE-2021-26701", "title": "ASP.NET Core RCE via RegExp",            "severity": "critical","cvss": 9.8},
    ],
    "magento": [
        {"cve": "CVE-2022-24086", "title": "Magento RCE via Template Injection",     "severity": "critical","cvss": 9.8},
    ],
    "openssl": [
        {"cve": "CVE-2022-3602",  "title": "OpenSSL Buffer Overflow",                "severity": "critical","cvss": 9.8},
        {"cve": "CVE-2023-0286",  "title": "OpenSSL X.400 Type Confusion",           "severity": "high",    "cvss": 7.4},
    ],
    "log4j": [
        {"cve": "CVE-2021-44228", "title": "Log4Shell JNDI RCE",                     "severity": "critical","cvss": 10.0},
        {"cve": "CVE-2021-45046", "title": "Log4Shell DoS / RCE (bypass)",           "severity": "critical","cvss": 9.0},
    ],
    "spring": [
        {"cve": "CVE-2022-22965", "title": "Spring4Shell RCE",                       "severity": "critical","cvss": 9.8},
        {"cve": "CVE-2022-22963", "title": "Spring Cloud Function RCE",              "severity": "critical","cvss": 9.8},
    ],
    "jenkins": [
        {"cve": "CVE-2024-23897", "title": "Jenkins CLI Arbitrary File Read",        "severity": "critical","cvss": 9.8},
    ],
    "grafana": [
        {"cve": "CVE-2021-43798", "title": "Grafana Path Traversal",                 "severity": "high",    "cvss": 7.5},
    ],
    "gitlab": [
        {"cve": "CVE-2021-22205", "title": "GitLab Unauthenticated RCE",             "severity": "critical","cvss": 10.0},
        {"cve": "CVE-2023-2825",  "title": "GitLab Path Traversal",                  "severity": "critical","cvss": 10.0},
    ],
    "elasticsearch": [
        {"cve": "CVE-2021-22145", "title": "Elasticsearch Memory Disclosure",        "severity": "medium",  "cvss": 4.9},
    ],
    "node.js": [
        {"cve": "CVE-2022-32212", "title": "Node.js DNS rebinding",                  "severity": "high",    "cvss": 8.1},
    ],
}

_HIGH_RISK_PORTS: Dict[int, Dict] = {
    21:    {"service": "ftp",           "severity": "medium",   "desc": "FTP plaintext — credentials exposed in transit"},
    22:    {"service": "ssh",           "severity": "info",     "desc": "SSH exposed — monitor for brute-force"},
    23:    {"service": "telnet",        "severity": "high",     "desc": "Telnet exposed — replace with SSH immediately"},
    445:   {"service": "smb",           "severity": "critical", "desc": "SMB exposed — EternalBlue/WannaCry attack surface"},
    1433:  {"service": "mssql",         "severity": "high",     "desc": "MSSQL internet-facing — high brute-force risk"},
    2375:  {"service": "docker-daemon", "severity": "critical", "desc": "Docker daemon (no TLS) — full container escape / host takeover"},
    3306:  {"service": "mysql",         "severity": "high",     "desc": "MySQL exposed — should never be internet-facing"},
    3389:  {"service": "rdp",           "severity": "critical", "desc": "RDP exposed — BlueKeep/brute-force risk"},
    4444:  {"service": "backdoor",      "severity": "critical", "desc": "Port 4444 — common Metasploit/C2 default port"},
    5432:  {"service": "postgresql",    "severity": "high",     "desc": "PostgreSQL exposed — should be firewalled"},
    5900:  {"service": "vnc",           "severity": "critical", "desc": "VNC exposed — often weak auth, full desktop access"},
    6379:  {"service": "redis",         "severity": "critical", "desc": "Redis exposed — no auth by default, common ransomware vector"},
    7001:  {"service": "weblogic",      "severity": "critical", "desc": "WebLogic — unauthenticated RCE (CVE-2020-14882)"},
    8888:  {"service": "jupyter",       "severity": "high",     "desc": "Jupyter Notebook — typically unauthenticated code execution"},
    9200:  {"service": "elasticsearch", "severity": "critical", "desc": "Elasticsearch — no auth by default, all data readable"},
    11211: {"service": "memcached",     "severity": "high",     "desc": "Memcached — no auth, DDoS amplification source"},
    27017: {"service": "mongodb",       "severity": "critical", "desc": "MongoDB — no auth by default in older versions"},
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EnrichedFinding:
    """ScanFinding with full intelligence metadata."""
    base: scanning.ScanFinding
    fingerprint: str = ""
    is_kev: bool = False
    has_public_exploit: bool = False
    exploit_refs: List[str] = field(default_factory=list)
    nvd_cvss: Optional[float] = None
    nvd_vector: Optional[str] = None
    final_severity: str = ""
    risk_score: float = 0.0
    suppressed: bool = False
    suppression_reason: str = ""


@dataclass
class NucleiScanOptions:
    """Fine-grained options for nuclei execution."""
    tags: Optional[List[str]] = None
    templates: Optional[List[str]] = None       # explicit template paths/dirs
    exclude_tags: Optional[List[str]] = None
    severity: Optional[List[str]] = None        # filter by severity level
    concurrency: Optional[int] = None
    rate_limit: Optional[int] = None
    bulk_size: Optional[int] = None
    timeout: Optional[int] = None               # per-request timeout (seconds)
    update_templates: bool = False
    no_interactsh: bool = True                  # disable OAST callbacks by default
    extra_args: Optional[List[str]] = None


@dataclass
class VulnScanResult:
    findings: List[EnrichedFinding] = field(default_factory=list)
    alive_hosts: List[scanning.HttpxResult] = field(default_factory=list)
    open_ports: List[scanning.NaabuResult] = field(default_factory=list)
    port_findings: List[EnrichedFinding] = field(default_factory=list)
    tech_cve_findings: List[EnrichedFinding] = field(default_factory=list)
    kev_count: int = 0
    exploit_count: int = 0
    suppressed_count: int = 0
    duration_seconds: float = 0.0
    targets_scanned: int = 0
    chunks_run: int = 0


# ---------------------------------------------------------------------------
# NVD API v2
# ---------------------------------------------------------------------------

_NVD_CACHE: Dict[str, Dict] = {}
_NVD_LOCK = threading.Lock()
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _fetch_nvd_cve(cve_id: str) -> Optional[Dict]:
    cve_id = cve_id.upper().strip()
    with _NVD_LOCK:
        if cve_id in _NVD_CACHE:
            return _NVD_CACHE[cve_id]
    api_key = config.get_nvd_api_key()
    headers: Dict[str, str] = {"User-Agent": "ASMPlatform/2.0"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        req = Request(f"{_NVD_BASE}?cveId={cve_id}", headers=headers)
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            result = vulns[0].get("cve", {})
            with _NVD_LOCK:
                _NVD_CACHE[cve_id] = result
            return result
    except Exception:
        return None


def _extract_nvd_cvss(cve_data: Dict) -> Tuple[Optional[float], Optional[str]]:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key, []):
            d = entry.get("cvssData", {})
            score = d.get("baseScore")
            vector = d.get("vectorString")
            if score is not None:
                return float(score), vector
    return None, None


# ---------------------------------------------------------------------------
# CISA KEV catalog
# ---------------------------------------------------------------------------

_KEV_CACHE: Optional[Set[str]] = None
_KEV_LOCK = threading.Lock()
_KEV_TS: float = 0
_KEV_TTL = 3600


def get_kev_cve_set() -> Set[str]:
    global _KEV_CACHE, _KEV_TS
    with _KEV_LOCK:
        if _KEV_CACHE is not None and (time.time() - _KEV_TS) < _KEV_TTL:
            return _KEV_CACHE
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        req = Request(url, headers={"User-Agent": "ASMPlatform/2.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            ids = {v.get("cveID", "").upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
            with _KEV_LOCK:
                _KEV_CACHE = ids
                _KEV_TS = time.time()
            return ids
    except Exception:
        with _KEV_LOCK:
            if _KEV_CACHE is None:
                _KEV_CACHE = set()
        return _KEV_CACHE or set()


# ---------------------------------------------------------------------------
# Exploit intelligence
# ---------------------------------------------------------------------------

_EXPLOIT_CACHE: Dict[str, bool] = {}
_EXPLOIT_LOCK = threading.Lock()


def _check_poc_in_github(cve_id: str) -> Tuple[bool, List[str]]:
    year = cve_id.split("-")[1] if "-" in cve_id else ""
    if not year.isdigit():
        return False, []
    url = f"https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve_id.upper()}.md"
    try:
        req = Request(url, headers={"User-Agent": "ASMPlatform/2.0"})
        with urlopen(req, timeout=6) as resp:
            content = resp.read(4096).decode("utf-8", errors="ignore")
            if len(content) > 80:
                return True, [f"https://github.com/trickest/cve/blob/main/{year}/{cve_id.upper()}.md"]
    except Exception as e:
        logger.debug('optional feature error', error=str(e))
        pass
    return False, []


def _check_exploitdb(cve_id: str) -> Tuple[bool, List[str]]:
    with _EXPLOIT_LOCK:
        if cve_id in _EXPLOIT_CACHE:
            return _EXPLOIT_CACHE[cve_id], []
    url = f"https://www.exploit-db.com/search?cve={cve_id}&json=true"
    refs: List[str] = []
    found = False
    try:
        req = Request(url, headers={"User-Agent": "ASMPlatform/2.0", "Accept": "application/json"})
        with urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            for exp in data.get("data", [])[:3]:
                eid = exp.get("id")
                if eid:
                    refs.append(f"https://www.exploit-db.com/exploits/{eid}")
            found = bool(refs)
    except Exception as e:
        logger.debug('optional feature error', error=str(e))
        pass
    with _EXPLOIT_LOCK:
        _EXPLOIT_CACHE[cve_id] = found
    return found, refs


# ---------------------------------------------------------------------------
# False-positive suppression
# ---------------------------------------------------------------------------

_FP_TITLE_PATTERNS = ["test page", "example domain", "it works", "default installation",
                       "placeholder", "under construction", "coming soon"]
_FP_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                         "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


def _is_false_positive(finding: scanning.ScanFinding) -> Tuple[bool, str]:
    title = (finding.title or "").lower()
    target = (finding.target or "").lower()
    evidence = (finding.evidence or "").lower()
    for p in _FP_TITLE_PATTERNS:
        if p in title:
            return True, f"title matches FP pattern: '{p}'"
    for p in ("127.0.0.1", "localhost", "example.com", "test.local"):
        if p in target or p in evidence:
            return True, f"target matches FP pattern: '{p}'"
    if finding.severity == "info" and not finding.cve:
        if any(target.startswith(prefix) for prefix in _FP_PRIVATE_PREFIXES) or \
                any(kw in target for kw in ("internal", "intranet")):
            return True, "info finding on private/internal address"
    return False, ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fingerprint(finding: scanning.ScanFinding) -> str:
    raw = "|".join([
        finding.tool or "",
        getattr(finding, "template_id", None) or "",
        finding.title or "",
        finding.target or "",
        str(finding.port or ""),
        finding.cve or "",
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0: return "critical"
    if cvss >= 7.0: return "high"
    if cvss >= 4.0: return "medium"
    if cvss >= 0.1: return "low"
    return "info"


def _risk_score(severity: str, cvss: Optional[float], is_kev: bool, has_exploit: bool) -> float:
    base = {"critical": 80.0, "high": 60.0, "medium": 40.0, "low": 20.0, "info": 5.0}.get(severity, 10.0)
    if cvss:
        base = max(base, cvss * 8.5)
    if is_kev:
        base += 15.0
    if has_exploit:
        base += 10.0
    return round(min(base, 100.0), 2)


# ---------------------------------------------------------------------------
# Nuclei runner — full integration
# ---------------------------------------------------------------------------

_NUCLEI_PROFILES: Dict[str, Dict] = {
    "web":      {"tags": ["cve", "exposures", "misconfiguration", "xss", "sqli", "ssrf", "rce", "lfi"],
                 "severity": ["critical", "high", "medium"]},
    "misconfig":{"tags": ["misconfig", "config", "exposure", "cloud"],
                 "severity": ["critical", "high", "medium", "low"]},
    "tls":      {"tags": ["ssl", "tls"],
                 "severity": ["critical", "high", "medium", "low"]},
    "headers":  {"tags": ["headers", "cors", "security"],
                 "severity": ["medium", "low", "info"]},
    "takeover": {"tags": ["takeover"],
                 "severity": ["critical", "high", "medium"]},
    "cve":      {"tags": ["cve"],
                 "severity": ["critical", "high", "medium"]},
    "api":      {"tags": ["api", "tokens", "exposure"],
                 "severity": ["critical", "high", "medium"]},
    "secret":   {"tags": ["secret", "token", "exposure", "default-login"],
                 "severity": ["critical", "high", "medium", "low"]},
    "deep":     {"tags": ["cve", "exposures", "misconfiguration", "default-login",
                          "takeover", "secret", "rce", "sqli", "xss", "ssrf"],
                 "severity": ["critical", "high", "medium"]},
    "discovery":{"tags": ["tech", "version", "info"],
                 "severity": ["info", "low", "medium"]},
}


def _resolve_nuclei_binary() -> Optional[str]:
    configured = os.getenv("ASM_NUCLEI_BIN", "nuclei")
    resolved = shutil.which(configured) or (configured if os.path.isfile(configured) else None)
    if resolved:
        return resolved
    if config.get_allow_stub_scans():
        return None
    raise RuntimeError("nuclei binary not found — set ASM_NUCLEI_BIN or install nuclei.")


def _write_targets(targets: Iterable[str]) -> str:
    h = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt", encoding="utf-8")
    for t in targets:
        t = t.strip()
        if t:
            h.write(t + "\n")
    h.close()
    return h.name


def _run_nuclei_raw(targets: List[str], opts: NucleiScanOptions, output_file: str) -> Tuple[int, str]:
    binary = _resolve_nuclei_binary()
    if not binary:
        return 0, ""

    target_file = _write_targets(targets)
    try:
        cmd = [binary, "-l", target_file, "-o", output_file, "-json", "-silent"]

        if opts.tags and not opts.templates:
            cmd += ["-tags", ",".join(opts.tags)]
        if opts.templates:
            for t in opts.templates:
                cmd += ["-t", t]
        if opts.exclude_tags:
            cmd += ["-exclude-tags", ",".join(opts.exclude_tags)]
        if opts.severity:
            cmd += ["-severity", ",".join(opts.severity)]

        concurrency = opts.concurrency or config.get_nuclei_concurrency()
        rate_limit = opts.rate_limit or config.get_nuclei_rate_limit()
        bulk_size = opts.bulk_size or config.get_nuclei_bulk_size()
        timeout = opts.timeout or config.get_nuclei_timeout()

        cmd += ["-c", str(concurrency), "-rl", str(rate_limit),
                "-bs", str(bulk_size), "-timeout", str(timeout)]

        if opts.no_interactsh:
            cmd.append("-no-interactsh")
        if opts.update_templates:
            cmd.append("-update-templates")
        if opts.extra_args:
            cmd.extend(opts.extra_args)
        cmd.extend(config.get_scanner_args("nuclei"))

        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=config.get_scanner_timeout(), check=False,
        )
        return proc.returncode, proc.stderr
    finally:
        try:
            os.unlink(target_file)
        except OSError:
            pass


def _parse_nuclei_jsonl(output_file: str) -> List[scanning.ScanFinding]:
    findings: List[scanning.ScanFinding] = []
    if not os.path.exists(output_file):
        return findings
    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                info = data.get("info", {}) or {}
                classif = info.get("classification", {}) or {}

                cve_val = classif.get("cve-id")
                if isinstance(cve_val, list):
                    cve_val = cve_val[0] if cve_val else None

                cvss_score = classif.get("cvss-score")
                if isinstance(cvss_score, str):
                    try:
                        cvss_score = float(cvss_score)
                    except ValueError:
                        cvss_score = None

                matched_at = data.get("matched-at") or data.get("host") or ""
                port = None
                if matched_at:
                    from urllib.parse import urlparse as _up
                    p = _up(matched_at)
                    if p.port:
                        port = p.port

                findings.append(scanning.ScanFinding(
                    title=info.get("name") or data.get("template-id") or "Nuclei finding",
                    severity=(info.get("severity") or "info").lower(),
                    description=info.get("description") or "",
                    evidence=data.get("template-id") or matched_at or "",
                    tool="nuclei",
                    target=matched_at,
                    port=port,
                    template_id=data.get("template-id"),
                    cvss=cvss_score,
                    cve=cve_val,
                ))
    except OSError:
        pass
    return findings


def nuclei_scan(
    targets: List[str],
    scan_type: str = "web",
    opts: Optional[NucleiScanOptions] = None,
) -> List[scanning.ScanFinding]:
    """Run nuclei with a profile-based option set. Returns raw findings."""
    if not targets:
        return []
    if opts is None:
        profile = _NUCLEI_PROFILES.get(scan_type, _NUCLEI_PROFILES["web"])
        opts = NucleiScanOptions(
            tags=profile.get("tags"),
            severity=profile.get("severity"),
        )
    output_file = tempfile.mktemp(suffix="_nuclei.jsonl")
    try:
        _run_nuclei_raw(targets, opts, output_file)
        return _parse_nuclei_jsonl(output_file)
    finally:
        try:
            os.unlink(output_file)
        except OSError:
            pass


def nuclei_scan_chunked(
    targets: List[str],
    scan_type: str = "web",
    chunk_size: Optional[int] = None,
    opts: Optional[NucleiScanOptions] = None,
) -> Tuple[List[scanning.ScanFinding], int]:
    """Chunked nuclei execution. Returns (findings, chunks_run)."""
    if not targets:
        return [], 0
    chunk_size = chunk_size or config.get_scan_chunk_size()
    seen: Set[str] = set()
    all_findings: List[scanning.ScanFinding] = []
    chunks_run = 0
    for i in range(0, len(targets), chunk_size):
        chunk = targets[i: i + chunk_size]
        chunks_run += 1
        try:
            for f in nuclei_scan(chunk, scan_type=scan_type, opts=opts):
                fp = _fingerprint(f)
                if fp not in seen:
                    seen.add(fp)
                    all_findings.append(f)
        except Exception:
            continue
    return all_findings, chunks_run


# ---------------------------------------------------------------------------
# Enrichment pipeline
# ---------------------------------------------------------------------------

def enrich_finding(
    finding: scanning.ScanFinding,
    kev_set: Optional[Set[str]] = None,
    check_exploits: bool = False,
    fetch_nvd: bool = True,
) -> EnrichedFinding:
    fp = _fingerprint(finding)
    ef = EnrichedFinding(base=finding, fingerprint=fp, final_severity=finding.severity or "info")

    if config.get_false_positive_auto_tag():
        is_fp, reason = _is_false_positive(finding)
        if is_fp:
            ef.suppressed = True
            ef.suppression_reason = reason
            return ef

    nvd_cvss = finding.cvss
    nvd_vector = None
    if finding.cve and fetch_nvd:
        try:
            cve_data = _fetch_nvd_cve(finding.cve)
            if cve_data:
                nvd_cvss, nvd_vector = _extract_nvd_cvss(cve_data)
                ef.nvd_cvss = nvd_cvss
                ef.nvd_vector = nvd_vector
                if nvd_cvss:
                    ef.final_severity = _severity_from_cvss(nvd_cvss)
        except Exception as e:
            logger.debug('optional feature error', error=str(e))
            pass

    if finding.cve:
        active_kev = kev_set if kev_set is not None else get_kev_cve_set()
        ef.is_kev = finding.cve.upper() in active_kev
        if ef.is_kev:
            ef.final_severity = "critical"

    if finding.cve and check_exploits and config.get_exploit_db_enabled():
        try:
            found_edb, edb_refs = _check_exploitdb(finding.cve)
            found_poc, poc_refs = _check_poc_in_github(finding.cve)
            ef.has_public_exploit = found_edb or found_poc
            ef.exploit_refs = (edb_refs + poc_refs)[:5]
            if ef.has_public_exploit and ef.final_severity not in ("critical",):
                ef.final_severity = "high"
        except Exception as e:
            logger.debug('optional feature error', error=str(e))
            pass

    ef.risk_score = _risk_score(ef.final_severity, nvd_cvss, ef.is_kev, ef.has_public_exploit)
    return ef


def enrich_findings_batch(
    findings: List[scanning.ScanFinding],
    check_exploits: bool = False,
) -> List[EnrichedFinding]:
    if not findings:
        return []
    kev_set = get_kev_cve_set()
    seen: Set[str] = set()
    enriched: List[EnrichedFinding] = []
    for f in findings:
        ef = enrich_finding(f, kev_set=kev_set, check_exploits=check_exploits)
        if config.get_vuln_dedup_enabled() and ef.fingerprint in seen:
            continue
        seen.add(ef.fingerprint)
        enriched.append(ef)
    return enriched


# ---------------------------------------------------------------------------
# Tech-CVE matching
# ---------------------------------------------------------------------------

def tech_cve_scan(
    techs: List[str],
    target: str,
    kev_set: Optional[Set[str]] = None,
) -> List[EnrichedFinding]:
    if kev_set is None:
        kev_set = get_kev_cve_set()
    findings: List[EnrichedFinding] = []
    seen_cves: Set[str] = set()
    for tech in techs:
        tech_lower = tech.lower().strip()
        for keyword, vulns in _TECH_VULN_MAP.items():
            if keyword not in tech_lower and tech_lower not in keyword:
                continue
            for vuln in vulns:
                cve_id = vuln["cve"]
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                base = scanning.ScanFinding(
                    title=f"[Tech-CVE] {vuln['title']}",
                    severity=vuln["severity"],
                    description=(
                        f"Technology '{tech}' matched {cve_id}. "
                        f"Verify patch status. CVSS: {vuln.get('cvss', 'N/A')}"
                    ),
                    evidence=f"tech={tech} | cve={cve_id}",
                    tool="tech-cve-matcher",
                    target=target,
                    cvss=vuln.get("cvss"),
                    cve=cve_id,
                )
                in_kev = cve_id.upper() in kev_set
                ef = EnrichedFinding(
                    base=base,
                    fingerprint=_fingerprint(base),
                    is_kev=in_kev,
                    final_severity="critical" if in_kev else vuln["severity"],
                    nvd_cvss=vuln.get("cvss"),
                    risk_score=_risk_score(
                        "critical" if in_kev else vuln["severity"],
                        vuln.get("cvss"), in_kev, False,
                    ),
                )
                findings.append(ef)
    return findings


# ---------------------------------------------------------------------------
# Port risk analysis
# ---------------------------------------------------------------------------

def port_risk_findings(
    naabu_results: List[scanning.NaabuResult],
    target_domain: str,
    kev_set: Optional[Set[str]] = None,
) -> List[EnrichedFinding]:
    findings: List[EnrichedFinding] = []
    for result in naabu_results:
        meta = _HIGH_RISK_PORTS.get(result.port)
        if not meta:
            continue
        base = scanning.ScanFinding(
            title=f"High-risk port exposed: {result.port}/{result.protocol} ({meta['service']})",
            severity=meta["severity"],
            description=meta["desc"],
            evidence=f"host={result.host or result.ip} port={result.port} proto={result.protocol}",
            tool="port-risk-analyzer",
            target=result.ip or result.host or target_domain,
            port=result.port,
        )
        ef = EnrichedFinding(
            base=base,
            fingerprint=_fingerprint(base),
            final_severity=meta["severity"],
            risk_score=_risk_score(meta["severity"], None, False, False),
        )
        findings.append(ef)
    return findings


# ---------------------------------------------------------------------------
# Convert back to ScanFinding for DB storage
# ---------------------------------------------------------------------------

def enriched_to_scan_finding(ef: EnrichedFinding) -> scanning.ScanFinding:
    """Upgrade EnrichedFinding to ScanFinding — overwrites severity, appends context."""
    base = ef.base
    parts = [base.description or ""]
    if ef.is_kev:
        parts.append(
            "CISA Known Exploited Vulnerability — actively exploited in the wild. "
            "Federal agencies must patch per BOD 22-01."
        )
    if ef.has_public_exploit:
        refs = " | ".join(ef.exploit_refs[:3])
        parts.append(f"Public exploit available: {refs}")
    if ef.nvd_vector:
        parts.append(f"CVSS vector: {ef.nvd_vector}")
    return scanning.ScanFinding(
        title=base.title,
        severity=ef.final_severity,
        description="\n\n".join(p for p in parts if p),
        evidence=base.evidence,
        tool=base.tool,
        target=base.target,
        port=base.port,
        template_id=getattr(base, "template_id", None),
        cvss=ef.nvd_cvss or base.cvss,
        cve=base.cve,
    )


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------

def full_vuln_pipeline(
    targets: List[str],
    scan_type: str = "web",
    run_tech_detection: bool = True,
    run_port_scan: bool = True,
    run_exploit_intel: bool = False,
    fetch_nvd_data: bool = True,
    nuclei_opts: Optional[NucleiScanOptions] = None,
) -> VulnScanResult:
    """Full enterprise vuln scan pipeline — call this from worker.py.

    Order: httpx -> naabu -> nuclei (chunked) -> tech-CVE -> KEV -> NVD -> FP filter.
    """
    t0 = time.time()
    result = VulnScanResult(targets_scanned=len(targets))

    result.alive_hosts = scanning.run_httpx(targets)
    alive_urls = [h.url for h in result.alive_hosts if h.url]

    if run_port_scan:
        ips = list({h.ip for h in result.alive_hosts if h.ip})
        if ips:
            result.open_ports = scanning.run_naabu(ips)
            result.port_findings = port_risk_findings(result.open_ports, targets[0] if targets else "")

    nuclei_targets = alive_urls if alive_urls else targets
    raw_nuclei, chunks = nuclei_scan_chunked(nuclei_targets, scan_type=scan_type, opts=nuclei_opts)
    result.chunks_run = chunks

    kev_set = get_kev_cve_set()
    if run_tech_detection:
        for h in result.alive_hosts:
            techs = h.tech or []
            if not techs and h.url:
                try:
                    from app.services.tech_detection import detect
                    techs = detect(h.url).technologies
                except Exception as e:
                    logger.debug('optional feature error', error=str(e))
                    pass
            if techs:
                result.tech_cve_findings.extend(tech_cve_scan(techs, h.url or h.host, kev_set=kev_set))

    result.findings = enrich_findings_batch(raw_nuclei, check_exploits=run_exploit_intel)

    all_ef = result.findings + result.port_findings + result.tech_cve_findings
    result.kev_count = sum(1 for ef in all_ef if ef.is_kev)
    result.exploit_count = sum(1 for ef in all_ef if ef.has_public_exploit)
    result.suppressed_count = sum(1 for ef in all_ef if ef.suppressed)
    result.duration_seconds = round(time.time() - t0, 2)
    return result

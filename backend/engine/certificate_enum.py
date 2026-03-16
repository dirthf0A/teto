from __future__ import annotations

import json
from typing import Iterable, List
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

from backend import config
from backend.engine import scanning


_GOOGLE_CT_URL = (
    "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch"
    "?include_subdomains=true&domain={domain}"
)


def _strip_google_prefix(raw: str) -> str:
    cleaned = raw.strip()
    if cleaned.startswith(")]}'"):
        parts = cleaned.split("\n", 1)
        return parts[1] if len(parts) > 1 else cleaned[4:]
    return cleaned


def _extract_hosts(obj: object) -> List[str]:
    if obj is None:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, list):
        hosts: List[str] = []
        for item in obj:
            hosts.extend(_extract_hosts(item))
        return hosts
    if isinstance(obj, dict):
        hosts: List[str] = []
        for key in ("name", "hostname", "domain", "subdomain", "value", "host"):
            if key in obj:
                hosts.extend(_extract_hosts(obj[key]))
        for value in obj.values():
            if isinstance(value, (list, dict)):
                hosts.extend(_extract_hosts(value))
        return hosts
    return []


def _normalize_hosts(raw_hosts: Iterable[str], domain: str) -> List[str]:
    results: List[str] = []
    seen = set()
    limit = config.get_intel_host_limit()
    for host in raw_hosts:
        if not host:
            continue
        value = str(host).strip().lower().rstrip(".")
        if value.startswith("*."):
            value = value[2:]
        if domain and not value.endswith(domain):
            continue
        if value in seen:
            continue
        seen.add(value)
        results.append(value)
        if len(results) >= limit:
            break
    return results


def run_google_transparency(domain: str) -> List[str]:
    url = _GOOGLE_CT_URL.format(domain=quote_plus(domain))
    request = Request(url, headers={"User-Agent": "asm-platform"})
    try:
        with urlopen(request, timeout=config.get_scanner_timeout()) as response:
            raw = response.read().decode("utf-8", errors="ignore")
    except Exception:
        return []
    cleaned = _strip_google_prefix(raw)
    if not cleaned:
        return []
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return []
    hosts = _extract_hosts(data)
    return _normalize_hosts(hosts, domain)


def discover(domain: str) -> List[scanning.SubdomainResult]:
    results: dict[str, scanning.SubdomainResult] = {}
    for hostname in scanning.run_cert_transparency(domain):
        results.setdefault(hostname, scanning.SubdomainResult(hostname=hostname, source="crt.sh"))
    for hostname in scanning.run_certspotter(domain):
        results.setdefault(hostname, scanning.SubdomainResult(hostname=hostname, source="certspotter"))
    for hostname in run_google_transparency(domain):
        results.setdefault(hostname, scanning.SubdomainResult(hostname=hostname, source="google-ct"))
    return list(results.values())

"""WHOIS pivoting for asset discovery.

Uses WHOIS data to pivot from a known domain to related domains and IP ranges:
- Registrant email → other domains registered by same person/org
- Registrant org name → related domains
- Nameserver → domains using same nameserver (ns pivoting)
- IP/CIDR blocks from WHOIS → new IP ranges to scan

Integrates with multiple WHOIS APIs and fallback to raw whois command.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app import config


_WHOIS_API_URL = "https://api.whoisxmlapi.com/v1"  # supports free tier
_RDAP_BASE = "https://rdap.org"

_EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_CIDR_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b")
_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


@dataclass
class WhoisData:
    domain: str
    registrant_email: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_name: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)
    related_domains: List[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class WhoisPivotResult:
    source_domain: str
    related_domains: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)
    pivot_type: str = ""  # "email", "org", "nameserver", "ip"


def _fetch_rdap(domain: str) -> Optional[dict]:
    url = f"{_RDAP_BASE}/domain/{domain}"
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "ASMPlatform/1.0"})
    try:
        with urlopen(request, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, json.JSONDecodeError, OSError):
        return None


def _fetch_rdap_ip(ip: str) -> Optional[dict]:
    url = f"{_RDAP_BASE}/ip/{ip}"
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "ASMPlatform/1.0"})
    try:
        with urlopen(request, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, json.JSONDecodeError, OSError):
        return None


def _run_whois_cmd(domain: str) -> str:
    whois_bin = shutil.which("whois")
    if not whois_bin:
        return ""
    try:
        result = subprocess.run(
            [whois_bin, domain],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return result.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _parse_rdap_whois(data: dict) -> WhoisData:
    """Parse RDAP JSON response into WhoisData."""
    domain = data.get("ldhName", "").lower()
    wd = WhoisData(domain=domain)

    # Extract nameservers
    for ns in data.get("nameservers", []):
        ns_name = ns.get("ldhName", "").lower()
        if ns_name:
            wd.nameservers.append(ns_name)

    # Extract registrant info from entities
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrant" not in roles and "administrative" not in roles:
            continue
        vcard = entity.get("vcardArray", [])
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if not isinstance(item, list):
                    continue
                label = item[0] if item else ""
                value = item[-1] if len(item) > 1 else ""
                if label == "fn" and not wd.registrant_name:
                    wd.registrant_name = str(value)
                elif label == "org" and not wd.registrant_org:
                    wd.registrant_org = str(value)
                elif label == "email" and not wd.registrant_email:
                    wd.registrant_email = str(value).lower()
    return wd


def _parse_raw_whois(domain: str, raw: str) -> WhoisData:
    wd = WhoisData(domain=domain, raw=raw)

    for line in raw.splitlines():
        lower = line.lower()
        if "registrant email:" in lower or "registrant e-mail:" in lower:
            emails = _EMAIL_PATTERN.findall(line)
            if emails and not wd.registrant_email:
                wd.registrant_email = emails[0].lower()
        elif "registrant organization:" in lower or "registrant org:" in lower:
            parts = line.split(":", 1)
            if len(parts) == 2 and not wd.registrant_org:
                wd.registrant_org = parts[1].strip()
        elif "registrant name:" in lower:
            parts = line.split(":", 1)
            if len(parts) == 2 and not wd.registrant_name:
                wd.registrant_name = parts[1].strip()
        elif "name server:" in lower or "nserver:" in lower:
            parts = line.split(":", 1)
            if len(parts) == 2:
                ns = parts[1].strip().lower().rstrip(".")
                if ns:
                    wd.nameservers.append(ns)
        # CIDR/IP ranges
        for cidr in _CIDR_PATTERN.findall(line):
            wd.ip_ranges.append(cidr)

    return wd


def lookup(domain: str) -> WhoisData:
    """Look up WHOIS data for a domain via RDAP, then fallback to whois cmd."""
    rdap_data = _fetch_rdap(domain)
    if rdap_data:
        wd = _parse_rdap_whois(rdap_data)
        if not wd.domain:
            wd.domain = domain
        return wd

    # Fallback to raw whois command
    raw = _run_whois_cmd(domain)
    if raw:
        return _parse_raw_whois(domain, raw)

    return WhoisData(domain=domain)


def lookup_ip(ip: str) -> WhoisData:
    """Look up WHOIS/RDAP data for an IP address to find owning org and CIDR."""
    wd = WhoisData(domain=ip)
    rdap = _fetch_rdap_ip(ip)
    if rdap:
        # Extract CIDR range
        start = rdap.get("startAddress", "")
        end = rdap.get("endAddress", "")
        cidr = rdap.get("cidr0_cidrs", [])
        if cidr:
            for c in cidr:
                v4p = c.get("v4prefix")
                length = c.get("length")
                if v4p and length:
                    wd.ip_ranges.append(f"{v4p}/{length}")
        # Extract org
        for entity in rdap.get("entities", []):
            vcard = entity.get("vcardArray", [])
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if not isinstance(item, list):
                        continue
                    if item[0] == "org" and not wd.registrant_org:
                        wd.registrant_org = str(item[-1])
    else:
        raw = _run_whois_cmd(ip)
        wd = _parse_raw_whois(ip, raw)
    return wd


def pivot_from_domain(domain: str) -> List[WhoisPivotResult]:
    """Pivot from a domain's WHOIS data to find related domains and IP ranges.

    Currently performs:
    1. Email pivot via ViewDNS (free, no key required)
    2. Nameserver pivot via ViewDNS
    3. Returns IP ranges from WHOIS

    Returns list of WhoisPivotResult objects, one per pivot type.
    """
    root = domain.strip().lower().rstrip(".")
    results: List[WhoisPivotResult] = []

    wd = lookup(root)

    # IP range pivot
    if wd.ip_ranges:
        results.append(
            WhoisPivotResult(
                source_domain=root,
                ip_ranges=wd.ip_ranges,
                pivot_type="ip_range",
            )
        )

    # Nameserver pivot: domains sharing same nameservers
    ns_domains: List[str] = []
    for ns in wd.nameservers[:3]:  # limit to 3 NS to avoid over-querying
        pivoted = _viewdns_reverse_ns(ns)
        for d in pivoted:
            if d != root and d not in ns_domains:
                ns_domains.append(d)

    if ns_domains:
        results.append(
            WhoisPivotResult(
                source_domain=root,
                related_domains=ns_domains,
                pivot_type="nameserver",
            )
        )

    # Email pivot
    if wd.registrant_email:
        email_domains = _viewdns_reverse_whois(wd.registrant_email)
        if email_domains:
            results.append(
                WhoisPivotResult(
                    source_domain=root,
                    related_domains=email_domains,
                    pivot_type="email",
                )
            )

    # Org name pivot
    if wd.registrant_org:
        org_domains = _viewdns_reverse_whois(wd.registrant_org)
        if org_domains:
            results.append(
                WhoisPivotResult(
                    source_domain=root,
                    related_domains=org_domains,
                    pivot_type="org",
                )
            )

    return results


def _viewdns_reverse_ns(nameserver: str) -> List[str]:
    """Query ViewDNS.info reverse nameserver lookup (free, public)."""
    url = f"https://viewdns.info/reversens/?ns={nameserver}&output=json"
    request = Request(url, headers={"User-Agent": "ASMPlatform/1.0"})
    try:
        with urlopen(request, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            domains_raw = data.get("response", {}).get("domains", [])
            return [d.get("name", "").lower() for d in domains_raw if d.get("name")]
    except (HTTPError, URLError, json.JSONDecodeError, OSError):
        return []


def _viewdns_reverse_whois(query: str) -> List[str]:
    """Query ViewDNS.info reverse WHOIS lookup by email/org (free tier limited)."""
    url = f"https://viewdns.info/reversewhois/?q={query}&output=json"
    request = Request(url, headers={"User-Agent": "ASMPlatform/1.0"})
    try:
        with urlopen(request, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            domains_raw = data.get("response", {}).get("domains", [])
            return [d.get("name", "").lower() for d in domains_raw if d.get("name")]
    except (HTTPError, URLError, json.JSONDecodeError, OSError):
        return []

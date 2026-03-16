from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from app import config
from app.services import scanning


CDN_SIGNATURES: dict[str, tuple[str, ...]] = {
    "cloudflare": (".cloudflare.net", ".cdn.cloudflare.net", ".workers.dev", ".pages.dev", ".r2.dev"),
    "cloudfront": (".cloudfront.net",),
    "fastly": (".fastly.net",),
    "akamai": (".akamaized.net", ".edgekey.net", ".edgesuite.net"),
    "azure": (".azureedge.net",),
    "gcp": (".googleusercontent.com", ".cloud.google.com"),
}


@dataclass
class HostEnrichment:
    host: str
    ips: List[str]
    cdn: Optional[str]


@dataclass
class IpEnrichment:
    ip: str
    asn: Optional[str]
    hosting_provider: Optional[str]
    country: Optional[str]


DEFAULT_LOOKUP_KEYS = (
    "asn",
    "asn_number",
    "as_number",
    "org",
    "organization",
    "isp",
    "provider",
    "name",
)
GEO_LOOKUP_KEYS = ("country", "country_code", "country_name", "country_iso", "country_iso_code", "iso_code", "code")


def _detect_cdn(host: str, cname: Optional[str]) -> Optional[str]:
    candidate = (cname or host or "").lower().rstrip(".")
    if not candidate:
        return None
    for provider, suffixes in CDN_SIGNATURES.items():
        if any(candidate.endswith(suffix) for suffix in suffixes):
            return provider
    return None


def _parse_lookup_value(raw: str, keys: Optional[Tuple[str, ...]] = None) -> Optional[str]:
    text = (raw or "").strip()
    if not text:
        return None
    lookup_keys = keys or DEFAULT_LOOKUP_KEYS
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for key in lookup_keys:
                value = data.get(key)
                if isinstance(value, (str, int, float)):
                    return str(value)
                if isinstance(value, dict):
                    for subkey in ("iso_code", "code", "country_code", "country", "name"):
                        inner = value.get(subkey)
                        if isinstance(inner, (str, int, float)):
                            return str(inner)
        if isinstance(data, list) and data:
            for item in data:
                if isinstance(item, (str, int, float)):
                    return str(item)
                if isinstance(item, dict):
                    for key in lookup_keys:
                        value = item.get(key)
                        if isinstance(value, (str, int, float)):
                            return str(value)
                        if isinstance(value, dict):
                            for subkey in ("iso_code", "code", "country_code", "country", "name"):
                                inner = value.get(subkey)
                                if isinstance(inner, (str, int, float)):
                                    return str(inner)
    return text.splitlines()[0].strip() if text else None


def _lookup_ip_value(template: Optional[str], ip: str, keys: Optional[Tuple[str, ...]] = None) -> Optional[str]:
    if not template:
        return None
    try:
        output = scanning._run_template_command(template, ip=ip)
    except Exception:
        return None
    return _parse_lookup_value(output, keys=keys)


def enrich_from_dnsx(
    results: Iterable[scanning.DnsxResult],
) -> Tuple[Dict[str, HostEnrichment], Dict[str, IpEnrichment]]:
    host_map: Dict[str, HostEnrichment] = {}
    ip_map: Dict[str, IpEnrichment] = {}
    asn_cmd = config.get_asn_command()
    hosting_cmd = config.get_hosting_command()
    geo_cmd = config.get_geoip_command()

    for result in results:
        host = (result.host or "").strip().lower().rstrip(".")
        if not host:
            continue
        ips = [ip for ip in (result.a + result.aaaa) if ip]
        cname = result.cname
        cdn = _detect_cdn(host, cname)
        host_map[host] = HostEnrichment(host=host, ips=ips, cdn=cdn)
        for ip in ips:
            if ip in ip_map:
                continue
            asn = _lookup_ip_value(asn_cmd, ip)
            hosting = _lookup_ip_value(hosting_cmd, ip)
            country = _lookup_ip_value(geo_cmd, ip, keys=GEO_LOOKUP_KEYS)
            ip_map[ip] = IpEnrichment(ip=ip, asn=asn, hosting_provider=hosting, country=country)

    return host_map, ip_map


def enrich_hosts(hosts: Iterable[str]) -> Tuple[Dict[str, HostEnrichment], Dict[str, IpEnrichment]]:
    host_list = [host for host in hosts if host]
    if not host_list:
        return {}, {}
    dnsx_results = scanning.run_dnsx(host_list)
    return enrich_from_dnsx(dnsx_results)

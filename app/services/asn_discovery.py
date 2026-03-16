from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, List, Set

from app import config
from app.services import asset_enrichment, scanning


ASN_REGEX = re.compile(r"\bAS(\d{1,10})\b", re.IGNORECASE)
ASN_NUMBER_REGEX = re.compile(r"\b(\d{1,10})\b")


@dataclass
class AsnResult:
    ip: str
    asn: str


def _normalize_asn(raw: str | None) -> str | None:
    if not raw:
        return None
    text = str(raw).strip().upper()
    match = ASN_REGEX.search(text)
    if match:
        return f"AS{match.group(1)}"
    match = ASN_NUMBER_REGEX.search(text)
    if match:
        return f"AS{match.group(1)}"
    return None


def discover_from_hosts(hosts: Iterable[str]) -> Set[str]:
    _, ip_map = asset_enrichment.enrich_hosts(hosts)
    results: Set[str] = set()
    for meta in ip_map.values():
        value = _normalize_asn(meta.asn)
        if value:
            results.add(value)
    return results


def discover_from_ips(ips: Iterable[str]) -> List[AsnResult]:
    template = config.get_asn_command()
    if not template:
        return []
    results: List[AsnResult] = []
    for ip in list({ip for ip in ips if ip}):
        try:
            output = scanning._run_template_command(template, ip=ip)
        except Exception:
            continue
        asn = _normalize_asn(output)
        if asn:
            results.append(AsnResult(ip=ip, asn=asn))
    return results


def discover_asns(ips: Iterable[str], hosts: Iterable[str] | None = None) -> Set[str]:
    results = {result.asn for result in discover_from_ips(ips)}
    if hosts:
        results.update(discover_from_hosts(hosts))
    return results

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, List, Set

from app import config
from app.services import scanning


CIDR_V4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
CIDR_V6 = re.compile(r"\b[0-9a-fA-F:]+/\d{1,3}\b")


@dataclass
class IpRangeResult:
    asn: str
    ranges: List[str]


def _extract_ranges(output: str) -> List[str]:
    ranges = CIDR_V4.findall(output or "") + CIDR_V6.findall(output or "")
    cleaned: List[str] = []
    seen = set()
    for value in ranges:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if value in seen:
            continue
        seen.add(value)
        cleaned.append(value)
    return cleaned


def ranges_for_asns(asns: Iterable[str]) -> List[IpRangeResult]:
    template = config.get_asn_ranges_command()
    if not template:
        return []
    results: List[IpRangeResult] = []
    limit = config.get_asn_range_limit()
    for asn in list({asn for asn in asns if asn}):
        try:
            output = scanning._run_template_command(template, asn=asn)
        except Exception:
            continue
        ranges = _extract_ranges(output)
        if ranges:
            results.append(IpRangeResult(asn=asn, ranges=ranges))
        if len(results) >= limit:
            break
    return results


def expand_ranges(ranges: Iterable[str], limit: int) -> List[str]:
    ips: List[str] = []
    for raw in ranges:
        if len(ips) >= limit:
            break
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        for ip in network.hosts():
            ips.append(str(ip))
            if len(ips) >= limit:
                break
    return ips


def discover_ips_for_asns(asns: Iterable[str]) -> List[str]:
    range_results = ranges_for_asns(asns)
    ranges: List[str] = []
    for entry in range_results:
        ranges.extend(entry.ranges)
    return expand_ranges(ranges, config.get_ip_range_scan_limit())


def discover_hosts_from_asns(asns: Iterable[str]) -> List[str]:
    if not config.get_asn_discovery_enabled():
        return []
    ips = discover_ips_for_asns(asns)
    hosts: List[str] = []
    seen: Set[str] = set()
    for ip in ips:
        for host in scanning.run_reverse_ip(ip):
            cleaned = host.strip().lower().rstrip(".")
            if not cleaned:
                continue
            if cleaned in seen:
                continue
            seen.add(cleaned)
            hosts.append(cleaned)
    return hosts

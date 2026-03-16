from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from backend import config
from backend.engine import scanning


@dataclass
class ReverseIpResult:
    ip: str
    hosts: List[str]


def _normalize_host(raw: str) -> str | None:
    value = (raw or "").strip().lower().rstrip(".")
    if not value:
        return None
    if value.startswith("*."):
        value = value[2:]
    return value or None


def discover(ip_addresses: Iterable[str]) -> List[ReverseIpResult]:
    limit = config.get_reverse_ip_limit()
    results: List[ReverseIpResult] = []
    for ip in list({ip for ip in ip_addresses if ip})[:limit]:
        hosts = scanning.run_reverse_ip(ip)
        if hosts:
            results.append(ReverseIpResult(ip=ip, hosts=hosts))
    return results


def discover_hosts(
    ip_addresses: Iterable[str],
    root_domain: str | None = None,
    include_external: bool = False,
) -> List[str]:
    results: List[str] = []
    seen = set()
    for item in discover(ip_addresses):
        for host in item.hosts:
            normalized = _normalize_host(host)
            if not normalized:
                continue
            if root_domain and not include_external and not normalized.endswith(root_domain):
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            results.append(normalized)
    return results

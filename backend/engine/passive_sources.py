from __future__ import annotations

from typing import Dict, List

from backend.engine import scanning


def discover(domain: str) -> List[scanning.SubdomainResult]:
    results: Dict[str, scanning.SubdomainResult] = {}
    for entry in scanning.run_subfinder(domain):
        results.setdefault(entry.hostname, entry)
    for entry in scanning.run_amass(domain):
        results.setdefault(entry.hostname, entry)
    return list(results.values())

from __future__ import annotations

from typing import Dict, List

from backend import config
from backend.engine import scanning


def _load_words() -> List[str]:
    words: List[str] = []
    wordlist = config.get_dns_brute_wordlist()
    limit = config.get_dns_brute_limit()
    if wordlist:
        try:
            with open(wordlist, "r", encoding="utf-8") as handle:
                for line in handle:
                    value = line.strip()
                    if not value or value.startswith("#"):
                        continue
                    words.append(value)
                    if len(words) >= limit:
                        break
        except OSError:
            words = []
    if not words:
        for value in config.get_dns_brute_words().split(","):
            cleaned = value.strip()
            if cleaned:
                words.append(cleaned)
        words = words[:limit]
    return words


def discover(domain: str) -> List[scanning.SubdomainResult]:
    words = _load_words()
    if not words:
        return []
    candidates = [f"{word}.{domain}" for word in words]
    results = scanning.run_dnsx(candidates)
    discovered: Dict[str, scanning.SubdomainResult] = {}
    for result in results:
        host = result.host or ""
        if not host:
            continue
        if not (result.a or result.aaaa or result.cname):
            continue
        discovered.setdefault(host, scanning.SubdomainResult(hostname=host, source="dns-bruteforce"))
    return list(discovered.values())

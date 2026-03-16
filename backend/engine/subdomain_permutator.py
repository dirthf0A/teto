from __future__ import annotations

from typing import Iterable, List, Set

from backend import config
from backend.engine import scanning


def _normalize_host(raw: str) -> str | None:
    value = (raw or "").strip().lower().rstrip(".")
    if not value:
        return None
    if value.startswith("*."):
        value = value[2:]
    return value or None


def _load_words() -> List[str]:
    return [word.strip() for word in config.get_permutation_words().split(",") if word.strip()]


def _extract_labels(host: str, root_domain: str) -> str | None:
    host = _normalize_host(host)
    if not host or not host.endswith(root_domain):
        return None
    prefix = host[: -len(root_domain)].rstrip(".")
    return prefix or None


def generate_candidates(hosts: Iterable[str], root_domain: str) -> List[str]:
    words = _load_words()
    limit = config.get_permutation_limit()
    seen: Set[str] = set()
    results: List[str] = []
    root_domain = root_domain.strip().lower().rstrip(".")
    if not root_domain:
        return []

    for host in hosts:
        label = _extract_labels(host, root_domain)
        if not label:
            continue
        base = label.split(".")[0]
        for word in words:
            if not word or word == base:
                continue
            variants = {
                f"{word}-{base}",
                f"{base}-{word}",
                f"{word}.{label}",
                f"{label}.{word}",
                f"{word}.{base}",
            }
            for variant in variants:
                candidate = f"{variant}.{root_domain}"
                if candidate in seen:
                    continue
                seen.add(candidate)
                results.append(candidate)
                if len(results) >= limit:
                    return results
    return results


def resolve_candidates(candidates: Iterable[str], root_domain: str) -> List[str]:
    resolved: List[str] = []
    seen = set()
    for result in scanning.run_dnsx(candidates):
        host = _normalize_host(result.host)
        if not host or not host.endswith(root_domain):
            continue
        if not (result.a or result.aaaa or result.cname):
            continue
        if host in seen:
            continue
        seen.add(host)
        resolved.append(host)
    return resolved


def discover(hosts: Iterable[str], root_domain: str) -> List[str]:
    candidates = generate_candidates(hosts, root_domain)
    if not candidates:
        return []
    return resolve_candidates(candidates, root_domain)

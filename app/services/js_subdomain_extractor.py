from __future__ import annotations

import re
from typing import Iterable, List
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from app import config
from app.services import scanning


def _normalize_host(raw: str) -> str | None:
    value = (raw or "").strip().lower().rstrip(".")
    if not value:
        return None
    if value.startswith("*."):
        value = value[2:]
    return value or None


def _is_js_url(url: str) -> bool:
    if not url:
        return False
    lower = url.lower()
    return lower.endswith(".js") or ".js?" in lower or ".js#" in lower


def extract_from_targets(targets: Iterable[str], root_domain: str) -> List[str]:
    urls = scanning.run_katana(targets)
    js_urls = [url for url in urls if _is_js_url(url)]
    return extract_from_js_urls(js_urls, root_domain)


def extract_from_js_urls(js_urls: Iterable[str], root_domain: str) -> List[str]:
    results: List[str] = []
    seen = set()
    limit = config.get_js_subdomain_limit()
    max_bytes = config.get_js_max_bytes()
    root_domain = root_domain.strip().lower().rstrip(".")
    if not root_domain:
        return []

    pattern = re.compile(rf"(?:[a-zA-Z0-9_-]+\\.)+{re.escape(root_domain)}")
    url_list = [url for url in js_urls if url]
    url_cap = config.get_js_url_limit()
    max_urls = min(len(url_list), url_cap) if url_cap > 0 else len(url_list)

    for url in url_list[:max_urls]:
        if not url:
            continue
        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname.endswith(root_domain):
            normalized = _normalize_host(parsed.hostname)
            if normalized and normalized not in seen:
                seen.add(normalized)
                results.append(normalized)
                if len(results) >= limit:
                    return results
        request = Request(url, headers={"User-Agent": "asm-platform"})
        try:
            with urlopen(request, timeout=config.get_scanner_timeout()) as response:
                raw = response.read(max_bytes)
        except (HTTPError, URLError):
            continue
        text = raw.decode("utf-8", errors="ignore")
        for match in pattern.findall(text):
            normalized = _normalize_host(match)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            results.append(normalized)
            if len(results) >= limit:
                return results
    return results

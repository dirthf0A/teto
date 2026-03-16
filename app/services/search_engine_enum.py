"""Search engine enumeration for subdomain and asset discovery.

Queries multiple search engines (Google, Bing, DuckDuckGo) using dork patterns
to discover subdomains and exposed assets that are indexed.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus, urlencode
from urllib.request import Request, urlopen

from app import config
from app.services import scanning


_SUBDOMAIN_PATTERN = re.compile(
    r"(?:https?://)?([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.[a-zA-Z]{2,})"
)

_USER_AGENT = (
    "Mozilla/5.0 (compatible; ASMBot/1.0; +https://github.com/asm-platform)"
)

_REQUEST_DELAY = 2.0  # seconds between requests to avoid rate-limiting


def _fetch_url(url: str, timeout: int = 10) -> Optional[str]:
    request = Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as resp:
            return resp.read(1_000_000).decode("utf-8", errors="ignore")
    except (HTTPError, URLError, OSError):
        return None


def _extract_subdomains(text: str, root_domain: str) -> List[str]:
    found: Dict[str, None] = {}
    for match in _SUBDOMAIN_PATTERN.finditer(text):
        host = match.group(1).lower().rstrip(".")
        if host.endswith(root_domain) and host != root_domain:
            found[host] = None
    return list(found.keys())


def _query_bing(domain: str, root_domain: str, limit: int) -> List[str]:
    results: Dict[str, None] = {}
    dorks = [
        f"site:{domain}",
        f"site:*.{domain}",
        f"site:{domain} -www",
    ]
    for dork in dorks:
        if len(results) >= limit:
            break
        url = f"https://www.bing.com/search?q={quote_plus(dork)}&count=50&first=1"
        text = _fetch_url(url)
        if text:
            for host in _extract_subdomains(text, root_domain):
                results[host] = None
                if len(results) >= limit:
                    break
        time.sleep(_REQUEST_DELAY)
    return list(results.keys())


def _query_duckduckgo(domain: str, root_domain: str, limit: int) -> List[str]:
    results: Dict[str, None] = {}
    dorks = [
        f"site:{domain}",
        f"site:*.{domain}",
    ]
    for dork in dorks:
        if len(results) >= limit:
            break
        params = urlencode({"q": dork, "t": "h_", "ia": "web"})
        url = f"https://html.duckduckgo.com/html/?{params}"
        text = _fetch_url(url)
        if text:
            for host in _extract_subdomains(text, root_domain):
                results[host] = None
                if len(results) >= limit:
                    break
        time.sleep(_REQUEST_DELAY)
    return list(results.keys())


def _query_google(domain: str, root_domain: str, limit: int) -> List[str]:
    """Query Google via public search (dorks, rate-limited)."""
    results: Dict[str, None] = {}
    dorks = [
        f"site:{domain}",
        f"site:*.{domain} -www",
        f"inurl:{domain}",
    ]
    for dork in dorks:
        if len(results) >= limit:
            break
        params = urlencode({"q": dork, "num": 100})
        url = f"https://www.google.com/search?{params}"
        text = _fetch_url(url)
        if text:
            for host in _extract_subdomains(text, root_domain):
                results[host] = None
                if len(results) >= limit:
                    break
        time.sleep(_REQUEST_DELAY)
    return list(results.keys())


def discover(domain: str, limit: int = 100) -> List[scanning.SubdomainResult]:
    """Discover subdomains via search engine dorking.

    Queries Bing and DuckDuckGo (Google optionally) with site: dorks to find
    indexed subdomains. Results are deduplicated and returned as SubdomainResult.
    """
    root = domain.strip().lower().rstrip(".")
    if not root:
        return []

    found: Dict[str, str] = {}

    # Bing is usually more permissive for automated queries
    for host in _query_bing(root, root, limit):
        found[host] = "search-bing"

    if len(found) < limit:
        for host in _query_duckduckgo(root, root, limit - len(found)):
            if host not in found:
                found[host] = "search-ddg"

    # Google last (most aggressive rate-limiting)
    if len(found) < limit:
        for host in _query_google(root, root, limit - len(found)):
            if host not in found:
                found[host] = "search-google"

    return [
        scanning.SubdomainResult(hostname=host, source=src)
        for host, src in found.items()
    ]

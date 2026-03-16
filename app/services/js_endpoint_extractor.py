"""JavaScript endpoint extractor.

Crawls JavaScript files loaded by a target domain and extracts:
- Hidden API endpoints (REST, GraphQL, WebSocket)
- Internal/external URLs referenced in JS bundles
- Subdomains discovered in JS
- API keys and tokens (detection only, for reporting)

Builds on js_subdomain_extractor but focused on endpoints and API paths.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from app import config
from app.services import scanning


# Endpoint patterns: matches common API path formats
_API_PATH_PATTERNS = [
    # REST paths: /api/v1/..., /v2/..., /graphql, etc.
    re.compile(r"""["'`](/(?:api|v\d+|graphql|rest|service|endpoint|rpc|ws|wss?)[^"'`\s<>]{0,200})["'`]"""),
    # Absolute URLs
    re.compile(r"""["'`](https?://[a-zA-Z0-9_\-.]+\.[a-zA-Z]{2,}[^"'`\s<>]{0,200})["'`]"""),
    # Relative paths starting with /
    re.compile(r"""["'`](/[a-zA-Z0-9_\-/]{4,100}(?:\?[^"'`\s<>]{0,100})?)["'`]"""),
    # WebSocket URLs
    re.compile(r"""["'`](wss?://[a-zA-Z0-9_\-.]+[^"'`\s<>]{0,200})["'`]"""),
    # fetch() / axios() / XMLHttpRequest patterns
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(\s*["'`]([^"'`\s]{5,200})["'`]"""),
]

_SUBDOMAIN_PATTERN = re.compile(
    r"""["'`](?:https?://)?([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+\.[a-zA-Z]{2,})(?:/[^"'`\s]*)?["'`]"""
)

_SECRET_HINTS = re.compile(
    r"""(?i)(?:api[_-]?key|apikey|token|secret|password|passwd|auth)[_-]?\s*[:=]\s*["'`]([a-zA-Z0-9_\-\.+/]{16,64})["'`]"""
)

_JS_EXTENSIONS = {".js", ".mjs", ".jsx", ".ts", ".tsx"}


@dataclass
class JsEndpoint:
    url: str
    method: str = "GET"
    source_js: str = ""
    is_api: bool = False
    is_websocket: bool = False


@dataclass
class JsDiscoveryResult:
    endpoints: List[JsEndpoint] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    secret_hints: int = 0  # count only, no values stored


def _is_js_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
    return ext in _JS_EXTENSIONS or "bundle" in path or "chunk" in path


def _fetch_text(url: str) -> Optional[str]:
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; ASMBot/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/javascript,*/*",
    }
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=config.get_scanner_timeout()) as resp:
            max_bytes = config.get_js_max_bytes()
            return resp.read(max_bytes).decode("utf-8", errors="ignore")
    except (HTTPError, URLError, OSError):
        return None


def _extract_js_links_from_html(html: str, base_url: str) -> List[str]:
    """Extract <script src=...> and inline JS file references from HTML."""
    pattern = re.compile(
        r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE
    )
    links = []
    for match in pattern.finditer(html):
        src = match.group(1).strip()
        if src:
            full = urljoin(base_url, src)
            links.append(full)
    return links


def _extract_endpoints_from_js(text: str, base_url: str) -> List[JsEndpoint]:
    found: dict[str, JsEndpoint] = {}
    for pattern in _API_PATH_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1).strip()
            if not raw or len(raw) < 2:
                continue
            # Build full URL if relative
            if raw.startswith("/"):
                parsed = urlparse(base_url)
                full = f"{parsed.scheme}://{parsed.netloc}{raw}"
            elif raw.startswith(("http://", "https://", "ws://", "wss://")):
                full = raw
            else:
                continue

            if full in found:
                continue

            is_api = any(
                seg in raw
                for seg in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/rpc/")
            )
            is_ws = raw.startswith(("ws://", "wss://"))
            found[full] = JsEndpoint(
                url=full,
                source_js=base_url,
                is_api=is_api,
                is_websocket=is_ws,
            )
    return list(found.values())


def _extract_subdomains_from_js(text: str, root_domain: str) -> List[str]:
    found: dict[str, None] = {}
    for match in _SUBDOMAIN_PATTERN.finditer(text):
        host = match.group(1).lower().rstrip(".")
        if host.endswith(root_domain) and host != root_domain:
            found[host] = None
    return list(found.keys())


def _count_secret_hints(text: str) -> int:
    return len(_SECRET_HINTS.findall(text))


def extract_from_targets(
    targets: Iterable[str],
    root_domain: str,
    max_js_files: int = 50,
) -> JsDiscoveryResult:
    """Crawl targets, find JS files, extract endpoints and subdomains.

    Args:
        targets: Base URLs to crawl (e.g. ["https://example.com"])
        root_domain: Root domain for subdomain filtering
        max_js_files: Maximum number of JS files to fetch and parse

    Returns:
        JsDiscoveryResult with all discovered data
    """
    result = JsDiscoveryResult()
    js_seen: set[str] = set()
    endpoint_seen: set[str] = set()
    subdomain_seen: set[str] = set()

    # First, try to get JS URLs from katana if available
    katana_urls = scanning.run_katana(list(targets))
    js_from_katana = [u for u in katana_urls if _is_js_url(u)]

    # Also extract from HTML pages directly
    js_from_html: List[str] = []
    for target in targets:
        html = _fetch_text(target)
        if html:
            js_from_html.extend(_extract_js_links_from_html(html, target))

    all_js_urls = list({*js_from_katana, *js_from_html})
    result.js_files = all_js_urls[:max_js_files]

    limit = config.get_endpoint_limit()
    subdomain_limit = config.get_js_subdomain_limit()

    for js_url in result.js_files:
        if js_url in js_seen:
            continue
        js_seen.add(js_url)

        text = _fetch_text(js_url)
        if not text:
            continue

        # Extract endpoints
        for ep in _extract_endpoints_from_js(text, js_url):
            if ep.url not in endpoint_seen and len(result.endpoints) < limit:
                endpoint_seen.add(ep.url)
                result.endpoints.append(ep)

        # Extract subdomains
        for sub in _extract_subdomains_from_js(text, root_domain):
            if sub not in subdomain_seen and len(result.subdomains) < subdomain_limit:
                subdomain_seen.add(sub)
                result.subdomains.append(sub)

        # Count (but never store) secret hints
        result.secret_hints += _count_secret_hints(text)

    return result


def extract_subdomains_only(targets: Iterable[str], root_domain: str) -> List[str]:
    """Lightweight wrapper — returns only subdomain list (used by asset_discovery)."""
    result = extract_from_targets(targets, root_domain)
    return result.subdomains

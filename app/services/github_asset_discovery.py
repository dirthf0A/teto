"""GitHub asset discovery module.

Searches GitHub public repositories for leaked/exposed assets:
- Subdomains mentioned in code, configs, CI/CD files
- API endpoints and internal URLs
- Exposed secrets and tokens (detection only, no exfiltration)
- Exposed domain references in package files, env files, etc.

Uses the GitHub Search API (authenticated via token for higher rate limits).
"""
from __future__ import annotations

import json
import re
import time
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus, urlencode
from urllib.request import Request, urlopen

from app import config
from app.logger import get_logger
_logger = get_logger("app.services.github_asset_discovery")
from app.services import scanning


_SUBDOMAIN_PATTERN = re.compile(
    r"(?:https?://)?([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+)"
)

_ENDPOINT_PATTERN = re.compile(
    r"""(?:["'`])(\/[a-zA-Z0-9_\-\/\.]+(?:\?[a-zA-Z0-9_=&%+.-]*)?)(?:["'`])"""
)

_API_KEY_PATTERN = re.compile(
    r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{16,})["']"""
)

_GITHUB_API = "https://api.github.com"
_REQUEST_DELAY = 2.0  # GitHub rate limit: 30 req/min unauthenticated, 30/min auth code search


def _github_request(
    path: str,
    params: Optional[Dict[str, str]] = None,
    _retry: int = 0,
) -> Optional[dict]:
    """GitHub API request with rate limit handling (429 + secondary 403 + Retry-After).

    GitHub enforces two rate limits:
      Primary:   60 req/hour unauthenticated, 5000/hour with token
      Secondary: abuse detection (burst) — responds 429 or 403 with Retry-After header

    On rate limit hit: backs off for Retry-After seconds (or 60s default), retries once.
    """
    token = config.get_github_token()
    headers: Dict[str, str] = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ASMPlatform/1.0",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    url = f"{_GITHUB_API}{path}"
    if params:
        url = f"{url}?{urlencode(params)}"

    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=15) as resp:
            # Surface remaining rate limit for diagnostics
            remaining = resp.headers.get("X-RateLimit-Remaining", "?")
            if remaining != "?" and int(remaining) < 5:
                _logger.debug("github rate limit low", remaining=remaining, path=path)
            return json.loads(resp.read().decode("utf-8"))

    except HTTPError as exc:
        if exc.code in (429, 403) and _retry == 0:
            # Rate limited — respect Retry-After header
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            wait = min(int(retry_after), 120) if retry_after and retry_after.isdigit() else 60
            _logger.warning(
                "github rate limit hit, backing off",
                status=exc.code, wait_seconds=wait, path=path,
            )
            time.sleep(wait)
            return _github_request(path, params, _retry=1)
        # 404 = not found (expected), 401 = bad token, others = transient
        if exc.code not in (404, 422):
            _logger.debug("github request failed", status=exc.code, path=path)
        return None

    except (URLError, json.JSONDecodeError, OSError) as exc:
        _logger.debug("github request error", path=path, error=str(exc))
        return None


def _search_code(query: str, per_page: int = 30) -> List[dict]:
    """Call GitHub Code Search API and return items."""
    result = _github_request("/search/code", {"q": query, "per_page": str(per_page)})
    if result and isinstance(result.get("items"), list):
        return result["items"]
    return []


def _fetch_raw_content(url: str, token: Optional[str]) -> Optional[str]:
    """Fetch raw file content from GitHub."""
    headers = {"User-Agent": "ASMPlatform/1.0"}
    if token:
        headers["Authorization"] = f"token {token}"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=10) as resp:
            return resp.read(256_000).decode("utf-8", errors="ignore")
    except (HTTPError, URLError, OSError):
        return None


def _extract_subdomains(text: str, root_domain: str) -> List[str]:
    found: Dict[str, None] = {}
    for match in _SUBDOMAIN_PATTERN.finditer(text):
        host = match.group(1).lower().rstrip(".")
        if host.endswith(root_domain) and host != root_domain:
            found[host] = None
    return list(found.keys())


def _extract_endpoints(text: str) -> List[str]:
    found: Dict[str, None] = {}
    for match in _ENDPOINT_PATTERN.finditer(text):
        ep = match.group(1)
        if len(ep) > 2 and not ep.startswith("//"):
            found[ep] = None
    return list(found.keys())


def discover_subdomains(domain: str, limit: int = 200) -> List[scanning.SubdomainResult]:
    """Search GitHub for subdomain references to the given domain."""
    root = domain.strip().lower().rstrip(".")
    if not root:
        return []

    found: Dict[str, str] = {}
    token = config.get_github_token()

    queries = [
        f'"{root}" language:yaml',
        f'"{root}" filename:.env',
        f'"{root}" filename:*.conf',
        f'"{root}" filename:*.json',
        f'"*.{root}"',
    ]

    org = config.get_github_org()
    if org:
        queries = [f"{q} org:{org}" for q in queries]

    for query in queries:
        if len(found) >= limit:
            break
        items = _search_code(query)
        time.sleep(_REQUEST_DELAY)
        for item in items:
            if len(found) >= limit:
                break
            raw_url = item.get("html_url", "").replace(
                "github.com", "raw.githubusercontent.com"
            ).replace("/blob/", "/")
            text = _fetch_raw_content(raw_url, token)
            if text:
                for host in _extract_subdomains(text, root):
                    if host not in found:
                        found[host] = "github"

    return [
        scanning.SubdomainResult(hostname=host, source=src)
        for host, src in found.items()
    ]


def discover_endpoints(domain: str, limit: int = 500) -> List[str]:
    """Search GitHub for API endpoints and internal URLs referencing the domain."""
    root = domain.strip().lower().rstrip(".")
    if not root:
        return []

    found: Dict[str, None] = {}
    token = config.get_github_token()

    queries = [
        f'"{root}/api" language:javascript',
        f'"{root}/api" language:python',
        f'"{root}" fetch OR axios OR requests language:javascript',
        f'"{root}" requests.get OR requests.post language:python',
    ]

    org = config.get_github_org()
    if org:
        queries = [f"{q} org:{org}" for q in queries]

    for query in queries:
        if len(found) >= limit:
            break
        items = _search_code(query)
        time.sleep(_REQUEST_DELAY)
        for item in items:
            if len(found) >= limit:
                break
            raw_url = item.get("html_url", "").replace(
                "github.com", "raw.githubusercontent.com"
            ).replace("/blob/", "/")
            text = _fetch_raw_content(raw_url, token)
            if text:
                for ep in _extract_endpoints(text):
                    found[ep] = None

    return list(found.keys())[:limit]


def find_exposed_secrets(domain: str, limit: int = 50) -> List[dict]:
    """Detect (not retrieve) potential secret/key exposures in GitHub for the domain.

    Returns metadata about files that may contain exposed credentials.
    Does NOT return the actual secret values — only file references.
    """
    root = domain.strip().lower().rstrip(".")
    if not root:
        return []

    token = config.get_github_token()
    results = []

    queries = [
        f'"{root}" password language:yaml',
        f'"{root}" api_key language:python',
        f'"{root}" secret language:json filename:*.env',
    ]

    org = config.get_github_org()
    if org:
        queries = [f"{q} org:{org}" for q in queries]

    for query in queries:
        if len(results) >= limit:
            break
        items = _search_code(query)
        time.sleep(_REQUEST_DELAY)
        for item in items:
            if len(results) >= limit:
                break
            results.append({
                "repo": item.get("repository", {}).get("full_name", ""),
                "file": item.get("name", ""),
                "path": item.get("path", ""),
                "url": item.get("html_url", ""),
                "source": "github-secret-scan",
            })

    return results

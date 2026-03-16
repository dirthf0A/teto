"""Deep web crawler — multi-strategy endpoint extraction.

Strategies (run in order, results merged + deduplicated):
  1. katana            — headless crawl, JavaScript rendering, form extraction
  2. gau               — GetAllUrls: Wayback Machine + CommonCrawl + VirusTotal
  3. waybackurls       — Wayback CDX API crawl
  4. passive HTML      — fetch live page and parse <a href>, <form action>,
                         <script src>, <link href>, data-url attributes
  5. JS endpoint scan  — fetch inline + external JS files, extract fetch()/axios
                         paths and API_BASE_ patterns
  6. robots.txt + sitemap — parse robots.txt Disallow/Allow + sitemap.xml URLs

Output:
  - All discovered URLs normalized and deduplicated
  - High-value endpoints (admin, API, debug, GraphQL) surfaced first

Config:
  ASM_CRAWL_STRATEGIES     — comma list: katana,gau,wayback,passive,js,robots
                             default: katana,gau,passive,js,robots
  ASM_ENDPOINT_LIMIT       — max endpoints returned per target (default 500)
  ASM_CRAWL_PASSIVE_TIMEOUT — timeout for passive HTTP fetch (default 15s)
  ASM_KATANA_DEPTH         — katana crawl depth (default 2)
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from app import config
from app.logger import get_logger
from app.services import scanning

logger = get_logger("app.services.crawler")


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _strategies() -> List[str]:
    raw = config.__dict__.get("get_crawl_strategies", lambda: None)()
    if raw:
        return [s.strip() for s in raw.split(",") if s.strip()]
    return ["katana", "gau", "passive", "js", "robots"]


HIGH_VALUE_PATHS = (
    "/admin", "/administrator", "/manager",
    "/api", "/v1", "/v2", "/v3", "/graphql", "/gql",
    "/debug", "/console", "/actuator", "/metrics",
    "/swagger", "/openapi", "/redoc", "/docs",
    "/login", "/auth", "/oauth", "/sso",
    "/upload", "/files", "/backup",
    "/wp-admin", "/wp-json", "/xmlrpc.php",
    "/.env", "/.git", "/config",
    "/internal", "/private", "/secret",
    "/phpmyadmin", "/adminer",
)

# JS patterns for API endpoint extraction
_JS_API_PATTERNS = [
    re.compile(r"""['"](/(?:api|v\d|graphql)[^'" ]{1,200})['"]"""),
    re.compile(r"""fetch\s*\(\s*['"](https?://[^'" ]{1,300}|/[^'" ]{1,200})['"]"""),
    re.compile(r"""axios\.[a-z]+\s*\(\s*['"](https?://[^'" ]{1,300}|/[^'" ]{1,200})['"]"""),
    re.compile(r"""url\s*[:=]\s*['"](https?://[^'" ]{1,300}|/[^'" ]{1,200})['"]"""),
    re.compile(r"""baseURL\s*[:=]\s*['"](https?://[^'" ]{1,200})['"]"""),
    re.compile(r"""API_BASE[A-Z_]*\s*=\s*['"](https?://[^'" ]{1,200})['"]"""),
    re.compile(r"""NEXT_PUBLIC_[A-Z_]*URL[A-Z_]*\s*=\s*['"](https?://[^'" ]{1,200})['"]"""),
]


# ---------------------------------------------------------------------------
# HTML parser for passive crawl
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Extract all URLs from HTML (href, src, action, data-url, content=url)."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: List[str] = []
        self._attrs_to_check = {"href", "src", "action", "data-url", "data-href", "data-src"}

    def handle_starttag(self, tag: str, attrs: list) -> None:
        for name, value in attrs:
            if not value:
                continue
            name_lower = name.lower()
            if name_lower in self._attrs_to_check:
                url = self._resolve(value.strip())
                if url:
                    self.links.append(url)
            # <meta http-equiv="refresh" content="0;url=...">
            if tag == "meta" and name_lower == "content" and "url=" in value.lower():
                m = re.search(r"url=([^\s;\"']+)", value, re.IGNORECASE)
                if m:
                    url = self._resolve(m.group(1))
                    if url:
                        self.links.append(url)

    def _resolve(self, raw: str) -> Optional[str]:
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        if raw.startswith("//"):
            parsed = urlparse(self.base_url)
            raw = f"{parsed.scheme}:{raw}"
        elif raw.startswith("/") or not raw.startswith("http"):
            raw = urljoin(self.base_url, raw)
        return raw if raw.startswith("http") else None


# ---------------------------------------------------------------------------
# Passive HTTP crawl
# ---------------------------------------------------------------------------

def _passive_crawl(url: str) -> List[str]:
    """Fetch a URL and extract all links from the HTML response."""
    timeout = int(getattr(config, "get_crawl_passive_timeout", lambda: 15)())
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; ASMPlatform/2.0)"})
        with urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct and "xml" not in ct:
                return []
            raw = resp.read(1_048_576).decode("utf-8", errors="ignore")  # 1 MB cap
        parser = _LinkExtractor(url)
        parser.feed(raw)
        return parser.links
    except Exception as e:
        logger.debug("passive crawl failed", url=url, error=str(e))
        return []


# ---------------------------------------------------------------------------
# JS endpoint extraction
# ---------------------------------------------------------------------------

def _js_endpoint_scan(url: str) -> List[str]:
    """Fetch a page, find all <script> tags, scan JS for API endpoints."""
    timeout = int(getattr(config, "get_crawl_passive_timeout", lambda: 15)())
    found: List[str] = []
    seen: Set[str] = set()

    def _scan_js(js_content: str, base: str) -> None:
        for pattern in _JS_API_PATTERNS:
            for m in pattern.finditer(js_content):
                raw = m.group(1).strip()
                if not raw or raw in seen:
                    continue
                seen.add(raw)
                if raw.startswith("http"):
                    found.append(raw)
                elif raw.startswith("/"):
                    parsed = urlparse(base)
                    found.append(f"{parsed.scheme}://{parsed.netloc}{raw}")

    # Fetch the page
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; ASMPlatform/2.0)"})
        with urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct:
                return []
            html = resp.read(2_097_152).decode("utf-8", errors="ignore")
    except Exception as e:
        logger.debug("js endpoint scan page fetch failed", url=url, error=str(e))
        return []

    # Scan inline scripts
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
        _scan_js(m.group(1), url)

    # Find external <script src="..."> and fetch them
    script_urls: List[str] = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        raw = m.group(1).strip()
        if raw.startswith("http"):
            script_urls.append(raw)
        elif raw.startswith("/"):
            parsed = urlparse(url)
            script_urls.append(f"{parsed.scheme}://{parsed.netloc}{raw}")

    js_limit = min(len(script_urls), 10)  # cap at 10 external scripts
    for script_url in script_urls[:js_limit]:
        try:
            req = Request(script_url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=timeout) as resp:
                js_content = resp.read(config.get_js_max_bytes()).decode("utf-8", errors="ignore")
            _scan_js(js_content, url)
        except Exception as e:
            logger.debug("js fetch failed", script_url=script_url, error=str(e))

    return found


# ---------------------------------------------------------------------------
# Robots.txt + sitemap
# ---------------------------------------------------------------------------

def _robots_sitemap(base_url: str) -> List[str]:
    """Parse robots.txt (Disallow/Allow paths) and linked sitemaps."""
    timeout = int(getattr(config, "get_crawl_passive_timeout", lambda: 15)())
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    urls: List[str] = []

    def _fetch(path: str) -> Optional[str]:
        try:
            req = Request(f"{origin}{path}", headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=timeout) as resp:
                return resp.read(524_288).decode("utf-8", errors="ignore")
        except Exception:
            return None

    # robots.txt
    robots = _fetch("/robots.txt")
    if robots:
        sitemap_urls = []
        for line in robots.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path and path != "/":
                        urls.append(f"{origin}{path}")
            elif line.lower().startswith("sitemap:"):
                sm_url = line.split(":", 1)[1].strip()
                if sm_url:
                    sitemap_urls.append(sm_url)

        # Fetch sitemaps
        if not sitemap_urls:
            sitemap_urls = [f"{origin}/sitemap.xml", f"{origin}/sitemap_index.xml"]

        for sm_url in sitemap_urls[:3]:
            sm_content = _fetch(sm_url.replace(origin, "")) if sm_url.startswith(origin) else None
            if not sm_content:
                try:
                    req = Request(sm_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urlopen(req, timeout=timeout) as resp:
                        sm_content = resp.read(524_288).decode("utf-8", errors="ignore")
                except Exception:
                    continue
            for m in re.finditer(r"<loc>(https?://[^<]+)</loc>", sm_content):
                urls.append(m.group(1).strip())

    return urls


# ---------------------------------------------------------------------------
# URL normalization + dedup
# ---------------------------------------------------------------------------

# Query params that, when numeric/high-cardinality, cause infinite crawl loops
# These are stripped to their key-only form for deduplication purposes.
_HIGH_CARDINALITY_PARAMS = frozenset({
    "id", "page", "p", "offset", "limit", "skip", "start", "end",
    "from", "to", "cursor", "token", "session", "timestamp", "ts",
    "t", "v", "ver", "version", "rand", "random", "nonce", "cb",
    "cache", "nocache", "_", "__", "ref", "utm_source", "utm_medium",
    "utm_campaign", "utm_content", "utm_term", "fbclid", "gclid",
})

# Params that look like pagination/iteration values
import re as _re
_NUMERIC_RE = _re.compile(r"^-?\d+$")


def _strip_crawl_params(query: str) -> str:
    """Remove high-cardinality query params to prevent infinite crawl loops.

    Keeps params that likely affect content/auth (e.g. ?category=news).
    Strips params that iterate (e.g. ?id=1, ?page=2, ?offset=100).
    """
    if not query:
        return ""
    from urllib.parse import parse_qsl, urlencode
    kept = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        key_lower = key.lower().rstrip("[]")
        # Strip known high-cardinality param names
        if key_lower in _HIGH_CARDINALITY_PARAMS:
            continue
        # Strip params with purely numeric values (pagination, IDs)
        if _NUMERIC_RE.match(value):
            continue
        # Strip params with UUID-like values (session tokens, nonces)
        if len(value) > 20 and _re.match(r"^[a-f0-9\-]{20,}$", value, _re.IGNORECASE):
            continue
        kept.append((key, value))
    return urlencode(kept) if kept else ""


def _normalize_url(raw: str, limit: int = 2048) -> Optional[str]:
    if not raw or len(raw) > limit:
        return None
    try:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            return None
        host = (parsed.hostname or "").lower()
        path = parsed.path.rstrip("/") or "/"
        port = parsed.port
        # Strip high-cardinality params to prevent infinite loops
        clean_query = _strip_crawl_params(parsed.query)
        query = f"?{clean_query}" if clean_query else ""
        if port and ((parsed.scheme == "https" and port != 443) or (parsed.scheme == "http" and port != 80)):
            return f"{parsed.scheme}://{host}:{port}{path}{query}"
        return f"{parsed.scheme}://{host}{path}{query}"
    except Exception:
        return None


def _is_same_domain(url: str, base_url: str) -> bool:
    try:
        url_host = urlparse(url).hostname or ""
        base_host = urlparse(base_url).hostname or ""
        # Allow subdomains of the same root
        url_parts = url_host.split(".")
        base_parts = base_host.split(".")
        return url_parts[-2:] == base_parts[-2:]
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def crawl_urls(targets: Iterable[str]) -> List[str]:
    """Crawl a list of URLs using katana (primary tool)."""
    return scanning.run_katana(list(targets))


def crawl_domain(domain: str) -> List[str]:
    """Crawl a domain with katana."""
    if not domain:
        return []
    if domain.startswith(("http://", "https://")):
        targets = [domain]
    else:
        targets = [f"https://{domain}", f"http://{domain}"]
    return crawl_urls(targets)


def deep_crawl(
    base_urls: List[str],
    strategies: Optional[List[str]] = None,
    same_domain_only: bool = True,
) -> List[str]:
    """Multi-strategy deep crawl returning deduplicated, normalized URLs.

    Strategies executed (configurable via ASM_CRAWL_STRATEGIES):
      katana   — katana headless crawl
      gau      — passive URL sources (Wayback, CommonCrawl)
      passive  — HTML link extraction
      js       — JavaScript API endpoint extraction
      robots   — robots.txt + sitemap.xml

    Args:
        base_urls:         Target URLs to crawl
        strategies:        Override strategy list (default from config)
        same_domain_only:  Filter results to same root domain as base_urls
    """
    if not base_urls:
        return []

    active = strategies or _strategies()
    limit = config.get_endpoint_limit()
    seen: Set[str] = set()
    all_urls: List[str] = []

    def _add(url: str) -> None:
        norm = _normalize_url(url)
        if not norm or norm in seen:
            return
        if same_domain_only and base_urls:
            if not any(_is_same_domain(norm, b) for b in base_urls):
                return
        seen.add(norm)
        all_urls.append(norm)

    for base_url in base_urls:
        logger.debug("deep crawl starting", url=base_url, strategies=active)

        if "katana" in active:
            try:
                for u in scanning.run_katana([base_url]):
                    _add(u)
            except Exception as e:
                logger.warning("katana crawl failed", url=base_url, error=str(e))

        if "gau" in active:
            try:
                parsed = urlparse(base_url)
                domain_name = parsed.hostname or ""
                if domain_name:
                    for u in scanning.run_gau(domain_name):
                        _add(u)
            except Exception as e:
                logger.warning("gau crawl failed", url=base_url, error=str(e))

        if "wayback" in active:
            try:
                parsed = urlparse(base_url)
                domain_name = parsed.hostname or ""
                if domain_name:
                    for u in scanning.run_waybackurls(domain_name):
                        _add(u)
            except Exception as e:
                logger.debug("waybackurls failed", url=base_url, error=str(e))

        if "passive" in active:
            try:
                for u in _passive_crawl(base_url):
                    _add(u)
            except Exception as e:
                logger.debug("passive crawl error", url=base_url, error=str(e))

        if "js" in active:
            try:
                for u in _js_endpoint_scan(base_url):
                    _add(u)
            except Exception as e:
                logger.debug("js endpoint scan error", url=base_url, error=str(e))

        if "robots" in active:
            try:
                for u in _robots_sitemap(base_url):
                    _add(u)
            except Exception as e:
                logger.debug("robots/sitemap error", url=base_url, error=str(e))

        if len(all_urls) >= limit:
            break

    logger.info(
        "deep crawl complete",
        base_urls=len(base_urls),
        urls_found=len(all_urls),
        strategies=active,
    )
    return all_urls[:limit]


def extract_high_value_endpoints(urls: Iterable[str]) -> List[str]:
    """Filter URLs to high-value security paths (admin, API, debug, etc.)."""
    results: List[str] = []
    seen: Set[str] = set()
    limit = config.get_endpoint_limit()
    for url in urls:
        if not url:
            continue
        path = urlparse(url).path.lower()
        if not any(token in path for token in HIGH_VALUE_PATHS):
            continue
        if url in seen:
            continue
        seen.add(url)
        results.append(url)
        if len(results) >= limit:
            break
    return results


def crawl_and_extract(
    base_urls: List[str],
    deep: bool = True,
) -> Dict[str, List[str]]:
    """Full crawl pipeline returning both all URLs and high-value subset.

    Returns:
        {
          "all": [...],
          "high_value": [...],
          "js_apis": [...],
          "robots_paths": [...],
        }
    """
    if deep:
        all_urls = deep_crawl(base_urls)
    else:
        all_urls = crawl_urls(base_urls)

    high_value = extract_high_value_endpoints(all_urls)

    # Separate JS API endpoints and robots paths for caller context
    js_apis = [u for u in all_urls if any(p in urlparse(u).path.lower() for p in ("/api/", "/v1/", "/v2/", "/graphql"))]
    robots_paths = [u for u in all_urls if any(p in urlparse(u).path.lower() for p in ("/.env", "/.git", "/config", "/backup"))]

    return {
        "all": all_urls,
        "high_value": high_value,
        "js_apis": js_apis[:50],
        "robots_paths": robots_paths[:20],
    }

"""Technology fingerprinting / detection module.

Detects technologies running on web assets using:
- HTTP response headers (Server, X-Powered-By, X-Generator, etc.)
- HTML meta tags and body content patterns
- Cookie names
- URL path patterns
- favicon hash matching
- JS global variable detection

Modeled after Wappalyzer's approach. Returns structured TechResult objects.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app import config


# ---------------------------------------------------------------------------
# Technology fingerprint database
# Each entry: name -> {headers, html, cookies, scripts, meta, implies}
# Patterns are strings that will be compiled to regex.
# ---------------------------------------------------------------------------
_TECH_DB: Dict[str, Dict] = {
    # Web servers
    "nginx": {
        "headers": {"Server": r"nginx(?:/[\d.]+)?"},
    },
    "apache": {
        "headers": {"Server": r"Apache(?:/[\d.]+)?"},
    },
    "iis": {
        "headers": {"Server": r"Microsoft-IIS(?:/[\d.]+)?"},
    },
    "caddy": {
        "headers": {"Server": r"Caddy"},
    },
    "openresty": {
        "headers": {"Server": r"openresty(?:/[\d.]+)?"},
    },
    # CDN/Proxy
    "cloudflare": {
        "headers": {
            "CF-RAY": r".+",
            "Server": r"cloudflare",
        },
    },
    "fastly": {
        "headers": {"Via": r"varnish", "X-Served-By": r"cache-"},
    },
    "akamai": {
        "headers": {"X-Check-Cacheable": r".+", "X-Akamai-Transformed": r".+"},
    },
    "cloudfront": {
        "headers": {"Via": r"CloudFront"},
    },
    # Cloud providers
    "aws": {
        "headers": {"x-amz-request-id": r".+", "x-amz-id-2": r".+"},
    },
    "aws-s3": {
        "headers": {"x-amz-bucket-region": r".+", "Server": r"AmazonS3"},
    },
    "azure": {
        "headers": {"x-ms-request-id": r".+", "x-azure-ref": r".+"},
    },
    "gcp": {
        "headers": {"x-goog-stored-content-encoding": r".+", "server": r"UploadServer"},
    },
    # Languages/frameworks
    "php": {
        "headers": {"X-Powered-By": r"PHP(?:/[\d.]+)?"},
        "cookies": {"PHPSESSID": r".+"},
    },
    "python": {
        "headers": {"X-Powered-By": r"Python(?:/[\d.]+)?"},
    },
    "ruby": {
        "headers": {"X-Powered-By": r"Phusion Passenger|Ruby"},
        "cookies": {"_session_id": r".+"},
    },
    "java": {
        "headers": {"X-Powered-By": r"JSP|Servlet|Tomcat|JBoss|WildFly"},
        "cookies": {"JSESSIONID": r".+"},
    },
    "asp.net": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".+"},
        "cookies": {"ASP.NET_SessionId": r".+", "ASPXAUTH": r".+"},
    },
    "node.js": {
        "headers": {"X-Powered-By": r"Express"},
    },
    # CMS
    "wordpress": {
        "html": r'<meta name="generator" content="WordPress|wp-content/|wp-includes/',
        "cookies": {"wordpress_logged_in": r".+", "wp-settings": r".+"},
    },
    "drupal": {
        "html": r'Drupal\.settings|/sites/default/files|drupal\.js',
        "headers": {"X-Generator": r"Drupal(?:\s[\d.]+)?"},
        "cookies": {"SESS[a-f0-9]+": r".+"},
    },
    "joomla": {
        "html": r'/media/jui/|Joomla!',
        "cookies": {"joomla_user_state": r".+"},
    },
    "shopify": {
        "html": r'cdn\.shopify\.com|Shopify\.theme',
        "cookies": {"_shopify_y": r".+"},
    },
    "magento": {
        "html": r'Magento|mage/|Mage\.Cookies',
        "cookies": {"frontend": r".+"},
    },
    "ghost": {
        "html": r'<meta name="generator" content="Ghost',
    },
    # JavaScript frameworks
    "react": {
        "html": r'__REACT_DEVTOOLS|data-reactroot|data-reactid|react\.development\.js|react\.production\.min\.js',
    },
    "vue.js": {
        "html": r'data-v-[a-f0-9]+|Vue\.config|__vue_store__',
    },
    "angular": {
        "html": r'ng-version=|angular\.min\.js|<app-root|ng-app=',
    },
    "next.js": {
        "html": r'__NEXT_DATA__|_next/static/|next\.config\.js',
    },
    "nuxt.js": {
        "html": r'__NUXT__|/_nuxt/',
    },
    # Databases/backend indicators
    "mysql": {
        "html": r"mysql_connect|mysqli_connect|PDO.*mysql",
    },
    "elasticsearch": {
        "headers": {"X-Elastic-Product": r".+"},
    },
    # Analytics/tracking
    "google-analytics": {
        "html": r'google-analytics\.com/ga\.js|ga\(\'create\'|gtag\(\'config\'',
    },
    "cloudflare-turnstile": {
        "html": r'challenges\.cloudflare\.com/turnstile',
    },
    # Security
    "waf-cloudflare": {
        "html": r"Attention Required! \| Cloudflare",
    },
    "sucuri": {
        "headers": {"X-Sucuri-ID": r".+"},
    },
    "modsecurity": {
        "headers": {"Server": r"mod_security|Mod_Security"},
    },
    # Load balancers
    "haproxy": {
        "headers": {"Server": r"haproxy(?:/[\d.]+)?"},
    },
    "traefik": {
        "headers": {"Server": r"traefik"},
    },
    # Auth providers
    "auth0": {
        "html": r'cdn\.auth0\.com|auth0\.js',
    },
    "okta": {
        "html": r'cdn\.jsdelivr\.net/npm/@okta|okta-signin-widget',
    },
    # Monitoring
    "datadog": {
        "html": r'browser\.datadoghq\.com|DD_LOGS|DD_RUM',
    },
    "sentry": {
        "html": r'browser\.sentry-cdn\.com|Sentry\.init',
    },
    # Email
    "sendgrid": {
        "headers": {"X-SG-EID": r".+"},
    },
    # Other
    "varnish": {
        "headers": {"Via": r"varnish", "X-Varnish": r".+"},
    },
    "jquery": {
        "html": r'jquery(?:\.min)?\.js|jQuery\.fn\.jquery',
    },
    "bootstrap": {
        "html": r'bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js',
    },
    "recaptcha": {
        "html": r'google\.com/recaptcha|g-recaptcha',
    },
}

# Compile all patterns
_COMPILED_DB: Dict[str, Dict] = {}
for _tech, _rules in _TECH_DB.items():
    _compiled: Dict = {}
    if "headers" in _rules:
        _compiled["headers"] = {
            h: re.compile(p, re.IGNORECASE)
            for h, p in _rules["headers"].items()
        }
    if "html" in _rules:
        _compiled["html"] = re.compile(_rules["html"], re.IGNORECASE)
    if "cookies" in _rules:
        _compiled["cookies"] = {
            re.compile(k, re.IGNORECASE): re.compile(v, re.IGNORECASE)
            for k, v in _rules["cookies"].items()
        }
    if "scripts" in _rules:
        _compiled["scripts"] = re.compile(_rules["scripts"], re.IGNORECASE)
    _COMPILED_DB[_tech] = _compiled


@dataclass
class TechResult:
    url: str
    technologies: List[str] = field(default_factory=list)
    server: Optional[str] = None
    tls_info: Optional[Dict] = None
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)


def _parse_set_cookie(cookie_header: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def _detect_from_response(
    url: str,
    status: int,
    headers: Dict[str, str],
    body: str,
) -> List[str]:
    detected = []

    # Parse cookies from Set-Cookie header
    cookie_vals: Dict[str, str] = {}
    cookie_header = headers.get("set-cookie", "")
    if cookie_header:
        cookie_vals = _parse_set_cookie(cookie_header)

    for tech, rules in _COMPILED_DB.items():
        matched = False

        # Check headers
        if "headers" in rules:
            for header_name, pattern in rules["headers"].items():
                val = headers.get(header_name.lower(), "")
                if val and pattern.search(val):
                    matched = True
                    break

        # Check HTML body
        if not matched and "html" in rules:
            if rules["html"].search(body):
                matched = True

        # Check cookies
        if not matched and "cookies" in rules:
            for k_pattern, v_pattern in rules["cookies"].items():
                for cookie_name, cookie_val in cookie_vals.items():
                    if k_pattern.search(cookie_name):
                        if v_pattern.pattern == ".+" or v_pattern.search(cookie_val):
                            matched = True
                            break
                if matched:
                    break

        if matched:
            detected.append(tech)

    return detected


def detect(url: str) -> TechResult:
    """Probe a URL and return detected technologies.

    Fetches the URL and analyzes headers + body to identify technology stack.
    """
    result = TechResult(url=url)
    headers_dict: Dict[str, str] = {}
    body = ""
    status = 0

    request = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; TechDetect/1.0)",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
    )

    try:
        with urlopen(request, timeout=config.get_scanner_timeout()) as resp:
            status = resp.status
            # Normalize header names to lowercase
            for k, v in resp.headers.items():
                headers_dict[k.lower()] = v
            body = resp.read(config.get_js_max_bytes()).decode("utf-8", errors="ignore")
    except HTTPError as e:
        status = e.code
        for k, v in e.headers.items():
            headers_dict[k.lower()] = v
        try:
            body = e.read(50_000).decode("utf-8", errors="ignore")
        except OSError:
            pass
    except (URLError, OSError):
        return result

    result.status_code = status
    result.headers = headers_dict
    result.server = headers_dict.get("server")
    result.technologies = _detect_from_response(url, status, headers_dict, body)

    return result


def detect_bulk(urls: List[str]) -> List[TechResult]:
    """Detect technologies for multiple URLs."""
    results = []
    for url in urls:
        results.append(detect(url))
    return results


def technologies_to_str(techs: List[str]) -> str:
    """Serialize technology list to comma-separated string for DB storage."""
    return ",".join(sorted(set(techs)))


def str_to_technologies(tech_str: Optional[str]) -> List[str]:
    """Deserialize technology string from DB."""
    if not tech_str:
        return []
    return [t.strip() for t in tech_str.split(",") if t.strip()]

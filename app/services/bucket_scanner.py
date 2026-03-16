from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app import config


EXISTS_CODES = {200, 204, 301, 302, 307, 401, 403}
S3_ENDPOINT = "https://{name}.s3.amazonaws.com"
S3_WEBSITE_ENDPOINT = "https://{name}.s3-website-{region}.amazonaws.com"
GCP_ENDPOINT = "https://storage.googleapis.com/{name}"
GCP_ENDPOINT_VHOST = "https://{name}.storage.googleapis.com"
AZURE_BLOB_ENDPOINT = "https://{name}.blob.core.windows.net"


@dataclass
class BucketHit:
    name: str
    provider: str
    url: str
    status_code: int


def _load_bucket_words() -> List[str]:
    words: List[str] = []
    wordlist = config.get_bucket_wordlist()
    limit = config.get_bucket_limit()
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
        for token in config.get_bucket_words().split(","):
            cleaned = token.strip()
            if cleaned:
                words.append(cleaned)
        words = words[:limit]
    return words


def _domain_token(domain: str) -> str:
    parts = [part for part in domain.lower().split(".") if part]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else domain


def generate_bucket_candidates(domains: Iterable[str]) -> List[str]:
    words = _load_bucket_words()
    seen = set()
    results: List[str] = []
    limit = config.get_bucket_limit()
    for domain in domains:
        if not domain:
            continue
        base = _domain_token(domain)
        base_clean = base.replace("_", "-")
        base_dash = domain.replace(".", "-").replace("_", "-")
        base_compact = domain.replace(".", "").replace("_", "")
        for token in {base_clean, base_dash, base_compact}:
            if token and token not in seen:
                seen.add(token)
                results.append(token)
                if len(results) >= limit:
                    return results
            for word in words:
                for candidate in (
                    f"{token}-{word}",
                    f"{word}-{token}",
                    f"{token}{word}",
                    f"{word}{token}",
                ):
                    candidate = candidate.strip("-")
                    if not candidate or candidate in seen:
                        continue
                    seen.add(candidate)
                    results.append(candidate)
                    if len(results) >= limit:
                        return results
    return results


def _probe_url(url: str, timeout: int) -> Optional[int]:
    request = Request(url, headers={"User-Agent": "asm-platform"}, method="HEAD")
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status if hasattr(response, "status") else response.getcode()
    except HTTPError as exc:
        return exc.code
    except URLError:
        return None


def probe_buckets(names: Iterable[str]) -> List[BucketHit]:
    timeout = config.get_bucket_probe_timeout()
    results: List[BucketHit] = []
    for name in names:
        if not name:
            continue
        urls = [
            ("aws", S3_ENDPOINT.format(name=name)),
            ("gcp", GCP_ENDPOINT.format(name=name)),
            ("gcp", GCP_ENDPOINT_VHOST.format(name=name)),
            ("azure", AZURE_BLOB_ENDPOINT.format(name=name)),
        ]
        for provider, url in urls:
            status = _probe_url(url, timeout)
            if status is None:
                continue
            if status in EXISTS_CODES:
                results.append(BucketHit(name=name, provider=provider, url=url, status_code=status))
                break
    return results

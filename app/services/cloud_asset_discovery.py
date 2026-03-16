from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from app import config
from app.services import bucket_scanner


CDN_SUFFIXES = (
    ".cloudfront.net",
    ".fastly.net",
    ".akamaized.net",
    ".edgekey.net",
    ".edgesuite.net",
    ".azureedge.net",
    ".cdn.jsdelivr.net",
)
CLOUDFLARE_SUFFIXES = (
    ".pages.dev",
    ".workers.dev",
    ".r2.dev",
    ".cloudflare.net",
    ".cdn.cloudflare.net",
    ".r2.cloudflarestorage.com",
)
GCP_SUFFIXES = (".storage.googleapis.com", ".storage.cloud.google.com")
AZURE_SUFFIXES = (
    ".blob.core.windows.net",
    ".file.core.windows.net",
    ".queue.core.windows.net",
    ".table.core.windows.net",
    ".azurewebsites.net",
    ".azure-api.net",
)


@dataclass
class CloudAsset:
    host: str
    service: str
    provider: str
    url: str


def _normalize_host(raw: str) -> Optional[str]:
    if not raw:
        return None
    value = raw.strip()
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    value = value.split(":")[0].strip().lower().rstrip(".")
    if not value:
        return None
    return value


def identify_cloud_host(host: str) -> Optional[tuple[str, str]]:
    value = host.lower().rstrip(".")
    if not value:
        return None
    if value.endswith(".s3.amazonaws.com") or value.endswith(".s3.amazonaws.com.cn"):
        return ("s3", "aws")
    if ".s3-website-" in value and value.endswith(".amazonaws.com"):
        return ("s3-website", "aws")
    if ".s3-website." in value and value.endswith(".amazonaws.com"):
        return ("s3-website", "aws")
    if ".s3." in value and value.endswith(".amazonaws.com"):
        return ("s3", "aws")
    if value.endswith(GCP_SUFFIXES):
        return ("gcp-storage", "gcp")
    if value.endswith(AZURE_SUFFIXES):
        return ("azure", "azure")
    if value.endswith(CDN_SUFFIXES):
        return ("cdn", "cdn")
    if value.endswith(CLOUDFLARE_SUFFIXES):
        return ("cloudflare", "cloudflare")
    return None


def discover_from_hosts(hosts: Iterable[str]) -> List[CloudAsset]:
    results: List[CloudAsset] = []
    seen = set()
    for raw in hosts:
        host = _normalize_host(raw)
        if not host or host in seen:
            continue
        service_info = identify_cloud_host(host)
        if not service_info:
            continue
        service, provider = service_info
        seen.add(host)
        results.append(CloudAsset(host=host, service=service, provider=provider, url=f"https://{host}"))
    return results


def discover_bucket_assets(domains: Iterable[str]) -> List[CloudAsset]:
    if not config.get_cloud_enum_enabled():
        return []
    candidates = bucket_scanner.generate_bucket_candidates(domains)
    hits = bucket_scanner.probe_buckets(candidates)
    assets: List[CloudAsset] = []
    for hit in hits:
        service = "s3" if hit.provider == "aws" else "gcp-storage" if hit.provider == "gcp" else "azure-storage"
        assets.append(CloudAsset(host=urlparse(hit.url).hostname or hit.url, service=service, provider=hit.provider, url=hit.url))
    return assets

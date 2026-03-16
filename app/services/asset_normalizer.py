"""Asset normalization and deduplication.

Ensures the asset database stays clean by:
1. Normalizing: canonicalizing hostnames, IPs, URLs to consistent formats
2. Deduplicating: detecting and merging duplicate asset records

Duplicate detection uses multiple strategies:
- Exact match on (type, domain, subdomain, ip, port, protocol)
- Fingerprint-based matching (SHA256 of canonical key)
- CNAME/redirect-based merging
"""
from __future__ import annotations

import ipaddress
import re
from hashlib import sha256
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset
from app.logger import get_logger
logger = get_logger('app.services.asset_normalizer')


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_hostname(raw: Optional[str]) -> Optional[str]:
    """Canonical hostname: lowercase, no trailing dot, no wildcard prefix."""
    if not raw:
        return None
    value = str(raw).strip().lower().rstrip(".")
    # Remove wildcard prefix
    if value.startswith("*."):
        value = value[2:]
    # Remove http(s):// if accidentally present
    if "://" in value:
        try:
            value = urlparse(f"https://{value}" if not value.startswith("http") else value).hostname or value
        except Exception as e:
            logger.warning('unexpected error', error=str(e))
            pass
    value = value.rstrip(".")
    return value or None


def normalize_ip(raw: Optional[str]) -> Optional[str]:
    """Canonical IP address string. Returns None if invalid."""
    if not raw:
        return None
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def normalize_url(raw: Optional[str]) -> Optional[str]:
    """Canonical URL: lowercase scheme+host, preserve path."""
    if not raw:
        return None
    try:
        parsed = urlparse(raw.strip())
        scheme = (parsed.scheme or "https").lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        path = parsed.path.rstrip("/") or ""
        query = f"?{parsed.query}" if parsed.query else ""
        if port and ((scheme == "https" and port != 443) or (scheme == "http" and port != 80)):
            return f"{scheme}://{host}:{port}{path}{query}"
        return f"{scheme}://{host}{path}{query}"
    except Exception:
        return raw


def normalize_protocol(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    return raw.strip().lower()


def normalize_asset_type(raw: Optional[str]) -> str:
    known = {"domain", "subdomain", "ip", "cloud", "endpoint", "service", "external_domain"}
    if raw and raw.lower() in known:
        return raw.lower()
    return "unknown"


def canonical_key(
    asset_type: Optional[str],
    domain: Optional[str],
    subdomain: Optional[str],
    ip: Optional[str],
    port: Optional[int],
    protocol: Optional[str],
    url: Optional[str],
) -> Tuple:
    """Return a normalized tuple suitable for deduplication comparisons."""
    return (
        normalize_asset_type(asset_type),
        normalize_hostname(domain),
        normalize_hostname(subdomain),
        normalize_ip(ip),
        int(port) if port else None,
        normalize_protocol(protocol),
        normalize_url(url),
    )


def fingerprint(
    asset_type: Optional[str],
    domain: Optional[str],
    subdomain: Optional[str],
    ip: Optional[str],
    port: Optional[int],
    protocol: Optional[str],
    url: Optional[str],
) -> str:
    """SHA256 fingerprint of the canonical key for fast duplicate detection."""
    key = "|".join(str(v) if v is not None else "" for v in canonical_key(
        asset_type, domain, subdomain, ip, port, protocol, url
    ))
    return sha256(key.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def find_duplicate(db: Session, org_id: int, asset: Asset) -> Optional[Asset]:
    """Find an existing asset in the DB that is a duplicate of the given asset.

    Checks exact canonical key match first, then looser subdomain/IP match.
    """
    fp = fingerprint(
        asset.asset_type, asset.domain, asset.subdomain,
        asset.ip, asset.port, asset.protocol, asset.url,
    )

    # 1. Try by fingerprint if stored (fast path)
    # (fingerprint column would need to be added to Asset model — we fall back to query)

    # 2. Exact canonical match
    key = canonical_key(
        asset.asset_type, asset.domain, asset.subdomain,
        asset.ip, asset.port, asset.protocol, asset.url,
    )
    atype, domain, subdomain, ip, port, protocol, url = key

    query = select(Asset).where(Asset.org_id == org_id)

    if subdomain:
        query = query.where(Asset.subdomain == subdomain)
    elif domain:
        query = query.where(Asset.domain == domain)
    elif ip:
        query = query.where(Asset.ip == ip)
    else:
        return None

    if port:
        query = query.where(Asset.port == port)
    if protocol:
        query = query.where(Asset.protocol == protocol)

    existing = db.execute(query).scalars().first()
    return existing


def merge_assets(primary: Asset, duplicate: Asset) -> Asset:
    """Merge duplicate's fields into primary, keeping best values.

    Primary asset is kept; duplicate should be deleted after this call.
    The primary is enriched with any non-null fields from duplicate.
    """
    # Merge source tracking
    if duplicate.technology and not primary.technology:
        primary.technology = duplicate.technology
    elif duplicate.technology and primary.technology:
        # Merge technology lists
        existing = set(t.strip().lower() for t in (primary.technology or "").split(",") if t.strip())
        for t in (duplicate.technology or "").split(","):
            t = t.strip()
            if t and t.lower() not in existing:
                primary.technology = f"{primary.technology},{t}" if primary.technology else t

    # Enrich with additional metadata from duplicate
    for field in ("asn", "hosting_provider", "cdn", "country", "environment"):
        if not getattr(primary, field) and getattr(duplicate, field):
            setattr(primary, field, getattr(duplicate, field))

    # Use highest importance/exposure
    if duplicate.importance and (not primary.importance or duplicate.importance > primary.importance):
        primary.importance = duplicate.importance
    if duplicate.exposure_score and (not primary.exposure_score or duplicate.exposure_score > primary.exposure_score):
        primary.exposure_score = duplicate.exposure_score

    # Extend tags
    if duplicate.tags and not primary.tags:
        primary.tags = duplicate.tags
    elif duplicate.tags and primary.tags:
        existing_tags = set(t.strip().lower() for t in primary.tags.split(","))
        for tag in duplicate.tags.split(","):
            tag = tag.strip()
            if tag and tag.lower() not in existing_tags:
                primary.tags = f"{primary.tags},{tag}"

    # Keep earliest first_seen
    if duplicate.first_seen and primary.first_seen and duplicate.first_seen < primary.first_seen:
        primary.first_seen = duplicate.first_seen

    # Keep latest last_seen
    if duplicate.last_seen and primary.last_seen and duplicate.last_seen > primary.last_seen:
        primary.last_seen = duplicate.last_seen

    return primary


def deduplicate_org_assets(db: Session, org_id: int, dry_run: bool = False) -> Dict[str, int]:
    """Run deduplication across all assets for an organization.

    Finds duplicate assets, merges them, and deletes the duplicates.

    Returns:
        dict with stats: {"scanned": N, "duplicates_found": N, "merged": N}
    """
    all_assets = db.execute(
        select(Asset).where(Asset.org_id == org_id).order_by(Asset.id)
    ).scalars().all()

    seen: Dict[str, int] = {}  # fingerprint -> primary asset id
    duplicates: List[Tuple[Asset, Asset]] = []  # (primary, duplicate)
    stats = {"scanned": len(all_assets), "duplicates_found": 0, "merged": 0}

    for asset in all_assets:
        fp = fingerprint(
            asset.asset_type, asset.domain, asset.subdomain,
            asset.ip, asset.port, asset.protocol, asset.url,
        )
        if fp in seen:
            # Find primary
            primary_id = seen[fp]
            primary = db.execute(select(Asset).where(Asset.id == primary_id)).scalar_one_or_none()
            if primary:
                duplicates.append((primary, asset))
                stats["duplicates_found"] += 1
        else:
            seen[fp] = asset.id

    if not dry_run:
        for primary, dup in duplicates:
            merge_assets(primary, dup)
            db.delete(dup)
            stats["merged"] += 1
        db.commit()

    return stats


def normalize_asset_record(asset: Asset) -> Asset:
    """Normalize all fields of an Asset record in-place."""
    if asset.domain:
        asset.domain = normalize_hostname(asset.domain)
    if asset.subdomain:
        asset.subdomain = normalize_hostname(asset.subdomain)
    if asset.ip:
        asset.ip = normalize_ip(asset.ip) or asset.ip
    if asset.url:
        asset.url = normalize_url(asset.url)
    if asset.protocol:
        asset.protocol = normalize_protocol(asset.protocol)
    if asset.asset_type:
        asset.asset_type = normalize_asset_type(asset.asset_type)
    return asset

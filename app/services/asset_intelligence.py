from __future__ import annotations

from hashlib import sha256
from typing import Iterable, Optional

from app.services.scanning import ScanFinding
from app.services import risk_engine


def asset_key(
    asset_type: str,
    domain: Optional[str],
    subdomain: Optional[str],
    ip: Optional[str],
    port: Optional[int],
    protocol: Optional[str],
    url: Optional[str],
) -> tuple:
    return (asset_type or "unknown", domain, subdomain, ip, port, protocol, url)


def edge_key(source_id: int, target_id: int, relation: str) -> tuple:
    return (source_id, target_id, relation)


def compute_asset_importance(environment: Optional[str], tags: Optional[str], asset_type: Optional[str]) -> float:
    return risk_engine.importance_score(environment, tags, asset_type)


def classify_exposure(
    environment: Optional[str],
    tags: Optional[str],
    asset_type: Optional[str],
    ip: Optional[str] = None,
    is_public: Optional[bool] = None,
) -> str:
    return risk_engine.classify_exposure(environment, tags, asset_type, ip=ip, is_public=is_public)


def exposure_score(exposure_class: str) -> float:
    return risk_engine.exposure_score(exposure_class)


def merge_technology(existing: Optional[str], new: Optional[Iterable[str] | str]) -> Optional[str]:
    if not existing and not new:
        return None
    existing_items = [item.strip() for item in (existing or "").split(",") if item.strip()]
    if isinstance(new, str):
        new_items = [item.strip() for item in new.split(",") if item.strip()]
    elif new is None:
        new_items = []
    else:
        new_items = [str(item).strip() for item in new if str(item).strip()]
    combined = []
    seen = set()
    for item in existing_items + new_items:
        if not item or item.lower() in seen:
            continue
        seen.add(item.lower())
        combined.append(item)
    return ",".join(combined) if combined else None


def fingerprint_for_finding(finding: ScanFinding, target: str) -> str:
    raw = "|".join(
        [
            finding.tool or "",
            finding.template_id or "",
            finding.title or "",
            target or finding.target or "",
            str(finding.port or ""),
            finding.cve or "",
        ]
    )
    return sha256(raw.encode("utf-8")).hexdigest()[:32]


def fingerprint_for_asset(
    asset_type: Optional[str],
    domain: Optional[str],
    subdomain: Optional[str],
    ip: Optional[str],
    port: Optional[int],
    protocol: Optional[str],
    url: Optional[str],
) -> str:
    raw = "|".join(
        [
            asset_type or "",
            domain or "",
            subdomain or "",
            ip or "",
            str(port or ""),
            protocol or "",
            url or "",
        ]
    )
    return sha256(raw.encode("utf-8")).hexdigest()[:32]

from __future__ import annotations

from typing import Iterable, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Asset, AssetChange, AssetSnapshot, Scan
from app.services import asset_intelligence


ASSET_SCAN_TYPES = {"asset_discovery", "deep", "service", "exposed"}


def _previous_asset_scan(db: Session, scan: Scan) -> Optional[Scan]:
    return (
        db.execute(
            select(Scan)
            .where(
                Scan.org_id == scan.org_id,
                Scan.scan_type.in_(ASSET_SCAN_TYPES),
                Scan.completed_at.is_not(None),
                Scan.completed_at < (scan.completed_at or scan.started_at),
            )
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )


def _assets_seen_in_scan(db: Session, scan: Scan) -> List[Asset]:
    if not scan.started_at:
        return []
    return (
        db.execute(
            select(Asset).where(
                Asset.org_id == scan.org_id,
                Asset.last_seen >= scan.started_at,
            )
        )
        .scalars()
        .all()
    )


def snapshot_assets(db: Session, scan: Scan, assets: Optional[Iterable[Asset]] = None) -> List[AssetSnapshot]:
    if scan.scan_type not in ASSET_SCAN_TYPES:
        return []
    existing = db.execute(
        select(func.count()).select_from(AssetSnapshot).where(AssetSnapshot.scan_id == scan.id)
    ).scalar_one()
    if existing:
        return (
            db.execute(select(AssetSnapshot).where(AssetSnapshot.scan_id == scan.id))
            .scalars()
            .all()
        )
    if assets is None:
        assets = _assets_seen_in_scan(db, scan)
    snapshots: List[AssetSnapshot] = []
    for asset in assets:
        fingerprint = asset_intelligence.fingerprint_for_asset(
            asset.asset_type,
            asset.domain,
            asset.subdomain,
            asset.ip,
            asset.port,
            asset.protocol,
            asset.url,
        )
        snapshot = AssetSnapshot(
            org_id=scan.org_id,
            scan_id=scan.id,
            asset_id=asset.id,
            fingerprint=fingerprint,
            asset_type=asset.asset_type,
            domain=asset.domain,
            subdomain=asset.subdomain,
            ip=asset.ip,
            port=asset.port,
            protocol=asset.protocol,
            url=asset.url,
            service=asset.service,
        )
        db.add(snapshot)
        snapshots.append(snapshot)
    return snapshots


def diff_assets(db: Session, scan: Scan, snapshots: Optional[List[AssetSnapshot]] = None) -> List[AssetChange]:
    if scan.scan_type not in ASSET_SCAN_TYPES:
        return []
    existing = db.execute(
        select(func.count()).select_from(AssetChange).where(AssetChange.scan_id == scan.id)
    ).scalar_one()
    if existing:
        return []
    previous = _previous_asset_scan(db, scan)
    if not previous:
        return []
    if snapshots is None:
        snapshots = (
            db.execute(select(AssetSnapshot).where(AssetSnapshot.scan_id == scan.id))
            .scalars()
            .all()
        )
    prev_snapshots = (
        db.execute(select(AssetSnapshot).where(AssetSnapshot.scan_id == previous.id))
        .scalars()
        .all()
    )
    prev_fingerprints = {snapshot.fingerprint for snapshot in prev_snapshots}
    changes: List[AssetChange] = []
    for snapshot in snapshots:
        if snapshot.fingerprint in prev_fingerprints:
            continue
        change_type = "asset_discovered"
        detail = snapshot.subdomain or snapshot.domain or snapshot.ip or snapshot.url or ""
        if snapshot.asset_type == "service":
            change_type = "port_exposed"
            detail = f"{snapshot.subdomain or snapshot.ip}:{snapshot.port}/{snapshot.protocol or 'tcp'}"
        if snapshot.asset_type == "endpoint":
            change_type = "endpoint_discovered"
        change = AssetChange(
            org_id=scan.org_id,
            scan_id=scan.id,
            asset_id=snapshot.asset_id,
            change_type=change_type,
            detail=detail,
        )
        db.add(change)
        changes.append(change)
    return changes

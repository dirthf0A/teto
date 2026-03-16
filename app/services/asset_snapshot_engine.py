from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models import Asset, AssetChange, AssetSnapshot, Scan
from app.services import asset_diff


def snapshot_assets(db: Session, scan: Scan, assets: Optional[Iterable[Asset]] = None) -> List[AssetSnapshot]:
    return asset_diff.snapshot_assets(db, scan, assets=assets)


def diff_assets(db: Session, scan: Scan, snapshots: Optional[List[AssetSnapshot]] = None) -> List[AssetChange]:
    return asset_diff.diff_assets(db, scan, snapshots=snapshots)


def snapshot_and_diff(
    db: Session, scan: Scan, assets: Optional[Iterable[Asset]] = None
) -> Tuple[List[AssetSnapshot], List[AssetChange]]:
    snapshots = snapshot_assets(db, scan, assets=assets)
    changes = diff_assets(db, scan, snapshots=snapshots)
    return snapshots, changes

from datetime import datetime, timedelta

from typing import Optional
from sqlalchemy.orm import Session

from app.models import Scan
from app.services.queue import get_queue


def create_scheduled_scan(
    db: Session,
    org_id: int,
    scan_type: str,
    asset_id: Optional[int] = None,
    dedup_window_minutes: int = 30,
) -> Optional[Scan]:
    """Create a scheduled scan if no identical scan is already pending.

    Prevents duplicate scans by checking for existing scheduled/running scans
    of the same type within the dedup_window_minutes window.
    """
    from sqlalchemy import select
    from app.models import Scan

    # Dedup check: skip if identical scan already scheduled or running
    cutoff = datetime.utcnow() - timedelta(minutes=dedup_window_minutes)
    existing = db.execute(
        select(Scan).where(
            Scan.org_id == org_id,
            Scan.scan_type == scan_type,
            Scan.asset_id == asset_id,
            Scan.status.in_(["scheduled", "running"]),
            Scan.scheduled_at >= cutoff,
        ).limit(1)
    ).scalar_one_or_none()

    if existing:
        return existing  # Return the already-scheduled scan, don't create duplicate

    scan = Scan(
        org_id=org_id,
        asset_id=asset_id,
        scan_type=scan_type,
        status="scheduled",
        scheduled_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    try:
        queue = get_queue()
    except Exception:
        queue = None
    if queue:
        queue.enqueue(scan.id, scan_type=scan_type)
    return scan


def should_run_deep_scan(now: datetime) -> bool:
    # Monthly on day 1.
    return now.day == 1


def next_daily_run(now: datetime) -> datetime:
    return now + timedelta(days=1)

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler

from backend import config
from backend.db import SessionLocal, init_db
from backend.models import ScanJob, Target
from backend.services.queue import get_queue


logging.basicConfig(level=logging.INFO, format="[scheduler] %(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def enqueue_scans() -> None:
    queue = get_queue()
    session = SessionLocal()
    try:
        targets = session.query(Target).filter(Target.status == "active").all()
        if not targets:
            logger.info("no targets to schedule")
            return
        for target in targets:
            job = ScanJob(target_id=target.id, status="queued")
            session.add(job)
            session.flush()
            queue.enqueue(job.id)
            logger.info("enqueued scheduled scan for %s", target.domain)
        session.commit()
    finally:
        session.close()


def main() -> None:
    init_db()
    interval_hours = max(1, config.get_asset_scan_interval_hours())
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(enqueue_scans, "interval", hours=interval_hours, next_run_time=_utcnow())
    scheduler.start()
    logger.info("scheduler started with %s hour interval", interval_hours)
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        scheduler.shutdown()


if __name__ == "__main__":
    main()

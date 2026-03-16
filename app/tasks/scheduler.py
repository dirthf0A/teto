"""Production scan scheduler with adaptive priority scheduling.

Jobs:
  1. asset_discovery  — every ASM_ASSET_SCAN_INTERVAL_HOURS (default: 6h)
  2. vuln             — every ASM_VULN_SCAN_INTERVAL_DAYS   (default: 1d)
  3. deep             — every ASM_DEEP_SCAN_INTERVAL_DAYS   (default: 7d)
  4. adaptive_vuln    — every 30 min: score all assets, enqueue high-priority
  5. siem_export      — every ASM_SIEM_AUTO_EXPORT_HOURS (default: 1h, if enabled)
  6. escalations      — every 1h: re-alert unacknowledged critical/high alerts
  7. queue_gc         — every 10 min: flush ready retries, clean stale workers
"""
from __future__ import annotations

from datetime import datetime

from apscheduler.schedulers.blocking import BlockingScheduler
from sqlalchemy import select

from app import config
from app.db import SessionLocal, init_db
from app.logger import get_logger
from app.models import Organization
from app.services.monitoring import create_scheduled_scan

logger = get_logger("app.tasks.scheduler")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _all_org_ids():
    db = SessionLocal()
    try:
        return db.execute(select(Organization.id)).scalars().all()
    finally:
        db.close()


def enqueue_scan_for_all_orgs(scan_type: str) -> None:
    db = SessionLocal()
    try:
        org_ids = db.execute(select(Organization.id)).scalars().all()
        for org_id in org_ids:
            create_scheduled_scan(db, org_id, scan_type)
        logger.info("scheduled scan for all orgs", scan_type=scan_type, org_count=len(org_ids))
    except Exception as e:
        logger.error("enqueue scan failed", scan_type=scan_type, error=str(e), exc_info=True)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Adaptive scheduling job
# ---------------------------------------------------------------------------

def run_adaptive_scheduling() -> None:
    """Score all assets by risk and enqueue high-priority scans immediately."""
    from app.services.adaptive_scanner import schedule_adaptive_scans

    db = SessionLocal()
    try:
        org_ids = db.execute(select(Organization.id)).scalars().all()
        total_enqueued = 0
        for org_id in org_ids:
            result = schedule_adaptive_scans(db, org_id, scan_type="vuln", max_assets=20)
            total_enqueued += result.get("enqueued", 0)
        if total_enqueued:
            logger.info("adaptive scheduling complete", total_enqueued=total_enqueued)
    except Exception as e:
        logger.error("adaptive scheduling failed", error=str(e), exc_info=True)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# SIEM export job
# ---------------------------------------------------------------------------

def run_siem_export() -> None:
    """Export recent findings to configured SIEM destinations."""
    if not config.get_siem_export_enabled():
        return
    from app.services.siem_export import export_org_findings

    db = SessionLocal()
    try:
        org_ids = db.execute(select(Organization.id)).scalars().all()
        for org_id in org_ids:
            export_org_findings(db, org_id, [], since_hours=config.get_siem_auto_export_hours())
    except Exception as e:
        logger.error("siem export job failed", error=str(e), exc_info=True)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Alert escalation job
# ---------------------------------------------------------------------------

def run_escalations() -> None:
    """Re-alert on unacknowledged critical/high alerts older than threshold."""
    from app.services.alert_engine import check_escalations

    db = SessionLocal()
    try:
        count = check_escalations(db)
        if count:
            logger.info("escalated unacknowledged alerts", count=count)
    except Exception as e:
        logger.error("escalation check failed", error=str(e), exc_info=True)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Queue GC job
# ---------------------------------------------------------------------------

def run_queue_gc() -> None:
    """Flush retry queue and clean up stale worker registrations."""
    from app.services.queue import get_queue

    try:
        q = get_queue()
        if q:
            flushed = q.flush_ready_retries()
            if flushed:
                logger.info("retry queue flushed", flushed=flushed)
    except Exception as e:
        logger.debug("queue gc error", error=str(e))


# ---------------------------------------------------------------------------
# Main scheduler
# ---------------------------------------------------------------------------

def run_scheduler() -> None:
    init_db()
    scheduler = BlockingScheduler(timezone="UTC")

    # Routine scans for all orgs
    scheduler.add_job(
        lambda: enqueue_scan_for_all_orgs("asset_discovery"),
        "interval",
        hours=config.get_asset_scan_interval_hours(),
        id="asset_discovery",
        replace_existing=True,
    )
    scheduler.add_job(
        lambda: enqueue_scan_for_all_orgs("vuln"),
        "interval",
        days=config.get_vuln_scan_interval_days(),
        id="vuln_scan",
        replace_existing=True,
    )
    scheduler.add_job(
        lambda: enqueue_scan_for_all_orgs("deep"),
        "interval",
        days=config.get_deep_scan_interval_days(),
        id="deep_scan",
        replace_existing=True,
    )

    # Adaptive priority scheduling (every 30 minutes)
    scheduler.add_job(
        run_adaptive_scheduling,
        "interval",
        minutes=30,
        id="adaptive_scheduling",
        replace_existing=True,
    )

    # SIEM export (every N hours, if enabled)
    scheduler.add_job(
        run_siem_export,
        "interval",
        hours=config.get_siem_auto_export_hours(),
        id="siem_export",
        replace_existing=True,
    )

    # Alert escalation check (every hour)
    scheduler.add_job(
        run_escalations,
        "interval",
        hours=1,
        id="alert_escalations",
        replace_existing=True,
    )

    # Queue GC (every 10 minutes)
    scheduler.add_job(
        run_queue_gc,
        "interval",
        minutes=10,
        id="queue_gc",
        replace_existing=True,
    )

    logger.info(
        "scheduler started",
        ts=datetime.utcnow().isoformat() + "Z",
        jobs=[
            "asset_discovery", "vuln_scan", "deep_scan",
            "adaptive_scheduling", "siem_export", "alert_escalations", "queue_gc",
        ],
    )
    scheduler.start()


if __name__ == "__main__":
    run_scheduler()

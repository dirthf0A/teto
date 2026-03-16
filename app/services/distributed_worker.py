"""Distributed scan worker — multi-threaded, Redis-backed, production-grade.

Architecture:
  - Workers register in Redis (asm:workers SET, asm:worker:{id} HASH)
  - Heartbeat published every ASM_WORKER_HEARTBEAT_SECONDS (default 30s)
  - Coordinator thread detects stale workers and reclaims their inflight scans
  - ThreadPoolExecutor runs up to ASM_WORKER_MAX_PARALLEL scans concurrently
  - Per-worker scan rate limiter (token bucket) protects targets
  - Graceful SIGTERM — waits for running scans before exit
  - Scan specialization — worker only handles configured scan_types
  - Automatic fallback to DB polling when Redis unavailable

Worker Redis layout:
  asm:workers             SET   — all active worker IDs
  asm:worker:{id}         HASH  — {id, hostname, pid, mode, started_at,
                                   scans_run, scans_failed, last_heartbeat,
                                   status, current_scan_id, specialization}
"""
from __future__ import annotations

import json
import os
import signal
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.db import SessionLocal, init_db
from app.models import Alert, Asset, AssetChange, Scan
from app.logger import get_logger
logger = get_logger("app.services.distributed_worker")
from app.services.queue import (
    PRIORITY_NORMAL,
    PriorityRedisQueue,
    get_queue,
)


# ---------------------------------------------------------------------------
# Worker registry (Redis-backed)
# ---------------------------------------------------------------------------

class WorkerRegistry:
    """Manage worker registration, heartbeats, and stale detection in Redis."""

    def __init__(self, redis_client, worker_id: str) -> None:
        self._r = redis_client
        self._id = worker_id
        self._workers_key = "asm:workers"
        self._key = f"asm:worker:{worker_id}"

    def register(self, mode: str, specialization: List[str]) -> None:
        self._r.sadd(self._workers_key, self._id)
        self._r.hset(self._key, mapping={
            "id":             self._id,
            "hostname":       os.uname().nodename,
            "pid":            str(os.getpid()),
            "mode":           mode,
            "specialization": ",".join(specialization),
            "started_at":     str(time.time()),
            "scans_run":      "0",
            "scans_failed":   "0",
            "last_heartbeat": str(time.time()),
            "status":         "idle",
            "current_scan_id": "",
        })
        self._r.expire(self._key, 300)  # 5-min TTL; refreshed by heartbeat

    def heartbeat(self, status: str = "idle", current_scan_id: Optional[int] = None) -> None:
        update: Dict[str, str] = {
            "last_heartbeat": str(time.time()),
            "status":         status,
        }
        if current_scan_id is not None:
            update["current_scan_id"] = str(current_scan_id)
        else:
            update["current_scan_id"] = ""
        self._r.hset(self._key, mapping=update)
        self._r.expire(self._key, 300)

    def incr_scans_run(self) -> None:
        self._r.hincrby(self._key, "scans_run", 1)

    def incr_scans_failed(self) -> None:
        self._r.hincrby(self._key, "scans_failed", 1)

    def deregister(self) -> None:
        self._r.srem(self._workers_key, self._id)
        self._r.delete(self._key)

    def list_all(self) -> List[Dict]:
        worker_ids = self._r.smembers(self._workers_key)
        workers = []
        for wid in worker_ids:
            data = self._r.hgetall(f"asm:worker:{wid}")
            if data:
                workers.append(dict(data))
        return workers

    def detect_stale(self, stale_threshold_seconds: int) -> List[str]:
        now = time.time()
        stale = []
        for w in self.list_all():
            last_hb = float(w.get("last_heartbeat", "0") or "0")
            if now - last_hb > stale_threshold_seconds:
                wid = w.get("id", "")
                if wid and wid != self._id:
                    stale.append(wid)
        return stale

    def reclaim_inflight(self, worker_id: str, queue: PriorityRedisQueue) -> int:
        """Re-enqueue scans that were inflight on a stale worker."""
        count = 0
        stale_threshold = config.get_worker_stale_threshold_seconds()
        inflight = self._r.smembers("asm:inflight")
        for scan_id_str in inflight:
            try:
                scan_id = int(scan_id_str)
                meta = self._r.hgetall(f"asm:scan_meta:{scan_id}")
                enqueued_at = float(meta.get("enqueued_at", "0") or "0")
                if time.time() - enqueued_at > stale_threshold * 2:
                    self._r.srem("asm:inflight", scan_id_str)
                    queue.enqueue(scan_id, priority=PRIORITY_NORMAL)
                    count += 1
            except Exception as e:
                logger.warning('queue operation error', error=str(e))
                pass
        return count


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class ScanRateLimiter:
    """Per-worker rate limiter — prevents hammering a single target."""

    def __init__(self, rate_per_second: float = 1.0) -> None:
        self._rate = rate_per_second
        self._tokens = rate_per_second
        self._last = time.time()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                now = time.time()
                self._tokens = min(self._rate, self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            time.sleep(0.1)
        return False


# ---------------------------------------------------------------------------
# Distributed worker
# ---------------------------------------------------------------------------

class DistributedWorker:
    """Production distributed scan worker.

    Responsibilities:
    - Dequeue from PriorityRedisQueue (or fallback DB poll)
    - Run scans in ThreadPoolExecutor (up to max_parallel at once)
    - Publish heartbeats to Redis every heartbeat_interval seconds
    - Detect and reclaim stale worker inflight scans
    - Graceful SIGTERM — finish active scans before exit
    - Scan type specialization (whitelist)
    """

    def __init__(
        self,
        worker_id: Optional[str] = None,
        max_parallel: Optional[int] = None,
        poll_interval: int = 5,
    ) -> None:
        self.worker_id = worker_id or config.get_worker_id()
        self.max_parallel = max_parallel or config.get_worker_max_parallel_scans()
        self.poll_interval = poll_interval
        self.specialization: List[str] = config.get_worker_specialization()
        self.mode = config.get_worker_mode()

        self._shutdown = threading.Event()
        self._active: Dict[int, Future] = {}     # scan_id -> future
        self._active_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_parallel,
            thread_name_prefix="asm-scan",
        )
        self._rate_limiter = ScanRateLimiter(rate_per_second=1.0)
        self._registry: Optional[WorkerRegistry] = None
        self._queue: Optional[PriorityRedisQueue] = None
        self._stats = {
            "scans_run": 0,
            "scans_failed": 0,
            "start_time": time.time(),
        }

        signal.signal(signal.SIGTERM, self._on_sigterm)
        signal.signal(signal.SIGINT, self._on_sigterm)

    # ── Signal handlers ──────────────────────────────────────────────────

    def _on_sigterm(self, signum, frame) -> None:
        logger.info("shutdown signal received", worker_id=self.worker_id, signal=signum)
        self._shutdown.set()

    # ── Scan type filtering ──────────────────────────────────────────────

    def _allows_scan_type(self, scan_type: str) -> bool:
        mode = self.mode
        discovery = {"asset_discovery", "service", "exposed", "deep"}
        vuln = {"vuln", "web", "api", "misconfig", "tls", "headers"}
        secret = {"secret"}

        if mode in ("discovery", "asset") and scan_type not in discovery:
            return False
        if mode in ("vuln", "vulnerability") and scan_type not in vuln:
            return False
        if mode == "secret" and scan_type not in secret:
            return False
        if self.specialization and scan_type not in self.specialization:
            return False
        return True

    # ── Redis setup ──────────────────────────────────────────────────────

    def _setup_redis(self) -> bool:
        try:
            import redis
            r = redis.Redis.from_url(config.get_redis_url(), decode_responses=True)
            r.ping()
            self._registry = WorkerRegistry(r, self.worker_id)
            self._registry.register(self.mode, self.specialization)
            return True
        except Exception as e:
            logger.warning("Redis unavailable, using standalone mode", worker_id=self.worker_id, error=str(e))
            return False

    # ── Background threads ───────────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        interval = config.get_worker_heartbeat_interval()
        while not self._shutdown.is_set():
            try:
                with self._active_lock:
                    active = len([f for f in self._active.values() if not f.done()])
                status = "busy" if active > 0 else "idle"
                if self._registry:
                    self._registry.heartbeat(status)
            except Exception as e:
                logger.warning('queue operation error', error=str(e))
                pass
            time.sleep(interval)

    def _stale_gc_loop(self) -> None:
        threshold = config.get_worker_stale_threshold_seconds()
        while not self._shutdown.is_set():
            time.sleep(threshold)
            if not self._registry or not self._queue:
                continue
            try:
                stale = self._registry.detect_stale(threshold)
                for wid in stale:
                    reclaimed = self._registry.reclaim_inflight(wid, self._queue)
                    if reclaimed:
                        logger.warning("reclaimed scans from stale worker", worker_id=self.worker_id, stale_worker=wid, reclaimed=reclaimed)
            except Exception as e:
                logger.warning('queue operation error', error=str(e))
                pass

    # ── Scan execution ───────────────────────────────────────────────────

    def _run_single_scan(self, db: Session, scan: Scan) -> None:
        """Execute one scan in a thread-pool thread."""
        from app.tasks.worker import claim_scan, process_scan, schedule_retry
        from app.services import asset_snapshot_engine, diff_engine
        from app.services.alert_engine import dispatch_alert, SEVERITY_MAP
        from app.models import ScanResult

        try:
            claim_scan(db, scan)
            if self._registry:
                self._registry.heartbeat("busy", scan.id)

            process_scan(db, scan)

            # Post-scan pipeline
            snapshots, changes = asset_snapshot_engine.snapshot_and_diff(db, scan)
            diff = diff_engine.collect_scan_diff(db, scan)
            diff_payload = diff_engine.diff_summary(diff)
            if any(diff_payload.values()):
                db.add(ScanResult(scan_id=scan.id, tool="diff_engine",
                                  raw_output=json.dumps(diff_payload)))

            # Auto-correlate after discovery scans
            if scan.scan_type in {"asset_discovery", "deep", "service"}:
                try:
                    from app.services.asset_correlation import correlate_org_assets
                    correlate_org_assets(db, scan.org_id)
                except Exception as e:
                    logger.debug('post-scan optional feature error', error=str(e))
                    pass

            # Auto-dedup
            if scan.scan_type in {"asset_discovery", "deep"}:
                try:
                    from app.services.asset_normalizer import deduplicate_org_assets
                    deduplicate_org_assets(db, scan.org_id)
                except Exception as e:
                    logger.debug('post-scan optional feature error', error=str(e))
                    pass

            # Attack surface score
            try:
                from app.services.attack_surface_score import compute_score as _css
                _css(db, scan.org_id, scan_id=scan.id)
            except Exception as e:
                logger.debug('post-scan optional feature error', error=str(e))
                pass

            # Change-based alerts
            seen_alert_keys: Set = set()
            if scan.started_at:
                existing = db.execute(
                    select(Alert).where(Alert.org_id == scan.org_id,
                                        Alert.created_at >= scan.started_at)
                ).scalars().all()
                seen_alert_keys = {(a.alert_type, a.asset_id) for a in existing}

            for change in changes:
                alert_type = {
                    "port_exposed":        "new_port",
                    "endpoint_discovered": "new_endpoint",
                    "new_subdomain":       "new_subdomain",
                }.get(change.change_type, "new_asset")
                key = (alert_type, change.asset_id)
                if key not in seen_alert_keys:
                    seen_alert_keys.add(key)
                    try:
                        dispatch_alert(
                            db, scan.org_id, alert_type,
                            f"{change.change_type.replace('_', ' ').title()}: {change.detail}",
                            asset_id=change.asset_id,
                        )
                    except Exception as e:
                        logger.warning('unexpected error', error=str(e))
                        pass

            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            scan.error = None
            db.commit()

            with self._active_lock:
                self._stats["scans_run"] += 1
            if self._registry:
                self._registry.incr_scans_run()
            if self._queue:
                try:
                    self._queue.complete(scan.id)
                except Exception as e:
                    logger.warning('queue operation error', error=str(e))
                    pass

        except Exception as exc:
            schedule_retry(db, scan, str(exc))
            with self._active_lock:
                self._stats["scans_failed"] += 1
            if self._registry:
                self._registry.incr_scans_failed()
            if self._queue:
                try:
                    self._queue.fail(scan.id, str(exc))
                except Exception as e:
                    logger.warning('queue operation error', error=str(e))
                    pass

    # ── Main loop ────────────────────────────────────────────────────────

    def run(self, poll_interval: Optional[int] = None) -> None:
        """Block until shutdown signal. Drains active scans before exit."""
        poll_interval = poll_interval or self.poll_interval
        init_db()

        self._queue = get_queue()
        has_redis = self._setup_redis()

        # Background threads
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="hb").start()
        if has_redis and self._queue:
            threading.Thread(target=self._stale_gc_loop, daemon=True, name="stale-gc").start()

        logger.info("worker started", worker_id=self.worker_id, mode=self.mode,
                    max_parallel=self.max_parallel, specialization=self.specialization or "all")

        while not self._shutdown.is_set():
            # Clean completed futures
            with self._active_lock:
                self._active = {sid: f for sid, f in self._active.items() if not f.done()}
                active_count = len(self._active)

            if active_count >= self.max_parallel:
                time.sleep(0.5)
                continue

            db = SessionLocal()
            try:
                scan: Optional[Scan] = None

                # Priority: Redis queue -> DB poll
                if self._queue:
                    try:
                        self._queue.flush_ready_retries()
                    except Exception as e:
                        logger.warning('queue operation error', error=str(e))
                        pass
                    scan_id = self._queue.dequeue(timeout=poll_interval)
                    if scan_id:
                        scan = db.get(Scan, scan_id)

                if not scan:
                    scan = db.execute(
                        select(Scan)
                        .where(Scan.status == "scheduled")
                        .order_by(Scan.scheduled_at.asc())
                    ).scalars().first()

                if not scan:
                    db.close()
                    time.sleep(poll_interval)
                    continue

                if not self._allows_scan_type(scan.scan_type):
                    scan.status = "scheduled"
                    scan.scheduled_at = datetime.utcnow() + timedelta(seconds=30)
                    db.commit()
                    db.close()
                    if self._queue:
                        self._queue.enqueue(scan.id, scan_type=scan.scan_type)
                    continue

                if not self._rate_limiter.acquire(timeout=10):
                    db.close()
                    continue

                future = self._executor.submit(self._run_single_scan, db, scan)
                with self._active_lock:
                    self._active[scan.id] = future
                # db ownership transferred to thread

            except Exception as e:
                logger.error("worker loop error", worker_id=self.worker_id, error=str(e), exc_info=True)
                try:
                    db.close()
                except Exception as e:
                    logger.warning('unexpected error', error=str(e))
                    pass
                time.sleep(poll_interval)

        # Graceful drain
        with self._active_lock:
            remaining = len(self._active)
        logger.info("draining active scans before shutdown", worker_id=self.worker_id, active=remaining)
        self._executor.shutdown(wait=True, cancel_futures=False)
        if self._registry:
            self._registry.deregister()
        logger.info("worker shutdown complete", worker_id=self.worker_id, **self._stats)

    # ── Stats ────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict:
        with self._active_lock:
            active = len([f for f in self._active.values() if not f.done()])
        return {
            "worker_id":       self.worker_id,
            "mode":            self.mode,
            "specialization":  self.specialization,
            "max_parallel":    self.max_parallel,
            "active_scans":    active,
            "scans_run":       self._stats["scans_run"],
            "scans_failed":    self._stats["scans_failed"],
            "uptime_seconds":  round(time.time() - self._stats["start_time"], 0),
        }


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def get_all_worker_stats() -> Optional[List[Dict]]:
    """Return stats for all registered workers from Redis."""
    try:
        import redis
        r = redis.Redis.from_url(config.get_redis_url(), decode_responses=True)
        worker_ids = r.smembers("asm:workers")
        now = time.time()
        results = []
        stale_threshold = config.get_worker_stale_threshold_seconds()
        for wid in worker_ids:
            data = r.hgetall(f"asm:worker:{wid}")
            if not data:
                continue
            last_hb = float(data.get("last_heartbeat", "0") or "0")
            data["is_stale"] = (now - last_hb) > stale_threshold
            data["uptime_seconds"] = round(now - float(data.get("started_at", now) or now), 0)
            data["last_heartbeat_ago"] = round(now - last_hb, 1)
            results.append(data)
        return results
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_worker(
    mode: Optional[str] = None,
    max_parallel: Optional[int] = None,
    specialization: Optional[List[str]] = None,
) -> None:
    """Run a distributed worker. Blocks until SIGTERM/SIGINT."""
    worker = DistributedWorker(max_parallel=max_parallel)
    if mode:
        worker.mode = mode
    if specialization:
        worker.specialization = specialization
    worker.run()


if __name__ == "__main__":
    run_worker()

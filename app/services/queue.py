"""Priority scan queue — Redis backend with DLQ, retry, and monitoring.

Priority levels (lower = higher priority):
  PRIORITY_CRITICAL = 0  (scan_type: "exposed")
  PRIORITY_HIGH     = 1  (scan_type: "service", "web", "misconfig", "secret")
  PRIORITY_NORMAL   = 2  (scan_type: "vuln", "asset_discovery", "tls", "api")
  PRIORITY_LOW      = 3  (scan_type: "deep")

Redis key layout:
  asm:queue:0-3       LIST  — priority queues (LPUSH / BRPOP)
  asm:inflight        SET   — scan IDs currently being processed
  asm:dlq             LIST  — dead-letter queue (max retry exceeded)
  asm:retry_set       ZSET  — scheduled retries (score = run_after timestamp)
  asm:scan_meta:{id}  HASH  — per-scan metadata (enqueued_at, retries, status)
  asm:workers         SET   — active worker IDs
  asm:worker:{id}     HASH  — per-worker stats (heartbeat, status, scans_run)
"""
from __future__ import annotations

import json
import time
from app.logger import get_logger
logger = get_logger('app.services.queue')
from typing import Dict, List, Optional

from app import config

PRIORITY_CRITICAL = 0
PRIORITY_HIGH = 1
PRIORITY_NORMAL = 2
PRIORITY_LOW = 3

SCAN_TYPE_PRIORITY: Dict[str, int] = {
    "exposed":         PRIORITY_CRITICAL,
    "service":         PRIORITY_HIGH,
    "web":             PRIORITY_HIGH,
    "misconfig":       PRIORITY_HIGH,
    "secret":          PRIORITY_HIGH,
    "vuln":            PRIORITY_NORMAL,
    "asset_discovery": PRIORITY_NORMAL,
    "tls":             PRIORITY_NORMAL,
    "headers":         PRIORITY_NORMAL,
    "api":             PRIORITY_NORMAL,
    "deep":            PRIORITY_LOW,
}

_QUEUE_PREFIX = "asm:queue:"
_DLQ_KEY = "asm:dlq"
_INFLIGHT_KEY = "asm:inflight"
_RETRY_ZSET = "asm:retry_set"
_SCAN_META_PREFIX = "asm:scan_meta:"


# ---------------------------------------------------------------------------
# Priority queue
# ---------------------------------------------------------------------------

class PriorityRedisQueue:
    """Multi-priority Redis queue for distributed scan job dispatch.

    Supports:
    - 4 priority levels with BRPOP drain order (critical first)
    - Inflight tracking — scans remain in asm:inflight until completed/failed
    - DLQ — scans exceeding max_retries go here instead of silently dropping
    - Retry scheduling — ZSET with score = run_after epoch; flush_ready_retries()
      moves them back to the appropriate priority queue
    - Per-scan metadata — enqueued_at, retries, last_error, status
    - Queue depth monitoring — depth() returns counts at all levels
    """

    def __init__(self, url: str) -> None:
        import redis
        self._r = redis.Redis.from_url(url, decode_responses=True)

    def _q(self, priority: int) -> str:
        return f"{_QUEUE_PREFIX}{priority}"

    # ── Enqueue ──────────────────────────────────────────────────────────

    def enqueue(
        self,
        scan_id: int,
        priority: Optional[int] = None,
        scan_type: Optional[str] = None,
    ) -> None:
        """Push scan_id onto the appropriate priority queue.

        If priority is not given, it is derived from scan_type using
        SCAN_TYPE_PRIORITY (default: PRIORITY_NORMAL).
        """
        if priority is None:
            priority = SCAN_TYPE_PRIORITY.get(scan_type or "", PRIORITY_NORMAL)

        payload = json.dumps({"scan_id": scan_id, "enqueued_at": time.time()})
        self._r.lpush(self._q(priority), payload)

        meta_key = f"{_SCAN_META_PREFIX}{scan_id}"
        self._r.hset(meta_key, mapping={
            "scan_id":    str(scan_id),
            "priority":   str(priority),
            "scan_type":  scan_type or "",
            "enqueued_at": str(time.time()),
            "status":     "queued",
            "retries":    "0",
        })
        self._r.expire(meta_key, 86400)  # 24h TTL

    # ── Dequeue ──────────────────────────────────────────────────────────

    def dequeue(self, timeout: int = 5) -> Optional[int]:
        """Block-pop from priority queues (critical first). Returns scan_id or None."""
        keys = [self._q(p) for p in range(4)]
        result = self._r.brpop(keys, timeout=timeout)
        if not result:
            return None
        _, payload = result
        try:
            data = json.loads(payload)
            scan_id = int(data["scan_id"])
        except (KeyError, ValueError, json.JSONDecodeError):
            try:
                scan_id = int(payload)
            except ValueError:
                return None

        self._r.sadd(_INFLIGHT_KEY, str(scan_id))
        self._r.hset(f"{_SCAN_META_PREFIX}{scan_id}", "status", "inflight")
        return scan_id

    # ── Completion / failure ─────────────────────────────────────────────

    def complete(self, scan_id: int) -> None:
        """Mark scan as completed — removes from inflight set."""
        self._r.srem(_INFLIGHT_KEY, str(scan_id))
        meta_key = f"{_SCAN_META_PREFIX}{scan_id}"
        self._r.hset(meta_key, mapping={
            "status":       "completed",
            "completed_at": str(time.time()),
        })

    def fail(
        self,
        scan_id: int,
        error: str,
        max_retries: int = 3,
        retry_backoff_seconds: float = 120.0,
    ) -> bool:
        """Handle scan failure — schedule retry or move to DLQ.

        Returns True if scan moved to DLQ (retries exhausted), False if retry scheduled.
        """
        self._r.srem(_INFLIGHT_KEY, str(scan_id))
        meta_key = f"{_SCAN_META_PREFIX}{scan_id}"

        retries = int(self._r.hget(meta_key, "retries") or "0") + 1
        scan_type = self._r.hget(meta_key, "scan_type") or ""

        self._r.hset(meta_key, mapping={
            "retries":    str(retries),
            "last_error": error[:500],
            "status":     "failed" if retries >= max_retries else "retry_scheduled",
        })

        if retries >= max_retries:
            # Move to dead-letter queue
            self._r.lpush(_DLQ_KEY, json.dumps({
                "scan_id":   scan_id,
                "error":     error[:500],
                "failed_at": time.time(),
                "retries":   retries,
            }))
            return True

        # Schedule exponential backoff retry
        backoff = retry_backoff_seconds * (2 ** (retries - 1))
        run_after = time.time() + min(backoff, 3600.0)  # cap at 1 hour
        self._r.zadd(_RETRY_ZSET, {str(scan_id): run_after})
        return False

    # ── Retry scheduler ──────────────────────────────────────────────────

    def flush_ready_retries(self) -> int:
        """Move scans whose retry window has passed back onto the work queue.

        Call this periodically from the worker loop (every poll cycle is fine).
        Returns the number of scans re-enqueued.
        """
        now = time.time()
        ready = self._r.zrangebyscore(_RETRY_ZSET, 0, now)
        count = 0
        for scan_id_str in ready:
            try:
                scan_id = int(scan_id_str)
                meta_key = f"{_SCAN_META_PREFIX}{scan_id}"
                scan_type = self._r.hget(meta_key, "scan_type") or ""
                self.enqueue(scan_id, scan_type=scan_type or None, priority=PRIORITY_NORMAL)
                self._r.zrem(_RETRY_ZSET, scan_id_str)
                count += 1
            except (ValueError, Exception):
                pass
        return count

    # ── Monitoring ───────────────────────────────────────────────────────

    def depth(self) -> Dict[str, int]:
        """Return queue depths at all priority levels plus inflight and DLQ."""
        _labels = {0: "critical", 1: "high", 2: "normal", 3: "low"}
        result: Dict[str, int] = {}
        total = 0
        for p in range(4):
            d = int(self._r.llen(self._q(p)) or 0)
            result[_labels[p]] = d
            total += d
        result["total"] = total
        result["inflight"] = int(self._r.scard(_INFLIGHT_KEY) or 0)
        result["dlq"] = int(self._r.llen(_DLQ_KEY) or 0)
        result["pending_retry"] = int(self._r.zcard(_RETRY_ZSET) or 0)
        return result

    def list_dlq(self, limit: int = 50) -> List[Dict]:
        """Return recent DLQ entries for inspection."""
        items = self._r.lrange(_DLQ_KEY, 0, limit - 1)
        results = []
        for item in items:
            try:
                results.append(json.loads(item))
            except json.JSONDecodeError:
                results.append({"raw": item})
        return results

    def get_scan_meta(self, scan_id: int) -> Optional[Dict]:
        """Return per-scan metadata dict or None if not found."""
        data = self._r.hgetall(f"{_SCAN_META_PREFIX}{scan_id}")
        return dict(data) if data else None

    def requeue_dlq(self, scan_id: int) -> bool:
        """Move a DLQ item back to the work queue (manual recovery).

        Returns True if found and re-enqueued.
        """
        dlq_items = self._r.lrange(_DLQ_KEY, 0, -1)
        for item in dlq_items:
            try:
                data = json.loads(item)
                if int(data.get("scan_id", -1)) == scan_id:
                    self._r.lrem(_DLQ_KEY, 1, item)
                    self.enqueue(scan_id, priority=PRIORITY_NORMAL)
                    return True
            except Exception:
                continue
        return False

    def ping(self) -> bool:
        """Check Redis connectivity."""
        try:
            return self._r.ping()
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Fallback: simple DB-polled queue (no Redis dependency)
# ---------------------------------------------------------------------------

class DBQueue:
    """Minimal in-process queue stub — no external dependency.

    Uses the Scan table directly (status='scheduled'). Not distributed,
    not persistent beyond what the DB provides. Use for dev/SQLite setups.
    """

    def enqueue(self, scan_id: int, priority: Optional[int] = None,
                scan_type: Optional[str] = None) -> None:
        pass  # scan is already in DB with status='scheduled'

    def dequeue(self, timeout: int = 5) -> Optional[int]:
        return None  # worker falls back to DB poll

    def complete(self, scan_id: int) -> None:
        pass

    def fail(self, scan_id: int, error: str, max_retries: int = 3,
             retry_backoff_seconds: float = 120.0) -> bool:
        return False

    def flush_ready_retries(self) -> int:
        return 0

    def depth(self) -> Dict[str, int]:
        return {"total": 0, "inflight": 0, "dlq": 0, "pending_retry": 0}

    def list_dlq(self, limit: int = 50) -> List[Dict]:
        return []

    def ping(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_queue_instance: Optional[PriorityRedisQueue] = None
_queue_lock = __import__("threading").Lock()


def get_queue() -> Optional[PriorityRedisQueue]:
    """Return the shared PriorityRedisQueue instance or None if Redis unavailable.

    Uses lazy init + singleton pattern — safe to call from multiple threads.
    """
    global _queue_instance
    if config.get_queue_backend() != "redis":
        return None

    with _queue_lock:
        if _queue_instance is not None:
            return _queue_instance
        try:
            q = PriorityRedisQueue(config.get_redis_url())
            if q.ping():
                _queue_instance = q
                return q
        except Exception as e:
            logger.warning('unexpected error', error=str(e))
            pass
    return None


def get_queue_depth() -> Optional[Dict[str, int]]:
    """Return queue depth dict or None if queue unavailable."""
    try:
        q = get_queue()
        if q:
            return q.depth()
    except Exception as e:
        logger.warning('unexpected error', error=str(e))
        pass
    return None


def reset_queue_singleton() -> None:
    """Force re-init of the queue singleton (useful after Redis reconnect)."""
    global _queue_instance
    with _queue_lock:
        _queue_instance = None

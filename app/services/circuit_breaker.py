"""Circuit breaker + retry utilities for external service calls.

Pattern: CLOSED → OPEN (after N failures) → HALF_OPEN (after timeout) → CLOSED

Usage:
    breaker = CircuitBreaker("nuclei", failure_threshold=3, recovery_timeout=60)

    @breaker
    def run_scan():
        ...

    # Or manual:
    with breaker.call():
        result = external_api()

Also provides:
    retry_with_backoff(fn, retries=3, backoff=1.0) — standalone retry decorator
    with_timeout(fn, seconds=30)                   — hard timeout wrapper
"""
from __future__ import annotations

import functools
import threading
import time
from contextlib import contextmanager
from enum import Enum
from typing import Any, Callable, Dict, Optional, Type

from app.logger import get_logger

logger = get_logger("app.services.circuit_breaker")


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class State(str, Enum):
    CLOSED     = "closed"      # normal — calls pass through
    OPEN       = "open"        # tripped — calls fail fast
    HALF_OPEN  = "half_open"   # testing — one call allowed


class CircuitBreakerOpen(Exception):
    """Raised when a circuit breaker is OPEN and call is rejected."""
    def __init__(self, name: str) -> None:
        super().__init__(f"Circuit breaker '{name}' is OPEN — service unavailable")
        self.breaker_name = name


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """Thread-safe circuit breaker with half-open probe logic.

    Args:
        name:               Identifier (used in logs)
        failure_threshold:  Consecutive failures before opening (default 5)
        recovery_timeout:   Seconds before attempting half-open probe (default 60)
        success_threshold:  Consecutive successes in half-open to re-close (default 2)
        expected_exceptions: Tuple of exception types that count as failures
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        success_threshold: int = 2,
        expected_exceptions: tuple = (Exception,),
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        self.expected_exceptions = expected_exceptions

        self._state = State.CLOSED
        self._failures = 0
        self._successes = 0
        self._opened_at: Optional[float] = None
        self._lock = threading.Lock()

    # ── State queries ─────────────────────────────────────────────────────

    @property
    def state(self) -> State:
        with self._lock:
            return self._check_recovery()

    def _check_recovery(self) -> State:
        """Must be called while holding self._lock."""
        if self._state == State.OPEN:
            if self._opened_at and (time.monotonic() - self._opened_at) >= self.recovery_timeout:
                self._state = State.HALF_OPEN
                self._successes = 0
                logger.info("circuit breaker half-open", name=self.name)
        return self._state

    def is_open(self) -> bool:
        return self.state == State.OPEN

    # ── Call handling ─────────────────────────────────────────────────────

    def __call__(self, fn: Callable) -> Callable:
        """Decorator form: @breaker"""
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return self._execute(fn, *args, **kwargs)
        return wrapper

    @contextmanager
    def call(self):
        """Context manager form: with breaker.call(): ..."""
        state = self.state
        if state == State.OPEN:
            raise CircuitBreakerOpen(self.name)
        try:
            yield
            self._on_success()
        except self.expected_exceptions as exc:
            self._on_failure(exc)
            raise

    def _execute(self, fn: Callable, *args, **kwargs) -> Any:
        state = self.state
        if state == State.OPEN:
            raise CircuitBreakerOpen(self.name)
        try:
            result = fn(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exceptions as exc:
            self._on_failure(exc)
            raise

    def _on_success(self) -> None:
        with self._lock:
            if self._state == State.HALF_OPEN:
                self._successes += 1
                if self._successes >= self.success_threshold:
                    self._state = State.CLOSED
                    self._failures = 0
                    self._opened_at = None
                    logger.info("circuit breaker closed (recovered)", name=self.name)
            elif self._state == State.CLOSED:
                self._failures = 0

    def _on_failure(self, exc: Exception) -> None:
        with self._lock:
            self._failures += 1
            if self._state == State.HALF_OPEN:
                # Probe failed — back to OPEN
                self._state = State.OPEN
                self._opened_at = time.monotonic()
                logger.warning(
                    "circuit breaker reopened (half-open probe failed)",
                    name=self.name, error=str(exc),
                )
            elif self._state == State.CLOSED and self._failures >= self.failure_threshold:
                self._state = State.OPEN
                self._opened_at = time.monotonic()
                logger.error(
                    "circuit breaker opened",
                    name=self.name, failures=self._failures, error=str(exc),
                )

    def reset(self) -> None:
        """Manually reset to CLOSED (for admin override)."""
        with self._lock:
            self._state = State.CLOSED
            self._failures = 0
            self._successes = 0
            self._opened_at = None
        logger.info("circuit breaker manually reset", name=self.name)

    def stats(self) -> Dict:
        with self._lock:
            state = self._check_recovery()
            age = round(time.monotonic() - self._opened_at, 1) if self._opened_at else None
            return {
                "name":         self.name,
                "state":        state.value,
                "failures":     self._failures,
                "successes":    self._successes,
                "opened_age_s": age,
            }


# ---------------------------------------------------------------------------
# Global registry
# ---------------------------------------------------------------------------

_registry: Dict[str, CircuitBreaker] = {}
_registry_lock = threading.Lock()


def get_breaker(
    name: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
) -> CircuitBreaker:
    """Get or create a named circuit breaker (singleton per name)."""
    with _registry_lock:
        if name not in _registry:
            _registry[name] = CircuitBreaker(
                name,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
            )
        return _registry[name]


def all_breaker_stats() -> Dict[str, Dict]:
    """Return stats for all registered breakers."""
    with _registry_lock:
        return {name: b.stats() for name, b in _registry.items()}


# ---------------------------------------------------------------------------
# Retry decorator
# ---------------------------------------------------------------------------

def retry_with_backoff(
    fn: Optional[Callable] = None,
    *,
    retries: int = 3,
    backoff: float = 1.0,
    max_backoff: float = 30.0,
    exceptions: tuple = (Exception,),
    on_retry: Optional[Callable[[int, Exception], None]] = None,
):
    """Retry decorator with exponential backoff.

    Usage:
        @retry_with_backoff(retries=3, backoff=1.0)
        def call_api():
            ...

        # Or as a context wrapper:
        result = retry_with_backoff(lambda: api_call(), retries=5)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = backoff
            last_exc: Optional[Exception] = None
            for attempt in range(retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt >= retries:
                        raise
                    if on_retry:
                        on_retry(attempt + 1, exc)
                    else:
                        logger.debug(
                            "retry attempt",
                            func=func.__name__,
                            attempt=attempt + 1,
                            max=retries,
                            error=str(exc),
                        )
                    time.sleep(min(delay, max_backoff))
                    delay = min(delay * 2, max_backoff)
            if last_exc:
                raise last_exc
            raise RuntimeError("retry loop exited without result")
        return wrapper

    if fn is not None:
        # Called as @retry_with_backoff (no args)
        return decorator(fn)
    return decorator


# ---------------------------------------------------------------------------
# Timeout wrapper
# ---------------------------------------------------------------------------

class TimeoutError(Exception):
    pass


def with_timeout(fn: Callable, seconds: float, *args, **kwargs) -> Any:
    """Run fn(*args, **kwargs) with a hard timeout.

    Raises TimeoutError if the function doesn't complete in time.
    Uses threading — works for blocking I/O but not CPU-bound code.
    """
    result_holder: Dict[str, Any] = {}
    exc_holder: Dict[str, Any] = {}

    def target():
        try:
            result_holder["result"] = fn(*args, **kwargs)
        except Exception as e:
            exc_holder["exc"] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout=seconds)

    if t.is_alive():
        raise TimeoutError(f"{fn.__name__} timed out after {seconds}s")
    if "exc" in exc_holder:
        raise exc_holder["exc"]
    return result_holder.get("result")

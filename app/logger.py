"""Centralized structured logging for the ASM platform.

Usage:
    from app.logger import get_logger
    logger = get_logger(__name__)
    logger.info("scan started", scan_id=42, org_id=1)
    logger.warning("channel failed", channel="slack", error=str(e))
    logger.error("scan crashed", scan_id=42, exc_info=True)

Log format (JSON when ASM_LOG_JSON=true, human-readable otherwise):
    {"ts":"2024-01-01T00:00:00Z","level":"INFO","logger":"app.tasks.worker","msg":"...","k":"v",...}

Environment variables:
    ASM_LOG_LEVEL    — DEBUG / INFO / WARNING / ERROR (default INFO)
    ASM_LOG_JSON     — true / false (default false in dev, true in prod)
"""
from __future__ import annotations

import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _log_level() -> int:
    level_str = os.getenv("ASM_LOG_LEVEL", "INFO").upper()
    return getattr(logging, level_str, logging.INFO)


def _use_json() -> bool:
    env = os.getenv("ASM_ENV", "dev").lower()
    default = "true" if env in ("prod", "production") else "false"
    return os.getenv("ASM_LOG_JSON", default).lower() == "true"


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        payload: dict = {
            "ts":     ts,
            "level":  record.levelname,
            "logger": record.name,
            "msg":    record.getMessage(),
        }
        # Extra fields injected via logger.info("msg", extra={...})
        for key, val in record.__dict__.items():
            if key.startswith("_") or key in {
                "name","msg","args","levelname","levelno","pathname",
                "filename","module","exc_info","exc_text","stack_info",
                "lineno","funcName","created","msecs","relativeCreated",
                "thread","threadName","processName","process","message",
                "taskName",
            }:
                continue
            payload[key] = val

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Human formatter
# ---------------------------------------------------------------------------

class _HumanFormatter(logging.Formatter):
    _COLORS = {
        "DEBUG":    "\033[36m",   # cyan
        "INFO":     "\033[32m",   # green
        "WARNING":  "\033[33m",   # yellow
        "ERROR":    "\033[31m",   # red
        "CRITICAL": "\033[35m",   # magenta
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        color = self._COLORS.get(record.levelname, "")
        reset = self._RESET if color else ""
        base = f"{ts} {color}{record.levelname:8s}{reset} [{record.name}] {record.getMessage()}"

        # Extra fields
        extras = []
        for key, val in record.__dict__.items():
            if key.startswith("_") or key in {
                "name","msg","args","levelname","levelno","pathname",
                "filename","module","exc_info","exc_text","stack_info",
                "lineno","funcName","created","msecs","relativeCreated",
                "thread","threadName","processName","process","message",
                "taskName",
            }:
                continue
            extras.append(f"{key}={val!r}")
        if extras:
            base += "  " + "  ".join(extras)

        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


# ---------------------------------------------------------------------------
# Setup (idempotent)
# ---------------------------------------------------------------------------

_configured = False


def configure_logging() -> None:
    global _configured
    if _configured:
        return
    _configured = True

    root = logging.getLogger()
    if root.handlers:
        return  # already configured externally

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter() if _use_json() else _HumanFormatter())
    root.addHandler(handler)
    root.setLevel(_log_level())

    # Silence noisy third-party loggers
    for noisy in ("sqlalchemy.engine", "urllib3", "httpx", "apscheduler"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------

class _BoundLogger:
    """Thin wrapper adding structured key=value fields to every log call."""

    def __init__(self, logger: logging.Logger) -> None:
        self._log = logger

    def _emit(self, level: int, msg: str, exc_info: bool = False, **kv: Any) -> None:
        if not self._log.isEnabledFor(level):
            return
        # 'name', 'message', 'asctime' etc are reserved LogRecord fields — prefix with _ to avoid conflict
        _RESERVED = {
            "name","msg","args","levelname","levelno","pathname","filename","module",
            "exc_info","exc_text","stack_info","lineno","funcName","created","msecs",
            "relativeCreated","thread","threadName","processName","process","message",
            "taskName","asctime",
        }
        safe_kv = {(f"_{k}" if k in _RESERVED else k): v for k, v in kv.items()}
        self._log.log(level, msg, extra=safe_kv, exc_info=exc_info)

    def debug(self, msg: str, **kv: Any) -> None:
        self._emit(logging.DEBUG, msg, **kv)

    def info(self, msg: str, **kv: Any) -> None:
        self._emit(logging.INFO, msg, **kv)

    def warning(self, msg: str, **kv: Any) -> None:
        self._emit(logging.WARNING, msg, **kv)

    def error(self, msg: str, exc_info: bool = False, **kv: Any) -> None:
        self._emit(logging.ERROR, msg, exc_info=exc_info, **kv)

    def critical(self, msg: str, exc_info: bool = False, **kv: Any) -> None:
        self._emit(logging.CRITICAL, msg, exc_info=exc_info, **kv)

    def exception(self, msg: str, **kv: Any) -> None:
        self._emit(logging.ERROR, msg, exc_info=True, **kv)


def get_logger(name: str) -> _BoundLogger:
    """Return a structured logger. Call configure_logging() first (done by get_logger on first call)."""
    configure_logging()
    return _BoundLogger(logging.getLogger(name))

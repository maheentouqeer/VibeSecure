"""Abuse and cost controls for scan creation.

Two independent guards, both configurable by environment variable
(set a value to 0 to disable that guard):

  SCAN_RATE_LIMIT_PER_HOUR  max scans/rescans started per client IP per hour (default 10)
  DAILY_SCAN_CAP            max scans/rescans started across all users per UTC day
                            (default 500) -- a hard ceiling on LLM spend

The per-IP window is held in process memory, so it resets on restart and is
per-instance. The daily cap is counted from the database and is exact.
"""
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend import db


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


class SlidingWindowLimiter:
    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._calls = 0

    def check(self, key: str, limit: int) -> int | None:
        """Records a hit and returns None, or returns seconds until the
        caller may retry if `limit` hits already happened in the window."""
        now = time.monotonic()
        with self._lock:
            self._calls += 1
            if self._calls % 500 == 0:
                self._sweep(now)
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= limit:
                return max(1, int(self.window - (now - hits[0])) + 1)
            hits.append(now)
            return None

    def _sweep(self, now: float) -> None:
        """Drop IPs with no hit inside the window so memory can't grow
        without bound as new addresses keep arriving."""
        for key in [k for k, hits in self._hits.items() if not hits or now - hits[-1] >= self.window]:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


ip_limiter = SlidingWindowLimiter(window_seconds=3600)


def client_ip(request: Request) -> str:
    """Behind a proxy (Railway) request.client is the proxy, so use the
    rightmost X-Forwarded-For entry: the one the nearest trusted proxy
    appended. Earlier entries are client-supplied and spoofable."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _seconds_until_utc_midnight() -> int:
    now = datetime.now(timezone.utc)
    midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((midnight - now).total_seconds()))


def enforce_scan_limits(request: Request, session: Session) -> None:
    """Raises 429 (per-IP) or 503 (global daily cap) before a scan is queued."""
    per_hour = _int_env("SCAN_RATE_LIMIT_PER_HOUR", 10)
    if per_hour > 0:
        retry = ip_limiter.check(client_ip(request), per_hour)
        if retry is not None:
            raise HTTPException(
                status_code=429,
                detail=f"Too many scans from your network. Try again in {retry // 60 + 1} minute(s).",
                headers={"Retry-After": str(retry)},
            )

    if daily_cap_reached(session):
        raise HTTPException(
            status_code=503,
            detail="Daily scan capacity reached. Please try again tomorrow.",
            headers={"Retry-After": str(_seconds_until_utc_midnight())},
        )


def daily_cap_reached(session: Session) -> bool:
    daily_cap = _int_env("DAILY_SCAN_CAP", 500)
    if daily_cap <= 0:
        return False
    start_of_day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    used = session.query(func.count(db.ScanRun.id)).filter(db.ScanRun.started_at >= start_of_day).scalar()
    return used >= daily_cap

"""Abuse and cost controls.

Scan creation has two independent guards (set a value to 0 to disable one):

  SCAN_RATE_LIMIT_PER_HOUR  max scans/rescans started per client IP per hour (default 10)
  DAILY_SCAN_CAP            max scans/rescans started across all users per UTC day
                            (default 500) -- a hard ceiling on LLM spend

Other endpoints are throttled by buckets (each 0 = off):

  OAUTH_RATE_LIMIT_PER_HOUR         per IP, GitHub connect flow (default 30)
  MUTATION_RATE_LIMIT_PER_HOUR      per user (or IP), org changes and deletions (default 120)
  WEBHOOK_FAIL_LIMIT_PER_HOUR       per IP, webhook deliveries with a BAD signature (default 30);
                                    an IP over the limit is refused before any crypto is done,
                                    so signature guessing gets throttled

RATE_LIMIT_STORE picks where hits are counted:
  db (default)   the rate_events table: exact across every API instance and it
                 survives restarts. Each check is one atomic statement (plus a
                 per-key advisory lock on Postgres). If the database can't be
                 reached the limiter fails OPEN, so a database blip does not
                 take the whole API down with it.
  memory         per-process, resets on restart. Fine for one instance.

The daily cap is always counted from the database and is exact.
"""
import logging
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy import DateTime, String, delete, func, insert, literal, select, text
from sqlalchemy.orm import Session

from backend import db
from backend.auth import Actor, get_actor

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 3600


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


class SlidingWindowLimiter:
    """In-process sliding window (RATE_LIMIT_STORE=memory)."""

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


ip_limiter = SlidingWindowLimiter(window_seconds=WINDOW_SECONDS)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _retry_after(oldest: datetime | None, now: datetime, window: float) -> int:
    if oldest is None:
        return 1
    return max(1, int(window - (now - _aware(oldest)).total_seconds()) + 1)


class DbWindowStore:
    """Sliding-window counters in the rate_events table."""

    def hit(self, bucket: str, key: str, limit: int, window: float = WINDOW_SECONDS) -> int | None:
        """Atomically records a hit unless `limit` hits are already inside the
        window. Returns None if recorded, else seconds until a hit expires."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window)
        with db.SessionLocal() as session:
            if session.get_bind().dialect.name == "postgresql":
                # Serializes concurrent hits on this key; released at commit/rollback.
                session.execute(
                    text("select pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"{bucket}:{key}"}
                )
            in_window = (
                select(func.count())
                .select_from(db.RateEvent)
                .where(db.RateEvent.bucket == bucket, db.RateEvent.key == key, db.RateEvent.ts > cutoff)
                .scalar_subquery()
            )
            # One statement counts and inserts, so two requests can't both see room for one more.
            recorded = session.execute(
                insert(db.RateEvent).from_select(
                    ["id", "bucket", "key", "ts"],
                    select(
                        literal(str(uuid.uuid4()), String),
                        literal(bucket, String),
                        literal(key, String),
                        literal(now, DateTime(timezone=True)),
                    ).where(in_window < limit),
                )
            ).rowcount
            if recorded:
                session.commit()
                return None
            oldest = session.execute(
                select(func.min(db.RateEvent.ts)).where(
                    db.RateEvent.bucket == bucket, db.RateEvent.key == key, db.RateEvent.ts > cutoff
                )
            ).scalar()
            session.rollback()
            return _retry_after(oldest, now, window)

    def peek(self, bucket: str, key: str, limit: int, window: float = WINDOW_SECONDS) -> int | None:
        """Like hit() but never records: is this key already at its limit?"""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window)
        with db.SessionLocal() as session:
            count, oldest = session.execute(
                select(func.count(), func.min(db.RateEvent.ts)).where(
                    db.RateEvent.bucket == bucket, db.RateEvent.key == key, db.RateEvent.ts > cutoff
                )
            ).one()
        return _retry_after(oldest, now, window) if count >= limit else None

    def record(self, bucket: str, key: str) -> None:
        with db.SessionLocal() as session:
            session.add(db.RateEvent(bucket=bucket, key=key))
            session.commit()

    def purge(self, older_than_seconds: float = 86400) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=older_than_seconds)
        with db.SessionLocal() as session:
            removed = session.execute(delete(db.RateEvent).where(db.RateEvent.ts < cutoff)).rowcount
            session.commit()
        return removed

    def reset(self) -> None:
        with db.SessionLocal() as session:
            session.execute(delete(db.RateEvent))
            session.commit()


db_store = DbWindowStore()


def _use_db() -> bool:
    return os.getenv("RATE_LIMIT_STORE", "db").lower() != "memory"


def hit(bucket: str, key: str, limit: int) -> int | None:
    """Record one hit for (bucket, key). None if allowed, else seconds to wait."""
    if limit <= 0:
        return None
    if _use_db():
        try:
            return db_store.hit(bucket, key, limit)
        except Exception:
            logger.warning("rate limit store unavailable; allowing the request", exc_info=True)
            return None
    return ip_limiter.check(f"{bucket}:{key}", limit)


def _too_many(retry: int, what: str) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail=f"Too many {what}. Try again in {retry // 60 + 1} minute(s).",
        headers={"Retry-After": str(retry)},
    )


def client_ip(request: Request) -> str:
    """Behind a proxy (Railway) request.client is the proxy, so use the
    rightmost X-Forwarded-For entry: the one the nearest trusted proxy
    appended. Earlier entries are client-supplied and spoofable."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def limit_by_ip(bucket: str, env_name: str, default: int, what: str = "requests"):
    """FastAPI dependency: throttles a route per client IP."""

    def dependency(request: Request) -> None:
        retry = hit(bucket, client_ip(request), _int_env(env_name, default))
        if retry is not None:
            raise _too_many(retry, what)

    return dependency


def limit_by_user(bucket: str, env_name: str, default: int, what: str = "requests"):
    """FastAPI dependency: throttles a route per signed-in user (per IP for anonymous callers)."""

    def dependency(request: Request, actor: Actor = Depends(get_actor)) -> None:
        key = f"user:{actor.user.id}" if actor.user else f"ip:{client_ip(request)}"
        retry = hit(bucket, key, _int_env(env_name, default))
        if retry is not None:
            raise _too_many(retry, what)

    return dependency


def failure_gate(request: Request, bucket: str, env_name: str, default: int, what: str) -> None:
    """Call BEFORE checking a credential: refuses IPs that have already failed
    too many times, without spending any effort on them (so guessing is throttled)."""
    limit = _int_env(env_name, default)
    if limit <= 0 or not _use_db():
        return
    try:
        retry = db_store.peek(bucket, client_ip(request), limit)
    except Exception:
        logger.warning("rate limit store unavailable; not gating %s", bucket, exc_info=True)
        return
    if retry is not None:
        raise _too_many(retry, what)


def record_failure(request: Request, bucket: str, env_name: str, default: int) -> None:
    """Call when a credential was rejected."""
    if _int_env(env_name, default) <= 0 or not _use_db():
        return
    try:
        db_store.record(bucket, client_ip(request))
    except Exception:
        logger.warning("could not record a failed attempt for %s", bucket, exc_info=True)


WEBHOOK_BUCKET = "webhook_fail"


def webhook_gate(request: Request) -> None:
    failure_gate(request, WEBHOOK_BUCKET, "WEBHOOK_FAIL_LIMIT_PER_HOUR", 30, "invalid webhook deliveries")


def webhook_failed(request: Request) -> None:
    record_failure(request, WEBHOOK_BUCKET, "WEBHOOK_FAIL_LIMIT_PER_HOUR", 30)


def _seconds_until_utc_midnight() -> int:
    now = datetime.now(timezone.utc)
    midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((midnight - now).total_seconds()))


def enforce_scan_limits(request: Request, session: Session) -> None:
    """Raises 429 (per-IP) or 503 (global daily cap) before a scan is queued."""
    retry = hit("scan", client_ip(request), _int_env("SCAN_RATE_LIMIT_PER_HOUR", 10))
    if retry is not None:
        raise _too_many(retry, "scans from your network")

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

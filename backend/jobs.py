"""Database-backed job queue for scans and rescans.

Why the database: it needs no extra infrastructure, jobs survive restarts,
and any number of API or worker processes can share it safely, because a job
is claimed with a single conditional UPDATE -- of any number of workers that
race for it, exactly one wins.

Lifecycle:  pending -> running -> done | failed
  * A running job's worker refreshes `locked_at` every HEARTBEAT_SECONDS. A
    job whose lock is older than JOB_STALE_SECONDS belongs to a dead worker;
    recover_stale() puts it back to pending (up to MAX_ATTEMPTS attempts,
    then it and its scan are failed).
  * Handlers (registered by backend/main.py) already record their own errors
    on the scan; anything that still escapes is caught here so a job can
    never be left running forever.

Modes (SCAN_WORKER_MODE):
  inline (default)  the API process runs jobs itself: each request kicks its
                    own job immediately and an embedded thread picks up
                    anything left over (e.g. jobs recovered after a crash).
  external          the API only enqueues; run `python -m backend.worker`
                    (one or more) to do the work.
"""
import logging
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from backend import db

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 3
ACTIVE_STATUSES = ("queued", "running")

_handlers: dict[str, Callable[[str], None]] = {}

# Scans are heavy (Semgrep is CPU and memory hungry), so only a few run at once in this
# process. They run on their OWN small thread pool, not the web server's: jobs waiting for
# a turn sit in this pool's queue (as "pending", which users see as "queued") instead of
# blocking threads that requests need. (Found with the load test: 40 waiting scans on the
# shared pool left no thread free to answer even /healthz.)
_executor_lock = threading.Lock()
_executor: tuple[int, ThreadPoolExecutor] | None = None


def scan_concurrency() -> int:
    try:
        return max(int(os.getenv("SCAN_CONCURRENCY", "3")), 1)
    except ValueError:
        return 3


def _get_executor() -> ThreadPoolExecutor:
    """One pool per process, rebuilt if SCAN_CONCURRENCY changes."""
    global _executor
    size = scan_concurrency()
    with _executor_lock:
        if _executor is None or _executor[0] != size:
            if _executor is not None:
                _executor[1].shutdown(wait=False)
            _executor = (size, ThreadPoolExecutor(max_workers=size, thread_name_prefix="scan"))
        return _executor[1]


def submit(job_id: str) -> None:
    """Queue a job on the scan pool and return immediately. Never blocks the caller."""

    def run() -> None:
        try:
            process(job_id)
        except Exception:  # process() settles the scan itself; this only guards the pool thread
            logger.exception("scan pool: job %s crashed outside its handler", job_id)

    _get_executor().submit(run)


def shutdown() -> None:
    """Stop accepting work at app shutdown. Queued jobs stay 'pending' in the database
    and are picked up after the next start, so nothing is lost."""
    global _executor
    with _executor_lock:
        if _executor is not None:
            _executor[1].shutdown(wait=False, cancel_futures=True)
            _executor = None


def register(kind: str, handler: Callable[[str], None]) -> None:
    _handlers[kind] = handler


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


def inline() -> bool:
    return os.getenv("SCAN_WORKER_MODE", "inline").lower() != "external"


def worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def enqueue(session: Session, scan_id: str, kind: str) -> db.ScanJob:
    """Adds a pending job. The caller commits, so the job appears atomically
    with the scan state change that requested it."""
    job = db.ScanJob(scan_id=scan_id, kind=kind)
    session.add(job)
    session.flush()
    return job


def _claim(session: Session, job_id: str, wid: str) -> bool:
    claimed = session.execute(
        update(db.ScanJob)
        .where(db.ScanJob.id == job_id, db.ScanJob.status == "pending")
        .values(status="running", locked_by=wid, locked_at=_now(), attempts=db.ScanJob.attempts + 1)
    ).rowcount
    session.commit()
    return claimed == 1


def _heartbeat(job_id: str, wid: str, stop: threading.Event) -> None:
    interval = _float_env("JOB_HEARTBEAT_SECONDS", 15)
    while not stop.wait(interval):
        try:
            with db.SessionLocal() as session:
                session.execute(
                    update(db.ScanJob)
                    .where(db.ScanJob.id == job_id, db.ScanJob.locked_by == wid, db.ScanJob.status == "running")
                    .values(locked_at=_now())
                )
                session.commit()
        except Exception:  # a missed beat is survivable; the next one may succeed
            logger.warning("job heartbeat failed for %s", job_id, exc_info=True)


def _settle_scan_after_crash(session: Session, scan_id: str, kind: str, message: str) -> None:
    """A handler died without settling its scan. A scan with earlier results
    (a rescan that crashed) keeps them and goes back to "completed" with the
    error recorded; one with nothing to show is simply failed."""
    scan = session.get(db.Scan, scan_id)
    if scan is None or scan.status not in ACTIVE_STATUSES:
        return
    has_results = session.query(db.Finding.id).filter_by(scan_id=scan_id).first() is not None
    scan.status = "completed" if kind != "scan" and has_results else "failed"
    scan.error = message


def process(job_id: str, wid: str | None = None) -> bool:
    """Claims and runs one job. Returns False if another worker got it first."""
    wid = wid or worker_id()
    with db.SessionLocal() as session:
        if not _claim(session, job_id, wid):
            return False
        job = session.get(db.ScanJob, job_id)
        scan_id, kind = job.scan_id, job.kind

    stop = threading.Event()
    beat = threading.Thread(target=_heartbeat, args=(job_id, wid, stop), daemon=True)
    beat.start()
    error: Exception | None = None
    try:
        handler = _handlers.get(kind)
        if handler is None:
            raise RuntimeError(f"no handler registered for job kind '{kind}'")
        handler(scan_id)
    except Exception as exc:
        error = exc
        logger.exception("job %s (%s) crashed", job_id, kind)
        try:
            import sentry_sdk

            sentry_sdk.capture_exception(exc)
        except Exception:
            pass
    finally:
        stop.set()
        beat.join(timeout=5)

    with db.SessionLocal() as session:
        job = session.get(db.ScanJob, job_id)
        job.status = "failed" if error else "done"
        job.finished_at = _now()
        if error:
            _settle_scan_after_crash(session, scan_id, kind, f"Scan failed: {error}")
        session.commit()
    return True


def next_pending_id(session: Session) -> str | None:
    row = (
        session.query(db.ScanJob.id)
        .filter(db.ScanJob.status == "pending")
        .order_by(db.ScanJob.created_at)
        .first()
    )
    return row[0] if row else None


def run_pending(wid: str | None = None, limit: int | None = None, stop: threading.Event | None = None) -> int:
    """Runs pending jobs one after another until none are left (or `stop` is
    set, which lets a worker finish its current job and exit). Returns how many ran."""
    done = 0
    while (limit is None or done < limit) and not (stop is not None and stop.is_set()):
        with db.SessionLocal() as session:
            job_id = next_pending_id(session)
        if job_id is None:
            break
        if process(job_id, wid):
            done += 1
    return done


def recover_stale(session: Session, stale_seconds: float | None = None) -> tuple[int, int]:
    """Frees jobs whose worker died. Returns (requeued, failed)."""
    stale = stale_seconds if stale_seconds is not None else _float_env("JOB_STALE_SECONDS", 90)
    cutoff = _now() - timedelta(seconds=stale)
    requeued = failed = 0

    for job in session.query(db.ScanJob).filter(db.ScanJob.status == "running", db.ScanJob.locked_at < cutoff).all():
        exhausted = job.attempts >= MAX_ATTEMPTS
        # Conditional on the row still being stale, so a job that a live worker
        # refreshed or finished in the meantime is left alone.
        changed = session.execute(
            update(db.ScanJob)
            .where(db.ScanJob.id == job.id, db.ScanJob.status == "running", db.ScanJob.locked_at < cutoff)
            .values(
                status="failed" if exhausted else "pending",
                locked_by=None,
                locked_at=None,
                finished_at=_now() if exhausted else None,
            )
            .execution_options(synchronize_session=False)
        ).rowcount
        if not changed:
            continue
        if exhausted:
            _settle_scan_after_crash(session, job.scan_id, job.kind, "Scan was interrupted repeatedly and gave up. Please scan again.")
            failed += 1
        else:
            requeued += 1
    session.commit()
    if requeued or failed:
        logger.warning("recovered stale jobs: %d requeued, %d failed", requeued, failed)
    return requeued, failed


def fail_orphaned_scans(session: Session) -> int:
    """Scans that claim to be queued/running but have no live job can never
    finish (e.g. created before the queue existed); fail them instead of
    leaving the UI polling forever."""
    live = select(db.ScanJob.scan_id).where(db.ScanJob.status.in_(("pending", "running")))
    orphans = (
        session.query(db.Scan)
        .filter(db.Scan.status.in_(ACTIVE_STATUSES), db.Scan.id.notin_(live))
        .all()
    )
    for scan in orphans:
        scan.status = "failed"
        scan.error = "Scan was interrupted by a server restart. Please scan again."
    session.commit()
    return len(orphans)


def purge_finished(session: Session, days: int = 7) -> int:
    cutoff = _now() - timedelta(days=days)
    removed = session.execute(
        delete(db.ScanJob).where(db.ScanJob.status.in_(("done", "failed")), db.ScanJob.finished_at < cutoff)
    ).rowcount
    session.commit()
    return removed


def _housekeeping() -> None:
    """Old finished jobs, and (if ANON_SCAN_RETENTION_DAYS is set) expired
    anonymous scans."""
    from backend import deletion

    with db.SessionLocal() as session:
        purge_finished(session)
    from backend import limits

    limits.db_store.purge()
    days = int(_float_env("ANON_SCAN_RETENTION_DAYS", 0))
    if days > 0:
        with db.SessionLocal() as session:
            removed = deletion.purge_expired_anonymous_scans(session, days)
        if removed:
            logger.info("retention: deleted %d anonymous scans older than %d days", removed, days)


def maintenance_loop(stop: threading.Event, run_jobs: bool) -> None:
    """Background loop for the embedded worker and for standalone workers:
    picks up pending jobs, and periodically recovers stale ones."""
    poll = _float_env("JOB_POLL_SECONDS", 2)
    last_recovery = 0.0
    last_purge = -1e9
    import time

    while not stop.is_set():
        # Independent steps: a failure while recovering must not stop jobs from running.
        now = time.monotonic()
        if now - last_recovery >= _float_env("JOB_RECOVERY_SECONDS", 30):
            last_recovery = now
            try:
                with db.SessionLocal() as session:
                    recover_stale(session)
            except Exception:
                logger.exception("job recovery failed")
        if now - last_purge >= _float_env("JOB_PURGE_SECONDS", 3600):
            last_purge = now
            try:
                _housekeeping()
            except Exception:
                logger.exception("housekeeping failed")
        if run_jobs:
            try:
                run_pending(stop=stop)
            except Exception:
                logger.exception("job runner failed")
        stop.wait(poll)

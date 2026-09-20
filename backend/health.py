"""Health endpoints for load balancers and uptime monitors.

  GET /healthz   liveness: the process is up. Touches nothing else, so a
                 database outage can't get a healthy web process restarted.
  GET /readyz    readiness: the database answers, its migrations are at the
                 version this code expects, and the job queue is moving.
                 Returns 503 (with the reason) when the instance should not
                 receive traffic. Reports counts only -- nothing sensitive.
"""
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Response
from sqlalchemy import func, text

from backend import db, jobs

router = APIRouter()

# A pending job older than this suggests no worker is running (or none can keep up).
QUEUE_STALL_SECONDS = 300


@lru_cache(maxsize=1)
def expected_revision() -> str:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    return ScriptDirectory.from_config(cfg).get_current_head()


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.get("/readyz")
def readyz(response: Response):
    problems: list[str] = []
    info: dict = {"mode": "inline" if jobs.inline() else "external"}
    try:
        with db.SessionLocal() as session:
            session.execute(text("select 1"))

            try:
                version = session.execute(text("select version_num from alembic_version")).scalar()
            except Exception:
                session.rollback()
                version = None
            info["migration"] = version
            if version != expected_revision():
                problems.append(f"database migrations are at {version!r}, expected {expected_revision()!r}")

            if version is not None:
                now = datetime.now(timezone.utc)
                pending = session.query(func.count(db.ScanJob.id)).filter_by(status="pending").scalar()
                running = session.query(func.count(db.ScanJob.id)).filter_by(status="running").scalar()
                oldest = session.query(func.min(db.ScanJob.created_at)).filter_by(status="pending").scalar()
                info["queue"] = {"pending": pending, "running": running}
                if oldest is not None:
                    if oldest.tzinfo is None:
                        oldest = oldest.replace(tzinfo=timezone.utc)
                    age = (now - oldest).total_seconds()
                    info["queue"]["oldest_pending_seconds"] = int(age)
                    # Only a problem in external mode, where something else must be draining the queue.
                    if age > QUEUE_STALL_SECONDS and not jobs.inline():
                        problems.append("scan queue is not being processed (is a worker running?)")
    except Exception as exc:
        problems.append(f"database unreachable: {exc.__class__.__name__}")

    if problems:
        response.status_code = 503
    return {"status": "unavailable" if problems else "ok", "problems": problems, **info}

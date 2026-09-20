"""A small real load test in the normal suite.

Starts the actual API (uvicorn, on a real port) with a stub scanner and hits it
with concurrent users through the load generator. It is far smaller than a
real load test (see loadtest/README.md) but fails if pool or thread starvation
comes back: that regression made 75% of scans fail at 50 users."""
import asyncio
import socket
import threading
import time

import pytest
import uvicorn

from backend import auth, db, jobs, limits, main
from backend.db import Base, engine
from loadtest.run import pct, run_level

pytestmark = pytest.mark.real_executor

USERS = 40
SCAN_SECONDS = 0.15


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def server(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    db.init_db()  # migrated, so /readyz reports queue depth like a real deployment
    limits.ip_limiter.reset()
    for name in ("SCAN_RATE_LIMIT_PER_HOUR", "DAILY_SCAN_CAP"):
        monkeypatch.setenv(name, "0")
    monkeypatch.setenv("SCAN_CONCURRENCY", "4")
    monkeypatch.delenv("SCAN_WORKER_MODE", raising=False)

    def stub(target, **kw):
        time.sleep(SCAN_SECONDS)
        return {
            "target": target, "platform": "generic", "commit_sha": None, "unchanged": False,
            "findings": [{
                "category": "hardcoded_secret", "label": f"finding {i}", "file": f"src/f{i}.ts", "severity": "high",
                "what_it_means": "x", "why_it_matters": "y", "fix_prompt": "z",
            } for i in range(5)],
        }

    monkeypatch.setattr(main, "run_full_scan", stub)

    port = _free_port()
    config = uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="error")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started, "test server did not start"
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(timeout=10)
    jobs.shutdown()
    Base.metadata.drop_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(db.text("drop table if exists alembic_version"))


def test_concurrent_users_all_get_their_scans_and_the_api_stays_responsive(server):
    level = asyncio.run(run_level(server, USERS, "https://github.com/example/app", poll=0.2, timeout=60, readers=3))

    bad = {k: v for k, v in level.codes.items() if str(k) not in ("200", "202")}
    assert level.failed == 0 and level.ok == USERS, f"{level.ok}/{USERS} scans finished; problems: {bad}"
    assert not bad, f"unexpected responses under load: {bad}"
    assert pct(level.reader, 95) < 1.0, f"/healthz p95 was {pct(level.reader, 95):.2f}s under load"
    assert pct(level.submit, 95) < 5.0, f"submitting took {pct(level.submit, 95):.2f}s at p95"
    assert level.peak_running <= 5  # 4 scan slots (+1 for the recovery thread), however many users there are
    assert level.peak_pending > 4  # and the rest really did queue


def test_the_queue_drains_completely(server):
    asyncio.run(run_level(server, 12, "https://github.com/example/app", poll=0.2, timeout=60, readers=1))
    with db.SessionLocal() as s:
        assert s.query(db.ScanJob).filter(db.ScanJob.status.in_(("pending", "running"))).count() == 0
        assert s.query(db.Scan).filter(db.Scan.status.in_(("queued", "running"))).count() == 0
    time.sleep(0.5)  # let the server finish answering its last requests
    assert db.engine.pool.checkedout() == 0  # nothing left checked out once the load is gone (outside our own session)

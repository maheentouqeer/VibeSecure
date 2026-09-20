"""The scan pool and connection handling, found and fixed with the load test.

Under load the API used to fail for three reasons: a running scan held a
database connection for its whole duration, each queued scan pinned its
request's connection, and scans waiting for a turn blocked the web server's
own threads. These tests keep all three fixed. They use the real background
pool (the rest of the suite runs jobs inline)."""
import threading
import time

import pytest
from fastapi.testclient import TestClient

from backend import db, jobs, limits, main
from backend.db import Base, engine

pytestmark = pytest.mark.real_executor

TARGET = "https://github.com/example/app"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    monkeypatch.setenv("DAILY_SCAN_CAP", "0")
    monkeypatch.delenv("SCAN_WORKER_MODE", raising=False)
    monkeypatch.delenv("SCAN_CONCURRENCY", raising=False)
    yield
    jobs.shutdown()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


class Gate:
    """A fake scanner that blocks until released, and records how many run at once."""

    def __init__(self):
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.running = 0
        self.peak = 0
        self.started = threading.Semaphore(0)
        self.connections_held_during_scan: list[int] = []

    def __call__(self, target, **kw):
        with self.lock:
            self.running += 1
            self.peak = max(self.peak, self.running)
        self.connections_held_during_scan.append(db.engine.pool.checkedout())
        self.started.release()
        self.release.wait(15)
        with self.lock:
            self.running -= 1
        return {"target": target, "platform": "generic", "commit_sha": None, "unchanged": False, "findings": []}


@pytest.fixture()
def gate(monkeypatch):
    g = Gate()
    monkeypatch.setattr(main, "run_full_scan", g)
    yield g
    g.release.set()


def _wait_for(predicate, seconds=10):
    end = time.time() + seconds
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _statuses():
    with db.SessionLocal() as s:
        return sorted(scan.status for scan in s.query(db.Scan))


def _job_statuses():
    with db.SessionLocal() as s:
        return sorted(j.status for j in s.query(db.ScanJob))


# ================================ the pool ==================================


def test_submit_returns_immediately_and_the_scan_runs_in_the_background(client, gate):
    resp = client.post("/scans", json={"target": TARGET})
    assert resp.status_code == 202
    assert gate.started.acquire(timeout=5)  # it is running now...
    assert _statuses() == ["running"]
    gate.release.set()  # ...and finishes without anyone waiting on it
    assert _wait_for(lambda: _statuses() == ["completed"])


def test_at_most_scan_concurrency_scans_run_at_once_and_the_rest_wait_as_queued(client, gate, monkeypatch):
    monkeypatch.setenv("SCAN_CONCURRENCY", "2")
    for _ in range(6):
        assert client.post("/scans", json={"target": TARGET}).status_code == 202

    assert gate.started.acquire(timeout=5) and gate.started.acquire(timeout=5)
    time.sleep(0.5)  # give any (wrongly) extra scans the chance to start
    assert gate.peak == 2
    assert _statuses().count("running") == 2 and _statuses().count("queued") == 4
    assert _job_statuses().count("running") == 2 and _job_statuses().count("pending") == 4  # honest, not stuck

    gate.release.set()
    assert _wait_for(lambda: _statuses() == ["completed"] * 6)
    assert gate.peak == 2


def test_the_default_is_a_small_number_that_protects_the_machine():
    assert jobs.scan_concurrency() == 3


@pytest.mark.parametrize("value, expected", [("5", 5), ("0", 1), ("-3", 1), ("garbage", 3), ("", 3)])
def test_scan_concurrency_setting_is_parsed_safely(monkeypatch, value, expected):
    monkeypatch.setenv("SCAN_CONCURRENCY", value)
    assert jobs.scan_concurrency() == expected


def test_changing_the_setting_rebuilds_the_pool(monkeypatch):
    monkeypatch.setenv("SCAN_CONCURRENCY", "2")
    first = jobs._get_executor()
    assert jobs._get_executor() is first  # stable while the setting is unchanged
    monkeypatch.setenv("SCAN_CONCURRENCY", "4")
    assert jobs._get_executor() is not first


def test_shutdown_leaves_queued_jobs_pending_so_they_survive_a_restart(client, gate, monkeypatch):
    monkeypatch.setenv("SCAN_CONCURRENCY", "1")
    for _ in range(3):
        client.post("/scans", json={"target": TARGET})
    assert gate.started.acquire(timeout=5)

    jobs.shutdown()  # what the app does when it stops
    gate.release.set()
    assert _wait_for(lambda: _job_statuses().count("done") == 1)
    assert _job_statuses().count("pending") == 2  # nothing lost: still queued in the database

    # the next start picks them up (here: the recovery loop's runner)
    monkeypatch.setattr(main, "run_full_scan", lambda t, **kw: {
        "target": t, "platform": "generic", "commit_sha": None, "unchanged": False, "findings": []})
    assert jobs.run_pending() == 2
    assert _statuses() == ["completed"] * 3


# ============================= connections ==================================


def test_a_running_scan_holds_no_database_connection(client, gate):
    client.post("/scans", json={"target": TARGET})
    assert gate.started.acquire(timeout=5)
    time.sleep(0.3)
    assert db.engine.pool.checkedout() == 0  # the scan is mid-run, and the pool is untouched
    assert gate.connections_held_during_scan == [0]
    gate.release.set()
    assert _wait_for(lambda: _statuses() == ["completed"])


def test_a_rescan_holds_no_connection_either(client, gate):
    first = client.post("/scans", json={"target": TARGET})
    token = {"X-Owner-Token": first.headers["X-Owner-Token"]}
    scan_id = first.json()["id"]
    gate.release.set()
    assert _wait_for(lambda: _statuses() == ["completed"])

    gate.release.clear()
    gate.connections_held_during_scan.clear()
    assert client.post(f"/scans/{scan_id}/rescan", headers=token).status_code == 202
    assert gate.started.acquire(timeout=5) and gate.started.acquire(timeout=5)
    time.sleep(0.3)
    assert gate.connections_held_during_scan[-1] == 0 and db.engine.pool.checkedout() == 0
    gate.release.set()


def test_scans_waiting_for_a_slot_pin_no_connections(client, gate, monkeypatch):
    """FastAPI keeps a request's session open until its background task ends; queued
    scans used to pin one connection each and starve every other request."""
    monkeypatch.setenv("SCAN_CONCURRENCY", "1")
    for _ in range(5):
        assert client.post("/scans", json={"target": TARGET}).status_code == 202
    assert gate.started.acquire(timeout=5)
    time.sleep(0.5)  # 1 scan running, 4 waiting
    assert db.engine.pool.checkedout() == 0
    gate.release.set()


def test_the_webhook_also_releases_its_connection(client, gate, monkeypatch):
    import hashlib
    import hmac
    import json

    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s3cret")
    monkeypatch.setenv("SCAN_CONCURRENCY", "1")
    gate.release.set()
    for _ in range(3):  # three different owners scanned the repo
        client.post("/scans", json={"target": TARGET})
    assert _wait_for(lambda: _statuses() == ["completed"] * 3)

    gate.release.clear()
    body = json.dumps({"ref": "refs/heads/main", "repository": {
        "full_name": "example/app", "html_url": TARGET, "default_branch": "main"}}).encode()
    sig = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    resp = client.post("/webhooks/github", content=body, headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": sig})
    assert resp.json() == {"triggered": 3}
    assert gate.started.acquire(timeout=5)
    time.sleep(0.4)  # one re-scan running, two waiting
    assert db.engine.pool.checkedout() == 0
    gate.release.set()


def test_the_pool_is_sized_for_the_request_threads_and_configurable():
    assert db.engine.pool.size() == 20 and db.engine.pool._max_overflow == 20
    assert db.engine.pool._timeout == 15


@pytest.mark.parametrize("value, expected", [("7", 7), ("0", 1), ("nope", 20)])
def test_pool_settings_are_parsed_safely(monkeypatch, value, expected):
    monkeypatch.setenv("DB_POOL_SIZE", value)
    assert db._int_env("DB_POOL_SIZE", 20) == expected


# ================================ responsiveness ============================


def test_the_api_stays_responsive_while_many_scans_wait(client, gate, monkeypatch):
    """Waiting scans must not use up the threads that answer requests (the /healthz timeouts under load)."""
    monkeypatch.setenv("SCAN_CONCURRENCY", "1")
    for _ in range(60):  # more than the web server's 40 request threads
        client.post("/scans", json={"target": TARGET})
    assert gate.started.acquire(timeout=5)

    started = time.time()
    assert client.get("/healthz").status_code == 200
    assert client.get("/me").status_code == 200  # a request that needs the database too
    assert time.time() - started < 2  # would hang if the request threads were all stuck waiting
    assert _job_statuses().count("pending") == 59
    gate.release.set()

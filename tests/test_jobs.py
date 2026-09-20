"""Job queue: atomic claiming, heartbeats, crash recovery, external-worker mode."""
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend import db, jobs, limits, main
from backend.db import Base, engine

REPO = "https://github.com/example/app"
FINDING = {
    "category": "missing_access_control",
    "label": "Row-Level Security not enabled",
    "file": "supabase migrations",
    "severity": "critical",
    "what_it_means": "x",
    "why_it_matters": "y",
    "fix_prompt": "z",
}


def _result(findings=None):
    return {
        "target": REPO, "platform": "generic", "commit_sha": None, "unchanged": False,
        "findings": [dict(FINDING)] if findings is None else findings,
    }


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    monkeypatch.delenv("SCAN_WORKER_MODE", raising=False)
    monkeypatch.setattr(main, "run_full_scan", lambda target, **kw: _result())
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


def _scan(status="queued", owner_token="tok") -> str:
    with db.SessionLocal() as s:
        scan = db.Scan(target=REPO, platform="generic", status=status, owner_token=owner_token)
        s.add(scan)
        s.commit()
        return scan.id


def _job(scan_id, kind="scan", status="pending", attempts=0, locked_ago=None) -> str:
    with db.SessionLocal() as s:
        job = db.ScanJob(scan_id=scan_id, kind=kind, status=status, attempts=attempts)
        if locked_ago is not None:
            job.locked_at = datetime.now(timezone.utc) - timedelta(seconds=locked_ago)
            job.locked_by = "dead-worker"
        s.add(job)
        s.commit()
        return job.id


def _get(model, pk):
    with db.SessionLocal() as s:
        row = s.get(model, pk)
        s.expunge(row)
        return row


def _findings(scan_id):
    with db.SessionLocal() as s:
        return s.query(db.Finding).filter_by(scan_id=scan_id).count()


# ----------------------------------------------------------------- claiming


def test_claim_is_exclusive_across_concurrent_workers():
    job_id = _job(_scan())
    wins, barrier = [], threading.Barrier(8)

    def race(i):
        with db.SessionLocal() as s:
            barrier.wait()
            wins.append(jobs._claim(s, job_id, f"worker-{i}"))

    threads = [threading.Thread(target=race, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert sorted(wins) == [False] * 7 + [True]
    job = _get(db.ScanJob, job_id)
    assert job.status == "running" and job.attempts == 1 and job.locked_by.startswith("worker-")


def test_process_skips_a_job_someone_else_already_took():
    job_id = _job(_scan(), status="running", attempts=1, locked_ago=1)
    assert jobs.process(job_id) is False


def test_process_runs_the_scan_and_marks_the_job_done():
    scan_id = _scan()
    job_id = _job(scan_id)

    assert jobs.process(job_id) is True

    assert _get(db.ScanJob, job_id).status == "done"
    assert _get(db.ScanJob, job_id).finished_at is not None
    assert _get(db.Scan, scan_id).status == "completed"
    assert _findings(scan_id) == 1


def test_running_the_same_completed_scan_job_twice_never_duplicates_findings():
    scan_id = _scan()
    jobs.process(_job(scan_id))
    jobs.process(_job(scan_id))  # e.g. a job recovered after it had actually finished
    assert _findings(scan_id) == 1


# ------------------------------------------------------------------ failures


def test_handler_crash_fails_job_and_settles_a_first_scan(monkeypatch):
    def crash(scan_id):
        raise RuntimeError("handler bug")

    monkeypatch.setitem(jobs._handlers, "scan", crash)
    scan_id = _scan()
    job_id = _job(scan_id)

    assert jobs.process(job_id) is True
    assert _get(db.ScanJob, job_id).status == "failed"
    scan = _get(db.Scan, scan_id)
    assert scan.status == "failed" and "handler bug" in scan.error


def test_handler_crash_on_a_rescan_keeps_earlier_results(monkeypatch):
    scan_id = _scan()
    jobs.process(_job(scan_id))  # a normal first scan
    with db.SessionLocal() as s:
        s.get(db.Scan, scan_id).status = "running"
        s.commit()

    monkeypatch.setitem(jobs._handlers, "rescan", lambda sid: (_ for _ in ()).throw(RuntimeError("boom")))
    jobs.process(_job(scan_id, kind="rescan"))

    scan = _get(db.Scan, scan_id)
    assert scan.status == "completed" and "boom" in scan.error
    assert _findings(scan_id) == 1


def test_unknown_job_kind_fails_instead_of_hanging():
    scan_id = _scan()
    job_id = _job(scan_id, kind="mystery")
    jobs.process(job_id)
    assert _get(db.ScanJob, job_id).status == "failed"
    assert _get(db.Scan, scan_id).status == "failed"


# ------------------------------------------------------------------ recovery


def test_stale_running_job_is_requeued_then_eventually_given_up_on():
    scan_id = _scan(status="running")
    job_id = _job(scan_id, status="running", attempts=1, locked_ago=500)

    with db.SessionLocal() as s:
        assert jobs.recover_stale(s, stale_seconds=90) == (1, 0)
    job = _get(db.ScanJob, job_id)
    assert job.status == "pending" and job.locked_by is None and job.attempts == 1

    exhausted = _job(scan_id, status="running", attempts=jobs.MAX_ATTEMPTS, locked_ago=500)
    with db.SessionLocal() as s:
        assert jobs.recover_stale(s, stale_seconds=90) == (0, 1)
    assert _get(db.ScanJob, exhausted).status == "failed"
    scan = _get(db.Scan, scan_id)
    assert scan.status == "failed" and "interrupted repeatedly" in scan.error


def test_a_recently_locked_job_is_left_alone():
    job_id = _job(_scan(status="running"), status="running", attempts=1, locked_ago=5)
    with db.SessionLocal() as s:
        assert jobs.recover_stale(s, stale_seconds=90) == (0, 0)
    assert _get(db.ScanJob, job_id).status == "running"


def test_crashed_worker_scan_completes_after_recovery():
    """A worker claimed the job and died: after recovery another worker finishes the scan."""
    scan_id = _scan(status="running")
    _job(scan_id, status="running", attempts=1, locked_ago=1000)

    with db.SessionLocal() as s:
        jobs.recover_stale(s, stale_seconds=90)
    assert jobs.run_pending() == 1

    assert _get(db.Scan, scan_id).status == "completed"
    assert _findings(scan_id) == 1


def test_heartbeat_keeps_a_long_job_from_being_recovered(monkeypatch):
    monkeypatch.setenv("JOB_HEARTBEAT_SECONDS", "0.1")
    finished = threading.Event()

    def slow(scan_id):
        time.sleep(0.8)
        finished.set()

    monkeypatch.setitem(jobs._handlers, "scan", slow)
    scan_id = _scan()
    job_id = _job(scan_id)

    runner = threading.Thread(target=jobs.process, args=(job_id,))
    runner.start()
    recovered = 0
    while not finished.is_set():
        with db.SessionLocal() as s:
            recovered += sum(jobs.recover_stale(s, stale_seconds=0.4))  # far shorter than the job
        time.sleep(0.05)
    runner.join()

    assert recovered == 0
    assert _get(db.ScanJob, job_id).status == "done"


def test_a_job_with_no_heartbeat_would_have_been_recovered(monkeypatch):
    """Control for the test above: the same timings without beats do get recovered."""
    monkeypatch.setenv("JOB_HEARTBEAT_SECONDS", "60")
    started, release = threading.Event(), threading.Event()

    def slow(scan_id):
        started.set()
        release.wait(5)

    monkeypatch.setitem(jobs._handlers, "scan", slow)
    job_id = _job(_scan())
    runner = threading.Thread(target=jobs.process, args=(job_id,))
    runner.start()
    started.wait(2)
    time.sleep(0.5)
    with db.SessionLocal() as s:
        requeued, _ = jobs.recover_stale(s, stale_seconds=0.3)
    release.set()
    runner.join()
    assert requeued == 1


def test_orphaned_scans_without_a_live_job_are_failed_but_queued_ones_are_kept():
    waiting = _scan(status="queued")
    _job(waiting, status="pending")
    busy = _scan(status="running")
    _job(busy, status="running", attempts=1, locked_ago=1)
    orphan = _scan(status="running")
    _job(orphan, status="done")
    legacy = _scan(status="queued")

    with db.SessionLocal() as s:
        assert jobs.fail_orphaned_scans(s) == 2

    assert _get(db.Scan, waiting).status == "queued"
    assert _get(db.Scan, busy).status == "running"
    assert _get(db.Scan, orphan).status == "failed"
    assert _get(db.Scan, legacy).status == "failed"


def test_purge_removes_only_old_finished_jobs():
    scan_id = _scan(status="completed")
    old, fresh, pending = (_job(scan_id, status="done"), _job(scan_id, status="done"), _job(scan_id))
    with db.SessionLocal() as s:
        s.get(db.ScanJob, old).finished_at = datetime.now(timezone.utc) - timedelta(days=30)
        s.get(db.ScanJob, fresh).finished_at = datetime.now(timezone.utc)
        s.commit()
    with db.SessionLocal() as s:
        assert jobs.purge_finished(s, days=7) == 1
    assert _get(db.ScanJob, fresh) is not None and _get(db.ScanJob, pending) is not None


# --------------------------------------------------------------- run_pending


def test_run_pending_processes_oldest_first_and_honours_limit_and_stop():
    order = []
    jobs._handlers["scan"] = lambda sid: order.append(sid)
    try:
        ids = [_scan() for _ in range(4)]
        for sid in ids:
            _job(sid)
            time.sleep(0.01)

        assert jobs.run_pending(limit=2) == 2
        assert order == ids[:2]

        stop = threading.Event()
        stop.set()
        assert jobs.run_pending(stop=stop) == 0

        assert jobs.run_pending() == 2
        assert order == ids
    finally:
        jobs._handlers["scan"] = main._run_scan_job


# ------------------------------------------------- API in external-worker mode


def test_external_mode_enqueues_and_leaves_the_work_to_a_worker(client, monkeypatch):
    monkeypatch.setenv("SCAN_WORKER_MODE", "external")
    resp = client.post("/scans", json={"target": REPO})
    assert resp.status_code == 202
    scan_id, token = resp.json()["id"], {"X-Owner-Token": resp.headers["X-Owner-Token"]}

    # nothing ran inside the API process
    assert client.get(f"/scans/{scan_id}", headers=token).json()["status"] == "queued"
    with db.SessionLocal() as s:
        job = s.query(db.ScanJob).one()
        assert (job.kind, job.status, job.scan_id) == ("scan", "pending", scan_id)

    assert jobs.run_pending() == 1  # what `python -m backend.worker` does

    done = client.get(f"/scans/{scan_id}", headers=token).json()
    assert done["status"] == "completed" and len(done["findings"]) == 1


def test_external_mode_rescan_is_queued_and_blocks_duplicates(client, monkeypatch):
    resp = client.post("/scans", json={"target": REPO})  # inline: finishes immediately
    scan_id, token = resp.json()["id"], {"X-Owner-Token": resp.headers["X-Owner-Token"]}
    monkeypatch.setenv("SCAN_WORKER_MODE", "external")

    again = client.post(f"/scans/{scan_id}/rescan", headers=token)
    assert again.status_code == 202 and again.json()["status"] == "queued"
    assert client.post(f"/scans/{scan_id}/rescan", headers=token).status_code == 409

    monkeypatch.setattr(main, "run_full_scan", lambda target, **kw: _result([]))
    assert jobs.run_pending() == 1
    body = client.get(f"/scans/{scan_id}", headers=token).json()
    assert body["status"] == "completed" and body["findings"][0]["status"] == "resolved"


def test_inline_mode_records_a_finished_job_per_request(client):
    client.post("/scans", json={"target": REPO})
    with db.SessionLocal() as s:
        job = s.query(db.ScanJob).one()
    assert job.status == "done" and job.attempts == 1 and job.finished_at is not None


def test_embedded_worker_thread_picks_up_and_recovers_jobs(client, monkeypatch):
    monkeypatch.setenv("SCAN_WORKER_MODE", "external")  # API enqueues only
    monkeypatch.setenv("JOB_POLL_SECONDS", "0.05")
    monkeypatch.setenv("JOB_RECOVERY_SECONDS", "0.05")
    resp = client.post("/scans", json={"target": REPO})
    scan_id, token = resp.json()["id"], {"X-Owner-Token": resp.headers["X-Owner-Token"]}

    # a worker that died holding a second job
    dead_scan = _scan(status="running", owner_token="other")
    _job(dead_scan, status="running", attempts=1, locked_ago=1000)

    stop = threading.Event()
    worker = threading.Thread(target=jobs.maintenance_loop, args=(stop, True))
    worker.start()
    try:
        deadline = time.time() + 8
        while time.time() < deadline:
            if (
                client.get(f"/scans/{scan_id}", headers=token).json()["status"] == "completed"
                and _get(db.Scan, dead_scan).status == "completed"
            ):
                break
            time.sleep(0.1)
    finally:
        stop.set()
        worker.join(timeout=5)

    assert client.get(f"/scans/{scan_id}", headers=token).json()["status"] == "completed"
    assert _get(db.Scan, dead_scan).status == "completed"
    assert not worker.is_alive()

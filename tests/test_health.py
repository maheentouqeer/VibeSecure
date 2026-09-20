"""Liveness and readiness endpoints."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from backend import db, health, main
from backend.db import Base, engine


@pytest.fixture(autouse=True)
def _migrated_db(monkeypatch):
    """A database migrated the real way (with alembic_version), unlike the
    create_all() shortcut the other test files use."""
    Base.metadata.drop_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("drop table if exists alembic_version"))
    db.init_db()
    monkeypatch.delenv("SCAN_WORKER_MODE", raising=False)
    yield
    Base.metadata.drop_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("drop table if exists alembic_version"))


@pytest.fixture()
def client():
    return TestClient(main.app)


def _add_job(status="pending", age_seconds=0):
    with db.SessionLocal() as s:
        scan = db.Scan(target="https://x.test", platform="generic", status="queued", owner_token="t")
        s.add(scan)
        s.flush()
        s.add(
            db.ScanJob(
                scan_id=scan.id, kind="scan", status=status,
                created_at=datetime.now(timezone.utc) - timedelta(seconds=age_seconds),
            )
        )
        s.commit()


def test_healthz_is_always_ok_and_does_not_touch_the_database(client, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("healthz must not use the database")

    monkeypatch.setattr(db, "SessionLocal", boom)
    resp = client.get("/healthz")
    assert resp.status_code == 200 and resp.json() == {"status": "ok"}


def test_readyz_reports_ok_with_the_migration_and_queue_state(client):
    _add_job("pending", 2)
    _add_job("running", 2)
    body = client.get("/readyz").json()

    assert body["status"] == "ok" and body["problems"] == []
    assert body["migration"] == health.expected_revision()
    assert body["mode"] == "inline"
    assert body["queue"]["pending"] == 1 and body["queue"]["running"] == 1
    assert body["queue"]["oldest_pending_seconds"] >= 2


def test_readyz_is_503_when_migrations_are_behind(client):
    with engine.begin() as conn:
        conn.execute(text("update alembic_version set version_num = '0001'"))
    resp = client.get("/readyz")
    assert resp.status_code == 503
    assert "migrations" in resp.json()["problems"][0] and resp.json()["migration"] == "0001"


def test_readyz_is_503_when_the_database_was_never_migrated(client):
    with engine.begin() as conn:
        conn.execute(text("drop table alembic_version"))
    resp = client.get("/readyz")
    assert resp.status_code == 503 and resp.json()["migration"] is None


def test_readyz_is_503_when_the_database_is_unreachable(client, monkeypatch):
    def down(*a, **k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(db, "SessionLocal", down)
    resp = client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["problems"] == ["database unreachable: RuntimeError"]


def test_a_stalled_queue_only_fails_readiness_when_workers_are_external(client, monkeypatch):
    _add_job("pending", health.QUEUE_STALL_SECONDS + 60)

    assert client.get("/readyz").status_code == 200  # inline: this process drains its own queue

    monkeypatch.setenv("SCAN_WORKER_MODE", "external")
    resp = client.get("/readyz")
    assert resp.status_code == 503 and "worker" in resp.json()["problems"][0]


def test_readiness_exposes_no_scan_or_user_data(client):
    _add_job("pending", 1)
    text_body = client.get("/readyz").text
    assert "x.test" not in text_body and "owner" not in text_body.lower()

"""The lightweight status endpoint used for polling, and releasing connections early."""
import pytest
from fastapi.testclient import TestClient

from backend import auth, db, limits, main, schemas
from backend.db import Base, engine
from test_accounts import _as, _FakeJwks, _make_scan, _scan_for

TARGET = "https://github.com/example/app"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    monkeypatch.delenv("SCAN_WORKER_MODE", raising=False)
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    monkeypatch.setattr(main, "run_full_scan", lambda target, **kw: _scan_for(target))
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


# ================================== status ==================================


def test_status_reports_only_the_state_not_the_findings(client):
    scan, token = _make_scan(client)
    resp = client.get(f"/scans/{scan['id']}/status", headers=token)

    assert resp.status_code == 200
    assert resp.json() == {"id": scan["id"], "status": "completed", "error": None}
    assert len(scan["findings"]) == 1  # the full scan still has them


def test_status_follows_the_scan_through_its_states(client, monkeypatch):
    monkeypatch.setenv("SCAN_WORKER_MODE", "external")  # nothing runs it, so it stays queued
    created = client.post("/scans", json={"target": TARGET})
    token = {"X-Owner-Token": created.headers["X-Owner-Token"]}
    scan_id = created.json()["id"]

    assert client.get(f"/scans/{scan_id}/status", headers=token).json()["status"] == "queued"
    with db.SessionLocal() as s:
        s.get(db.Scan, scan_id).status = "running"
        s.commit()
    assert client.get(f"/scans/{scan_id}/status", headers=token).json()["status"] == "running"


def test_status_carries_a_failure_message(client, monkeypatch):
    def boom(target, **kw):
        raise RuntimeError("clone exploded")

    monkeypatch.setattr(main, "run_full_scan", boom)
    scan, token = _make_scan(client)
    body = client.get(f"/scans/{scan['id']}/status", headers=token).json()
    assert body["status"] == "failed" and "clone exploded" in body["error"]


def test_status_follows_the_same_access_rules_as_the_scan(client):
    alice, bob = _as("alice"), _as("bob")
    scan, minted = _make_scan(client, alice)
    url = f"/scans/{scan['id']}/status"

    assert client.get(url, headers=alice).status_code == 200
    assert client.get(url, headers=bob).status_code == 404
    assert client.get(url).status_code == 404  # anonymous
    assert client.get(url, headers=minted).status_code == 404  # the token stopped working once an account owns it
    assert client.get("/scans/does-not-exist/status", headers=alice).status_code == 404


def test_org_admins_can_read_status_like_the_scan_itself(client):
    owner, member = _as("owner", "o@x.test"), _as("member", "m@x.test")
    client.get("/me", headers=member)
    org = client.post("/orgs", json={"name": "Cohort"}, headers=owner).json()["id"]
    client.post(f"/orgs/{org}/members", json={"email": "m@x.test"}, headers=owner)
    scan, _ = _make_scan(client, member, org_id=org)

    assert client.get(f"/scans/{scan['id']}/status", headers=owner).status_code == 200
    assert client.get(f"/scans/{scan['id']}/status", headers=_as("stranger")).status_code == 404


def test_status_never_exposes_the_owner_token_or_target(client):
    scan, token = _make_scan(client)
    text = client.get(f"/scans/{scan['id']}/status", headers=token).text
    assert token["X-Owner-Token"] not in text and TARGET not in text and "owner" not in text.lower()


def test_status_is_not_confused_with_the_scan_route(client):
    scan, token = _make_scan(client)
    full = client.get(f"/scans/{scan['id']}", headers=token).json()
    assert "findings" in full and "findings" not in client.get(f"/scans/{scan['id']}/status", headers=token).json()


# =========================== releasing connections ==========================


def test_release_returns_the_connection_but_keeps_the_response_intact(client):
    """FastAPI holds a request's session until background tasks end; releasing early keeps
    queued scans from pinning connections even if a background task is slow."""
    scan, _ = _make_scan(client)
    session = db.SessionLocal()
    row = session.get(db.Scan, scan["id"])
    assert db.engine.pool.checkedout() == 1  # the session really holds one

    response = main._release(session, row)

    assert db.engine.pool.checkedout() == 0  # handed back
    assert isinstance(response, schemas.ScanResponse)
    assert response.id == scan["id"] and len(response.findings) == 1  # findings were loaded before closing
    assert response.findings[0].label == "Row-Level Security not enabled"


def test_status_releases_its_connection_before_returning(client, monkeypatch):
    scan, token = _make_scan(client)
    seen = []
    original = main.get_scan_or_404

    def spy(session, scan_id, actor, **kw):
        result = original(session, scan_id, actor, **kw)
        seen.append(db.engine.pool.checkedout())  # while the route holds its session
        return result

    monkeypatch.setattr(main, "get_scan_or_404", spy)
    assert client.get(f"/scans/{scan['id']}/status", headers=token).status_code == 200
    assert seen and seen[0] >= 1
    assert db.engine.pool.checkedout() == 0

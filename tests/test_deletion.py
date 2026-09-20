"""Deleting scans, accounts and organizations, and the retention sweep."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend import auth, db, deletion, jobs, limits, main
from backend.db import Base, engine
from test_accounts import REPO, _add_sub, _as, _FakeJwks, _make_scan, _scan_for, _user_id


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    for var in ("ENFORCE_PLAN_LIMITS", "DAILY_SCAN_CAP", "ANON_SCAN_RETENTION_DAYS", "SCAN_WORKER_MODE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    monkeypatch.setattr(main, "run_full_scan", lambda target, **kw: _scan_for(target))
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


def _count(model, **filters):
    with db.SessionLocal() as s:
        return s.query(model).filter_by(**filters).count()


def _org_with_member(client):
    owner, member = _as("owner", "owner@x.test"), _as("member", "member@x.test")
    client.get("/me", headers=member)
    org = client.post("/orgs", json={"name": "Cohort"}, headers=owner).json()
    client.post(f"/orgs/{org['id']}/members", json={"email": "member@x.test"}, headers=owner)
    return owner, member, org


# ================================= scans ====================================


def test_owner_can_delete_a_scan_and_everything_hanging_off_it(client):
    scan, token = _make_scan(client)
    assert _count(db.Finding, scan_id=scan["id"]) == 1
    assert _count(db.ScanJob, scan_id=scan["id"]) == 1

    assert client.delete(f"/scans/{scan['id']}", headers=token).status_code == 204

    assert client.get(f"/scans/{scan['id']}", headers=token).status_code == 404
    assert client.get(f"/badge/{scan['id']}.svg").status_code == 404
    assert client.get("/scans", headers=token).json() == []
    assert _count(db.Scan) == 0 and _count(db.Finding) == 0 and _count(db.ScanJob) == 0


def test_only_the_owner_can_delete_a_scan(client):
    owner, member, org = _org_with_member(client)
    scan, _ = _make_scan(client, member, org_id=org["id"])

    assert client.delete(f"/scans/{scan['id']}", headers=_as("stranger")).status_code == 404
    assert client.delete(f"/scans/{scan['id']}", headers=owner).status_code == 404  # org admin: read-only
    assert client.delete(f"/scans/{scan['id']}").status_code == 404  # anonymous
    assert client.delete(f"/scans/{scan['id']}", headers=member).status_code == 204


def test_a_running_scan_cannot_be_deleted(client):
    scan, token = _make_scan(client)
    with db.SessionLocal() as s:
        s.get(db.Scan, scan["id"]).status = "running"
        s.commit()
    assert client.delete(f"/scans/{scan['id']}", headers=token).status_code == 409
    assert _count(db.Scan) == 1


def test_deleting_scans_does_not_reset_the_monthly_limit(client, monkeypatch):
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    alice = _as("alice")
    ids = []
    for _ in range(5):
        resp = client.post("/scans", json={"target": REPO}, headers=alice)
        assert resp.status_code == 202
        ids.append(resp.json()["id"])
    assert client.post("/scans", json={"target": REPO}, headers=alice).status_code == 402

    for scan_id in ids:
        assert client.delete(f"/scans/{scan_id}", headers=alice).status_code == 204

    assert client.get("/me", headers=alice).json()["usage"]["scans_this_month"] == 5
    assert client.post("/scans", json={"target": REPO}, headers=alice).status_code == 402


def test_anonymous_usage_survives_deletion_too(client, monkeypatch):
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    scan, token = _make_scan(client)
    client.delete(f"/scans/{scan['id']}", headers=token)
    assert client.get("/me", headers=token).json()["usage"]["scans_this_month"] == 1


def test_usage_records_keep_no_reference_to_a_deleted_scan(client):
    scan, token = _make_scan(client)
    client.delete(f"/scans/{scan['id']}", headers=token)
    with db.SessionLocal() as s:
        run = s.query(db.ScanRun).one()
    assert run.scan_id is None and run.owner_token == token["X-Owner-Token"]


def test_claiming_scans_moves_their_usage_records_to_the_account(client):
    _, anon = _make_scan(client)
    alice = _as("alice")
    client.post("/me/claim", headers={**alice, **anon})
    assert client.get("/me", headers=alice).json()["usage"]["scans_this_month"] == 1
    assert client.get("/me", headers=anon).json()["usage"]["scans_this_month"] == 0


# ================================ accounts ==================================


def test_delete_account_requires_sign_in(client):
    assert client.delete("/me").status_code == 401


def test_deleting_an_account_removes_the_user_and_their_scans(client):
    alice = _as("alice", "alice@x.test")
    _make_scan(client, alice, target="https://github.com/example/one")
    _make_scan(client, alice, target="https://github.com/example/two")
    bob_scan, _ = _make_scan(client, _as("bob"), target="https://github.com/example/bobs")
    uid = _user_id(client, alice)

    assert client.delete("/me", headers=alice).status_code == 204

    assert _count(db.User, id=uid) == 0
    assert _count(db.Scan, owner_user_id=uid) == 0
    assert _count(db.Scan) == 1 and _count(db.Finding) == 1  # only bob's scan is left
    assert client.get(f"/scans/{bob_scan['id']}", headers=_as("bob")).status_code == 200


def test_account_deletion_anonymizes_usage_but_keeps_the_daily_cap_honest(client, monkeypatch):
    monkeypatch.setenv("DAILY_SCAN_CAP", "2")
    alice = _as("alice")
    for _ in range(2):
        client.post("/scans", json={"target": REPO}, headers=alice)
    client.delete("/me", headers=alice)

    with db.SessionLocal() as s:
        runs = s.query(db.ScanRun).all()
    assert len(runs) == 2
    assert all(r.owner_user_id is None and r.owner_token is None and r.scan_id is None for r in runs)
    assert client.post("/scans", json={"target": REPO}).status_code == 503  # cap still counts them


def test_a_deleted_user_can_sign_up_again_as_a_fresh_account(client):
    alice = _as("alice", "alice@x.test")
    old_id = _user_id(client, alice)
    _make_scan(client, alice)
    client.delete("/me", headers=alice)

    fresh = client.get("/me", headers=alice).json()
    assert fresh["user"]["id"] != old_id
    assert client.get("/scans", headers=alice).json() == []


def test_account_deletion_is_blocked_by_an_active_subscription(client):
    alice = _as("alice")
    with db.SessionLocal() as s:
        _add_sub(s, user_id=_user_id(client, alice), plan="pro")

    resp = client.delete("/me", headers=alice)
    assert resp.status_code == 409 and "subscription" in resp.json()["detail"]
    assert client.get("/me", headers=alice).json()["user"] is not None  # nothing was removed


def test_account_deletion_proceeds_once_the_subscription_has_ended(client):
    alice = _as("alice")
    uid = _user_id(client, alice)
    with db.SessionLocal() as s:
        _add_sub(s, user_id=uid, plan="pro", status="expired")
    assert client.delete("/me", headers=alice).status_code == 204
    assert _count(db.Subscription) == 0


def test_account_deletion_is_blocked_while_a_scan_is_running(client):
    alice = _as("alice")
    scan, _ = _make_scan(client, alice)
    with db.SessionLocal() as s:
        s.get(db.Scan, scan["id"]).status = "queued"
        s.commit()
    assert client.delete("/me", headers=alice).status_code == 409
    assert _count(db.Scan) == 1


def test_owner_of_an_org_with_members_cannot_delete_their_account(client):
    owner, _, org = _org_with_member(client)
    resp = client.delete("/me", headers=owner)
    assert resp.status_code == 409 and "still has other members" in resp.json()["detail"]
    assert _count(db.Organization, id=org["id"]) == 1


def test_deleting_an_account_also_removes_a_solo_org_and_leaves_memberships(client):
    solo = _as("solo", "solo@x.test")
    client.post("/orgs", json={"name": "Solo"}, headers=solo)
    org_owner, member, org = _org_with_member(client)  # "member" also belongs to Cohort, owned by someone else
    assert _count(db.Organization) == 2

    assert client.delete("/me", headers=member).status_code == 204
    assert client.delete("/me", headers=solo).status_code == 204

    assert _count(db.Organization, name="Solo") == 0  # a solo-owned org goes with its owner
    cohort = client.get("/orgs", headers=org_owner).json()
    assert cohort[0]["name"] == "Cohort" and cohort[0]["member_count"] == 1  # the member left with the account


def test_deleting_a_member_leaves_no_dangling_org_reference(client):
    owner, member, org = _org_with_member(client)
    _make_scan(client, member, org_id=org["id"])
    client.delete("/me", headers=member)
    dash = client.get(f"/orgs/{org['id']}/dashboard", headers=owner).json()
    assert dash["summary"]["projects"] == 0


# ============================= organizations ================================


def test_org_deletion_permissions(client):
    owner, member, org = _org_with_member(client)
    url = f"/orgs/{org['id']}"
    assert client.delete(url, headers=member).status_code == 403
    assert client.delete(url, headers=_as("stranger")).status_code == 404
    assert client.delete(url).status_code == 401
    assert client.delete(url, headers=owner).status_code == 204
    assert _count(db.Organization) == 0 and _count(db.Membership) == 0


def test_deleting_an_org_keeps_members_scans_but_detaches_them(client):
    owner, member, org = _org_with_member(client)
    scan, _ = _make_scan(client, member, org_id=org["id"])
    client.delete(f"/orgs/{org['id']}", headers=owner)

    got = client.get(f"/scans/{scan['id']}", headers=member)
    assert got.status_code == 200
    assert client.get(f"/scans/{scan['id']}", headers=owner).status_code == 404  # no longer admin-visible


def test_org_with_an_active_team_subscription_cannot_be_deleted(client):
    owner, _, org = _org_with_member(client)
    with db.SessionLocal() as s:
        _add_sub(s, org_id=org["id"], plan="team")
    resp = client.delete(f"/orgs/{org['id']}", headers=owner)
    assert resp.status_code == 409 and "Team subscription" in resp.json()["detail"]
    assert _count(db.Organization) == 1


# =============================== retention ==================================


def _age(scan_id, days):
    with db.SessionLocal() as s:
        s.get(db.Scan, scan_id).created_at = datetime.now(timezone.utc) - timedelta(days=days)
        s.commit()


def test_retention_sweep_deletes_only_old_finished_anonymous_scans(client):
    old_anon, _ = _make_scan(client, target="https://github.com/example/old")
    fresh_anon, _ = _make_scan(client, target="https://github.com/example/fresh")
    old_running, _ = _make_scan(client, target="https://github.com/example/running")
    old_owned, _ = _make_scan(client, _as("alice"), target="https://github.com/example/owned")
    for scan in (old_anon, old_running, old_owned):
        _age(scan["id"], 90)
    with db.SessionLocal() as s:
        s.get(db.Scan, old_running["id"]).status = "running"
        s.commit()

    with db.SessionLocal() as s:
        assert deletion.purge_expired_anonymous_scans(s, days=30) == 1

    with db.SessionLocal() as s:
        remaining = {r.id for r in s.query(db.Scan).all()}
    assert remaining == {fresh_anon["id"], old_running["id"], old_owned["id"]}
    assert _count(db.Finding, scan_id=old_anon["id"]) == 0


def test_retention_is_off_by_default_and_when_days_is_zero(client):
    scan, _ = _make_scan(client)
    _age(scan["id"], 3650)
    with db.SessionLocal() as s:
        assert deletion.purge_expired_anonymous_scans(s, days=0) == 0
    assert _count(db.Scan) == 1


def test_housekeeping_applies_the_configured_retention(client, monkeypatch):
    old, _ = _make_scan(client, target="https://github.com/example/old")
    _age(old["id"], 90)

    jobs._housekeeping()  # ANON_SCAN_RETENTION_DAYS unset
    assert _count(db.Scan) == 1

    monkeypatch.setenv("ANON_SCAN_RETENTION_DAYS", "30")
    jobs._housekeeping()
    assert _count(db.Scan) == 0

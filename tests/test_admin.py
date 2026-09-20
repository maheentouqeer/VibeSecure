"""Admin API: access control, blindness to user code, complimentary plans, audit log."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend import auth, db, limits, main
from backend.db import Base, engine
from test_accounts import REPO, _add_sub, _as, _FakeJwks, _make_scan, _scan_for, _user_id

KEY = "k" * 32
H = {"X-Admin-Key": KEY}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    for var in ("ENFORCE_PLAN_LIMITS", "DAILY_SCAN_CAP", "ADMIN_FAIL_LIMIT_PER_HOUR", "ADMIN_RATE_LIMIT_PER_HOUR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    monkeypatch.setenv("ADMIN_API_KEY", KEY)
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    monkeypatch.setattr(main, "run_full_scan", lambda target, **kw: _scan_for(target))
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


ENDPOINTS = [
    ("get", "/admin/stats"),
    ("get", "/admin/users"),
    ("get", "/admin/audit"),
    ("post", "/admin/users/x/plan"),
    ("post", "/admin/orgs/x/plan"),
    ("delete", "/admin/subscriptions/x"),
]


def _call(client, method, path, headers=None, **kw):
    if method != "post":
        kw.pop("json", None)  # only POST carries a body here
    return getattr(client, method)(path, headers=headers, **kw)


# ============================== access control ==============================


@pytest.mark.parametrize("method, path", ENDPOINTS)
def test_disabled_without_a_key(client, monkeypatch, method, path):
    monkeypatch.delenv("ADMIN_API_KEY")
    assert _call(client, method, path, H, json={"days": 1}).status_code == 503


@pytest.mark.parametrize("weak", ["", "short", "x" * 23])
def test_a_weak_key_counts_as_unconfigured(client, monkeypatch, weak):
    monkeypatch.setenv("ADMIN_API_KEY", weak)
    assert client.get("/admin/stats", headers={"X-Admin-Key": weak}).status_code == 503


@pytest.mark.parametrize("method, path", ENDPOINTS)
def test_missing_or_wrong_key_is_401(client, method, path):
    assert _call(client, method, path, json={"days": 1}).status_code == 401
    assert _call(client, method, path, {"X-Admin-Key": KEY[:-1] + "X"}, json={"days": 1}).status_code == 401
    assert _call(client, method, path, {"X-Admin-Key": KEY + "x"}, json={"days": 1}).status_code == 401


def test_a_signed_in_users_token_is_not_an_admin_credential(client):
    assert client.get("/admin/stats", headers=_as("alice")).status_code == 401


def test_repeated_wrong_keys_lock_the_ip_out_even_for_the_right_key(client, monkeypatch):
    monkeypatch.setenv("ADMIN_FAIL_LIMIT_PER_HOUR", "3")
    for _ in range(3):
        assert client.get("/admin/stats", headers={"X-Admin-Key": "wrong" * 8}).status_code == 401

    locked = client.get("/admin/stats", headers=H)
    assert locked.status_code == 429 and "Retry-After" in locked.headers
    assert client.get("/admin/stats", headers={**H, "X-Forwarded-For": "7.7.7.7"}).status_code == 200  # another IP


def test_correct_keys_never_count_as_failures(client, monkeypatch):
    monkeypatch.setenv("ADMIN_FAIL_LIMIT_PER_HOUR", "2")
    assert all(client.get("/admin/stats", headers=H).status_code == 200 for _ in range(6))


def test_the_admin_api_is_rate_limited_too(client, monkeypatch):
    monkeypatch.setenv("ADMIN_RATE_LIMIT_PER_HOUR", "3")
    assert [client.get("/admin/stats", headers=H).status_code for _ in range(4)] == [200, 200, 200, 429]


# ==================================== stats =================================


def test_stats_counts_everything_without_exposing_content(client, monkeypatch):
    monkeypatch.setenv("DAILY_SCAN_CAP", "50")
    alice, bob = _as("alice", "alice@x.test"), _as("bob", "bob@x.test")
    _make_scan(client, alice, target="https://github.com/secret-corp/private-app")
    _make_scan(client, alice)
    _make_scan(client, bob)
    org = client.post("/orgs", json={"name": "Cohort"}, headers=alice).json()
    with db.SessionLocal() as s:
        _add_sub(s, user_id=_user_id(client, alice), plan="pro")
        _add_sub(s, org_id=org["id"], plan="team")
        _add_sub(s, user_id=_user_id(client, bob), plan="pro", status="expired")  # not active: not counted

    resp = client.get("/admin/stats", headers=H)
    body = resp.json()

    assert body["users"] == {"total": 2, "new_7d": 2}
    assert body["organizations"] == 1
    assert body["scans"] == {"total": 3, "last_24h": 3, "failed_24h": 0}
    assert body["usage_today"] == {"runs": 3, "daily_cap": 50, "remaining": 47}
    assert body["active_subscriptions"] == {"pro": 1, "team": 1}
    assert body["jobs"] == {"done": 3}
    assert "secret-corp" not in resp.text and "private-app" not in resp.text


def test_stats_reports_no_cap_when_it_is_disabled(client, monkeypatch):
    monkeypatch.setenv("DAILY_SCAN_CAP", "0")
    assert client.get("/admin/stats", headers=H).json()["usage_today"] == {"runs": 0, "daily_cap": None, "remaining": None}


def test_stats_on_an_empty_database(client):
    body = client.get("/admin/stats", headers=H).json()
    assert body["users"]["total"] == 0 and body["scans"]["total"] == 0 and body["active_subscriptions"] == {}


# ==================================== users =================================


def test_find_users_by_email_fragment_and_effective_plan(client):
    for sub, email in (("a", "alice@example.test"), ("b", "bob@example.test"), ("c", "carol@other.test")):
        client.get("/me", headers=_as(sub, email))
    with db.SessionLocal() as s:
        _add_sub(s, user_id=_user_id(client, _as("a")), plan="pro")

    found = client.get("/admin/users", params={"email": "EXAMPLE"}, headers=H).json()
    assert sorted(u["email"] for u in found) == ["alice@example.test", "bob@example.test"]
    alice = next(u for u in found if u["email"].startswith("alice"))
    assert alice["plan"] == "pro" and alice["subscriptions"][0]["plan"] == "pro"
    assert next(u for u in found if u["email"].startswith("bob"))["plan"] == "free"


def test_email_search_treats_wildcards_literally(client):
    client.get("/me", headers=_as("a", "alice@example.test"))
    assert client.get("/admin/users", params={"email": "%"}, headers=H).json() == []
    assert client.get("/admin/users", params={"email": "_"}, headers=H).json() == []


def test_find_users_respects_limit_and_returns_counts_not_scans(client):
    for i in range(5):
        _make_scan(client, _as(f"user{i}", f"u{i}@x.test"), target="https://github.com/hidden/repo")
    resp = client.get("/admin/users", params={"limit": 3}, headers=H)
    assert len(resp.json()) == 3 and all(u["scans"] == 1 for u in resp.json())
    assert "hidden/repo" not in resp.text
    assert client.get("/admin/users", params={"limit": 0}, headers=H).status_code == 422
    assert client.get("/admin/users", params={"limit": 51}, headers=H).status_code == 422


def test_user_listing_never_includes_tokens(client, monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", Fernet.generate_key().decode())
    alice = _as("alice", "alice@x.test")
    uid = _user_id(client, alice)
    with db.SessionLocal() as s:
        s.add(db.GithubConnection(user_id=uid, github_login="alice-gh", encrypted_token="ENCRYPTED-BLOB"))
        s.commit()
    resp = client.get("/admin/users", headers=H)
    assert resp.json()[0]["github_connected"] is True
    assert "ENCRYPTED-BLOB" not in resp.text and "owner_token" not in resp.text


# ================================ complimentary plans =======================


def test_granting_pro_upgrades_the_user_and_expires(client):
    alice = _as("alice", "alice@x.test")
    uid = _user_id(client, alice)

    resp = client.post(f"/admin/users/{uid}/plan", json={"days": 30, "note": "beta tester"}, headers=H)
    assert resp.status_code == 201 and resp.json()["plan"] == "pro"
    assert client.get("/me", headers=alice).json()["plan"] == "pro"

    with db.SessionLocal() as s:
        sub = s.query(db.Subscription).one()
        assert (sub.provider, sub.status, sub.user_id) == ("manual", "active", uid)
        end = sub.current_period_end.replace(tzinfo=timezone.utc)
        assert timedelta(days=29) < end - datetime.now(timezone.utc) < timedelta(days=31)


def test_a_granted_plan_lifts_enforced_limits(client, monkeypatch):
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    alice = _as("alice")
    uid = _user_id(client, alice)
    client.post(f"/admin/users/{uid}/plan", json={"days": 5}, headers=H)
    assert all(client.post("/scans", json={"target": REPO}, headers=alice).status_code == 202 for _ in range(8))


def test_grant_validation(client):
    uid = _user_id(client, _as("alice"))
    for days in (0, -1, 366):
        assert client.post(f"/admin/users/{uid}/plan", json={"days": days}, headers=H).status_code == 422
    assert client.post(f"/admin/users/{uid}/plan", json={}, headers=H).status_code == 422
    assert client.post(f"/admin/users/{uid}/plan", json={"days": 5, "note": "x" * 201}, headers=H).status_code == 422
    assert client.post("/admin/users/nobody/plan", json={"days": 5}, headers=H).status_code == 404
    with db.SessionLocal() as s:
        assert s.query(db.Subscription).count() == 0


def test_granting_team_to_an_org_upgrades_its_members(client):
    owner = _as("owner", "o@x.test")
    org = client.post("/orgs", json={"name": "Cohort"}, headers=owner).json()
    assert client.post(f"/admin/orgs/{org['id']}/plan", json={"days": 10}, headers=H).status_code == 201
    assert client.get("/me", headers=owner).json()["plan"] == "team"
    assert client.post("/admin/orgs/nope/plan", json={"days": 10}, headers=H).status_code == 404


def test_ending_a_manual_plan_downgrades_immediately(client):
    alice = _as("alice")
    grant = client.post(f"/admin/users/{_user_id(client, alice)}/plan", json={"days": 30}, headers=H).json()
    assert client.get("/me", headers=alice).json()["plan"] == "pro"

    ended = client.delete(f"/admin/subscriptions/{grant['subscription_id']}", headers=H)
    assert ended.json()["status"] == "expired"
    assert client.get("/me", headers=alice).json()["plan"] == "free"
    assert client.delete("/admin/subscriptions/nope", headers=H).status_code == 404


def test_provider_subscriptions_can_never_be_ended_from_here(client):
    alice = _as("alice")
    with db.SessionLocal() as s:
        _add_sub(s, user_id=_user_id(client, alice), plan="pro", sid="whop_mem_1")
        s.query(db.Subscription).update({"provider": "whop"})
        s.commit()
        sub_id = s.query(db.Subscription).one().id

    resp = client.delete(f"/admin/subscriptions/{sub_id}", headers=H)
    assert resp.status_code == 409 and "provider" in resp.json()["detail"]
    with db.SessionLocal() as s:
        assert s.get(db.Subscription, sub_id).status == "active"
    assert client.get("/me", headers=alice).json()["plan"] == "pro"


# ==================================== audit =================================


def test_every_admin_action_is_audited_with_the_ip_but_never_the_key(client):
    alice = _as("alice", "alice@x.test")
    uid = _user_id(client, alice)
    headers = {**H, "X-Forwarded-For": "5.6.7.8"}
    client.get("/admin/stats", headers=headers)
    client.get("/admin/users", params={"email": "alice"}, headers=headers)
    grant = client.post(f"/admin/users/{uid}/plan", json={"days": 7, "note": "press"}, headers=headers).json()
    client.delete(f"/admin/subscriptions/{grant['subscription_id']}", headers=headers)

    log = client.get("/admin/audit", headers=headers).json()
    assert [e["action"] for e in log] == ["end_manual_subscription", "grant_pro", "find_users", "stats"]  # newest first
    granted = next(e for e in log if e["action"] == "grant_pro")
    assert granted["target"] == uid and "7 days" in granted["detail"] and "press" in granted["detail"]
    assert all(e["ip"] == "5.6.7.8" for e in log)
    assert KEY not in client.get("/admin/audit", headers=headers).text


def test_the_audit_log_limit_is_validated_and_applied(client):
    for _ in range(4):
        client.get("/admin/stats", headers=H)
    assert len(client.get("/admin/audit", params={"limit": 2}, headers=H).json()) == 2
    assert client.get("/admin/audit", params={"limit": 0}, headers=H).status_code == 422
    assert client.get("/admin/audit", params={"limit": 201}, headers=H).status_code == 422

"""GitHub OAuth: connecting an account, token safety, and using it for private repos."""
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from backend import auth, db, github_oauth, limits, main
from backend.db import Base, engine
from test_accounts import REPO, _add_sub, _as, _FakeJwks, _make_scan, _scan_for, _user_id

PRIVATE = "https://github.com/alice/private-app"
SECRET_TOKEN = "gho_supersecrettoken123"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    for var in ("ENFORCE_PLAN_LIMITS", "FRONTEND_URL", "GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("GITHUB_OAUTH_REDIRECT_URI", "https://api.example.test/integrations/github/callback")
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    monkeypatch.setattr(github_oauth, "_exchange_code", lambda code: (SECRET_TOKEN, "repo"))
    monkeypatch.setattr(github_oauth, "_fetch_login", lambda token: "alice-gh")
    monkeypatch.setattr(github_oauth, "_revoke", lambda token: REVOKED.append(token))
    REVOKED.clear()
    yield
    Base.metadata.drop_all(bind=engine)


REVOKED: list[str] = []


@pytest.fixture()
def client():
    return TestClient(main.app, follow_redirects=False)


def _state_for(client, headers):
    url = client.get("/integrations/github/authorize", headers=headers).json()["url"]
    return parse_qs(urlparse(url).query)["state"][0]


def _connect(client, headers, code="abc"):
    return client.get("/integrations/github/callback", params={"code": code, "state": _state_for(client, headers)})


# ================================ configuration ==============================


def test_status_reports_unconfigured_and_anonymous_users(client, monkeypatch):
    assert client.get("/integrations/github").json() == {"configured": True, "connected": False, "login": None}
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_SECRET")
    assert client.get("/integrations/github").json()["configured"] is False


@pytest.mark.parametrize("missing", ["GITHUB_OAUTH_CLIENT_ID", "GITHUB_OAUTH_CLIENT_SECRET", "GITHUB_OAUTH_REDIRECT_URI", "TOKEN_ENCRYPTION_KEY"])
def test_every_setting_is_required(client, monkeypatch, missing):
    monkeypatch.delenv(missing)
    assert client.get("/integrations/github/authorize", headers=_as("alice")).status_code == 503
    assert client.get("/integrations/github/callback", params={"code": "x", "state": "y"}).status_code == 503


def test_an_invalid_encryption_key_counts_as_unconfigured(client, monkeypatch):
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", "not-a-fernet-key")
    assert client.get("/integrations/github").json()["configured"] is False
    assert client.get("/integrations/github/authorize", headers=_as("alice")).status_code == 503


# ================================== authorize ================================


def test_authorize_requires_sign_in(client):
    assert client.get("/integrations/github/authorize").status_code == 401


def test_authorize_url_points_at_github_with_the_right_parameters(client):
    url = client.get("/integrations/github/authorize", headers=_as("alice")).json()["url"]
    parsed = urlparse(url)
    q = parse_qs(parsed.query)

    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://github.com/login/oauth/authorize"
    assert q["client_id"] == ["cid"] and q["scope"] == ["repo"]
    assert q["redirect_uri"] == ["https://api.example.test/integrations/github/callback"]
    assert "csecret" not in url  # the client secret never leaves the server


# ================================== callback =================================


def test_callback_stores_the_connection_with_an_encrypted_token(client):
    alice = _as("alice", "a@x.test")
    resp = _connect(client, alice)

    assert resp.status_code == 200 and resp.json() == {"github": "connected"}
    with db.SessionLocal() as s:
        conn = s.query(db.GithubConnection).one()
    assert conn.github_login == "alice-gh" and conn.scope == "repo"
    assert SECRET_TOKEN not in conn.encrypted_token  # never plaintext at rest
    assert github_oauth.decrypt_token(conn.encrypted_token) == SECRET_TOKEN
    assert client.get("/integrations/github", headers=alice).json() == {
        "configured": True, "connected": True, "login": "alice-gh",
    }


def test_reconnecting_replaces_the_token_instead_of_adding_a_row(client, monkeypatch):
    alice = _as("alice")
    _connect(client, alice)
    monkeypatch.setattr(github_oauth, "_exchange_code", lambda code: ("gho_newer", "repo"))
    monkeypatch.setattr(github_oauth, "_fetch_login", lambda token: "alice-renamed")
    _connect(client, alice)

    with db.SessionLocal() as s:
        conn = s.query(db.GithubConnection).one()
    assert conn.github_login == "alice-renamed"
    assert github_oauth.decrypt_token(conn.encrypted_token) == "gho_newer"


def test_callback_redirects_the_browser_to_the_frontend_when_configured(client, monkeypatch):
    monkeypatch.setenv("FRONTEND_URL", "https://app.example.test/")
    resp = _connect(client, _as("alice"))
    assert resp.status_code == 302 and resp.headers["location"] == "https://app.example.test?github=connected"


def test_user_denying_access_is_reported_and_stores_nothing(client, monkeypatch):
    monkeypatch.setenv("FRONTEND_URL", "https://app.example.test")
    state = _state_for(client, _as("alice"))
    resp = client.get("/integrations/github/callback", params={"error": "access_denied", "state": state})
    assert resp.headers["location"].endswith("?github=denied")
    with db.SessionLocal() as s:
        assert s.query(db.GithubConnection).count() == 0


def test_github_failures_do_not_store_anything_or_leak_details(client, monkeypatch):
    def broken(code):
        raise ValueError("bad_verification_code: secret internal detail")

    monkeypatch.setattr(github_oauth, "_exchange_code", broken)
    resp = _connect(client, _as("alice"))
    assert resp.json() == {"github": "error"} and "secret internal detail" not in resp.text
    with db.SessionLocal() as s:
        assert s.query(db.GithubConnection).count() == 0


@pytest.mark.parametrize("bad_state", ["", "garbage", "a.b.c"])
def test_malformed_state_is_rejected(client, bad_state):
    resp = client.get("/integrations/github/callback", params={"code": "x", "state": bad_state})
    assert resp.status_code in (400, 422)


def test_tampered_state_is_rejected(client):
    state = _state_for(client, _as("alice"))
    forged = jwt.encode({"sub": "someone-else", "exp": int(time.time()) + 600}, "wrong-secret", algorithm="HS256")
    for bad in (state[:-4] + "AAAA", forged):
        assert client.get("/integrations/github/callback", params={"code": "x", "state": bad}).status_code == 400
    with db.SessionLocal() as s:
        assert s.query(db.GithubConnection).count() == 0


def test_expired_state_is_rejected(client):
    _as("alice")
    client.get("/me", headers=_as("alice"))
    uid = _user_id(client, _as("alice"))
    expired = jwt.encode({"sub": uid, "exp": int(time.time()) - 5}, github_oauth._state_secret(), algorithm="HS256")
    assert client.get("/integrations/github/callback", params={"code": "x", "state": expired}).status_code == 400


def test_state_for_a_deleted_user_is_rejected(client):
    alice = _as("alice")
    state = _state_for(client, alice)
    client.delete("/me", headers=alice)
    assert client.get("/integrations/github/callback", params={"code": "x", "state": state}).status_code == 400


def test_a_state_can_only_attach_github_to_the_user_who_started_the_flow(client):
    alice, mallory = _as("alice"), _as("mallory")
    client.get("/me", headers=mallory)
    alice_state = _state_for(client, alice)
    client.get("/integrations/github/callback", params={"code": "x", "state": alice_state})

    with db.SessionLocal() as s:
        conn = s.query(db.GithubConnection).one()
    assert conn.user_id == _user_id(client, alice)
    assert client.get("/integrations/github", headers=mallory).json()["connected"] is False


# ================================= disconnect ================================


def test_disconnect_deletes_the_token_and_revokes_the_grant(client):
    alice = _as("alice")
    _connect(client, alice)
    assert client.delete("/integrations/github", headers=alice).status_code == 204

    with db.SessionLocal() as s:
        assert s.query(db.GithubConnection).count() == 0
    assert REVOKED == [SECRET_TOKEN]
    assert client.get("/integrations/github", headers=alice).json()["connected"] is False


def test_disconnect_when_not_connected_is_a_harmless_no_op(client):
    assert client.delete("/integrations/github", headers=_as("alice")).status_code == 204
    assert client.delete("/integrations/github").status_code == 401
    assert REVOKED == []


def test_deleting_the_account_removes_and_revokes_the_connection(client):
    alice = _as("alice")
    _connect(client, alice)
    assert client.delete("/me", headers=alice).status_code == 204
    with db.SessionLocal() as s:
        assert s.query(db.GithubConnection).count() == 0
    assert REVOKED == [SECRET_TOKEN]


def test_unreadable_stored_tokens_are_simply_not_used(client, monkeypatch):
    alice = _as("alice")
    _connect(client, alice)
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", Fernet.generate_key().decode())  # key rotated without re-encrypting
    with db.SessionLocal() as s:
        scan = db.Scan(target=PRIVATE, owner_token="t", owner_user_id=_user_id(client, alice))
        s.add(scan)
        s.commit()
        assert github_oauth.token_for_scan(s, scan) is None


# =========================== using the token in scans ========================


@pytest.fixture()
def seen(monkeypatch):
    calls = []

    def fake(target, **kw):
        calls.append({"target": target, **kw})
        return _scan_for(target)

    monkeypatch.setattr(main, "run_full_scan", fake)
    return calls


def test_scans_use_the_owners_own_token_for_github_repos(client, seen):
    alice = _as("alice")
    _connect(client, alice)
    _make_scan(client, alice, target=PRIVATE)
    assert seen[-1] == {"target": PRIVATE, "github_token": SECRET_TOKEN}


def test_no_token_is_passed_when_nothing_is_connected_or_the_user_is_anonymous(client, seen):
    _make_scan(client, _as("alice"), target=PRIVATE)  # signed in, not connected
    _make_scan(client, target=PRIVATE)  # anonymous
    assert all("github_token" not in call for call in seen)


def test_the_token_is_never_used_for_other_hosts(client, seen):
    alice = _as("alice")
    _connect(client, alice)
    for target in ("https://gitlab.com/alice/x", "https://evil.example/github.com/alice/x.git", "https://example.com"):
        _make_scan(client, alice, target=target)
    assert all("github_token" not in call for call in seen)


def test_one_users_token_is_never_used_for_another_users_scan(client, seen):
    _connect(client, _as("alice"))
    _make_scan(client, _as("bob"), target=PRIVATE)
    assert "github_token" not in seen[-1]


def test_private_repos_are_a_paid_feature_when_plans_are_enforced(client, seen, monkeypatch):
    alice = _as("alice")
    _connect(client, alice)
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")

    _make_scan(client, alice, target=PRIVATE)
    assert "github_token" not in seen[-1]  # free plan: the token is not used

    with db.SessionLocal() as s:
        _add_sub(s, user_id=_user_id(client, alice), plan="pro")
    _make_scan(client, alice, target=PRIVATE)
    assert seen[-1]["github_token"] == SECRET_TOKEN


def test_rescans_use_the_token_too(client, seen):
    alice = _as("alice")
    _connect(client, alice)
    scan, _ = _make_scan(client, alice, target=PRIVATE)
    client.post(f"/scans/{scan['id']}/rescan", headers=alice)
    assert seen[-1]["github_token"] == SECRET_TOKEN


def test_an_auth_failure_with_a_token_points_the_user_at_reconnecting(client, monkeypatch):
    alice = _as("alice")
    _connect(client, alice)

    def denied(target, **kw):
        raise RuntimeError("Unable to clone repository: Authentication failed for 'https://github.com/alice/private-app'")

    monkeypatch.setattr(main, "run_full_scan", denied)
    scan, _ = _make_scan(client, alice, target=PRIVATE)
    assert scan["status"] == "failed" and "reconnect GitHub" in scan["error"]


def test_an_auth_failure_without_a_token_gets_no_misleading_hint(client, monkeypatch):
    def denied(target, **kw):
        raise RuntimeError("Unable to clone repository: Authentication failed")

    monkeypatch.setattr(main, "run_full_scan", denied)
    scan, _ = _make_scan(client, _as("alice"), target=PRIVATE)
    assert "reconnect" not in scan["error"]


def test_the_token_is_never_included_in_any_api_response(client, seen):
    alice = _as("alice")
    _connect(client, alice)
    scan, _ = _make_scan(client, alice, target=PRIVATE)
    for path in ("/integrations/github", "/me", "/scans", f"/scans/{scan['id']}"):
        assert SECRET_TOKEN not in client.get(path, headers=alice).text

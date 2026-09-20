"""Accounts layer: Clerk JWT verification, ownership/claiming, plans and
metering, organizations and the organizer dashboard, and the billing webhook.

Tokens are real RS256 JWTs signed with a key generated per test session; only
the JWKS network fetch is replaced (by a client that returns that key)."""
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from backend import auth, db, limits, main
from backend.db import Base, engine

ISSUER = "https://clerk.example.test"
REPO = "https://github.com/example/app"
BILLING_SECRET = "bill-secret"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
)
_OTHER_PEM = _OTHER_KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
)

BAD_FINDING = {
    "category": "missing_access_control",
    "label": "Row-Level Security not enabled",
    "file": "supabase migrations",
    "severity": "critical",
    "what_it_means": "x",
    "why_it_matters": "y",
    "fix_prompt": "z",
}


class _FakeKey:
    key = _KEY.public_key()


class _FakeJwks:
    def get_signing_key_from_jwt(self, token):
        return _FakeKey()


def _scan_for(target, **kw):
    findings = [] if "clean" in target else [dict(BAD_FINDING)]
    return {"target": target, "platform": "generic", "findings": findings, "commit_sha": None, "unchanged": False}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    for var in (
        "CLERK_ISSUER", "CLERK_AUTHORIZED_PARTIES", "ENFORCE_PLAN_LIMITS",
        "DAILY_SCAN_CAP", "GITHUB_WEBHOOK_SECRET", "BILLING_WEBHOOK_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    monkeypatch.setattr(main, "run_full_scan", lambda target, **kw: _scan_for(target))
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


def _jwt(sub="user_1", email=None, pem=_PEM, exp_in=300, **claims):
    payload = {"sub": sub, "exp": int(time.time()) + exp_in, "iat": int(time.time()), **claims}
    if email:
        payload["email"] = email
    return jwt.encode(payload, pem, algorithm="RS256")


def _as(sub="user_1", email=None, **kw):
    return {"Authorization": f"Bearer {_jwt(sub, email, **kw)}"}


def _make_scan(client, headers=None, target=REPO, **body):
    """Create a scan and return (finished_scan_json, response_headers)."""
    headers = headers or {}
    resp = client.post("/scans", json={"target": target, **body}, headers=headers)
    assert resp.status_code == 202, resp.text
    token = resp.headers["X-Owner-Token"]
    got = client.get(f"/scans/{resp.json()['id']}", headers={**headers, "X-Owner-Token": token})
    return got.json(), {"X-Owner-Token": token}


def _user_id(client, headers):
    return client.get("/me", headers=headers).json()["user"]["id"]


def _add_sub(session, *, user_id=None, org_id=None, plan="pro", status="active", period_end=None, sid=None):
    session.add(
        db.Subscription(
            user_id=user_id, org_id=org_id, provider="test", plan=plan, status=status,
            provider_subscription_id=sid or f"sub_{uuid.uuid4().hex}", current_period_end=period_end,
        )
    )
    session.commit()


# ============================ token verification ============================


def test_anonymous_requests_still_work_without_any_auth_config(client, monkeypatch):
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: None)
    scan, _ = _make_scan(client)
    assert scan["status"] == "completed"
    me = client.get("/me").json()
    assert me["user"] is None and me["plan"] == "free"


def test_bearer_token_when_signin_is_not_configured_returns_503(client, monkeypatch):
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: None)
    assert client.get("/me", headers=_as()).status_code == 503


def test_valid_token_creates_user_and_reports_identity(client):
    me = client.get("/me", headers=_as("user_abc", "a@x.test")).json()
    assert me["user"]["email"] == "a@x.test"
    assert me["plan"] == "free"
    assert me["limits"] == {"monthly_scans": 5, "auto_rescan": False}


def test_same_clerk_user_maps_to_one_row_and_email_updates(client):
    client.get("/me", headers=_as("user_abc", "old@x.test"))
    client.get("/me", headers=_as("user_abc", "new@x.test"))
    with db.SessionLocal() as s:
        users = s.query(db.User).all()
    assert len(users) == 1 and users[0].email == "new@x.test"


@pytest.mark.parametrize(
    "header",
    [
        {"Authorization": "Bearer not-a-jwt"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer "},
        {"Authorization": "garbage"},
    ],
)
def test_malformed_authorization_headers_are_rejected(client, header):
    assert client.get("/me", headers=header).status_code == 401


def test_expired_token_is_rejected(client):
    assert client.get("/me", headers=_as(exp_in=-60)).status_code == 401


def test_token_signed_with_a_different_key_is_rejected(client):
    bad = {"Authorization": f"Bearer {_jwt(pem=_OTHER_PEM)}"}
    assert client.get("/me", headers=bad).status_code == 401


def test_token_without_subject_is_rejected(client):
    token = jwt.encode({"exp": int(time.time()) + 60}, _PEM, algorithm="RS256")
    assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_unsigned_alg_none_token_is_rejected(client):
    token = jwt.encode({"sub": "u", "exp": int(time.time()) + 60}, None, algorithm="none")
    assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_issuer_is_enforced_when_configured(client, monkeypatch):
    monkeypatch.setenv("CLERK_ISSUER", ISSUER)
    assert client.get("/me", headers=_as(iss=ISSUER)).status_code == 200
    assert client.get("/me", headers=_as(iss="https://evil.test")).status_code == 401
    assert client.get("/me", headers=_as()).status_code == 401  # no iss at all


def test_authorized_parties_are_enforced_when_configured(client, monkeypatch):
    monkeypatch.setenv("CLERK_AUTHORIZED_PARTIES", "https://app.example.test, http://localhost:3000")
    assert client.get("/me", headers=_as(azp="http://localhost:3000")).status_code == 200
    assert client.get("/me", headers=_as(azp="https://evil.test")).status_code == 401
    assert client.get("/me", headers=_as()).status_code == 401


def test_unknown_signing_key_is_401_and_unreachable_provider_is_503(client, monkeypatch):
    class Unknown:
        def get_signing_key_from_jwt(self, token):
            raise PyJWKClientError("no such kid")

    class Down:
        def get_signing_key_from_jwt(self, token):
            raise PyJWKClientConnectionError("network down")

    monkeypatch.setattr(auth, "_get_jwks_client", lambda: Unknown())
    assert client.get("/me", headers=_as()).status_code == 401
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: Down())
    assert client.get("/me", headers=_as()).status_code == 503


def test_invalid_token_is_never_downgraded_to_anonymous(client):
    _, token_header = _make_scan(client)  # a perfectly valid anonymous scan exists
    resp = client.get("/scans", headers={**token_header, "Authorization": "Bearer bogus"})
    assert resp.status_code == 401


# ============================ ownership & claiming ==========================


def test_scan_created_while_signed_in_belongs_to_the_user_only(client):
    alice, bob = _as("alice", "a@x.test"), _as("bob", "b@x.test")
    scan, minted = _make_scan(client, alice)

    assert client.get(f"/scans/{scan['id']}", headers=alice).status_code == 200
    assert client.get(f"/scans/{scan['id']}", headers=bob).status_code == 404
    # the anonymous token minted for it must not be a back door
    assert client.get(f"/scans/{scan['id']}", headers=minted).status_code == 404
    assert client.post(f"/scans/{scan['id']}/rescan", headers=bob).status_code == 404


def test_signed_in_user_sees_own_scans_across_devices(client):
    alice = _as("alice")
    _make_scan(client, alice, target="https://github.com/example/one")
    _make_scan(client, alice, target="https://github.com/example/two")  # different token each time
    _make_scan(client, _as("bob"), target="https://github.com/example/bobs")

    targets = sorted(s["target"] for s in client.get("/scans", headers=alice).json())
    assert targets == ["https://github.com/example/one", "https://github.com/example/two"]


def test_claiming_moves_anonymous_scans_into_the_account(client):
    scan, anon = _make_scan(client)
    alice = _as("alice")

    assert client.post("/me/claim", headers={**alice, **anon}).json() == {"claimed": 1}

    assert client.get(f"/scans/{scan['id']}", headers=alice).status_code == 200
    assert [s["id"] for s in client.get("/scans", headers=alice).json()] == [scan["id"]]
    # the old browser token no longer grants access, and claiming is idempotent
    assert client.get(f"/scans/{scan['id']}", headers=anon).status_code == 404
    assert client.post("/me/claim", headers={**alice, **anon}).json() == {"claimed": 0}
    # another account can't steal an already-claimed scan with the same token
    assert client.post("/me/claim", headers={**_as("mallory"), **anon}).json() == {"claimed": 0}


def test_claim_requires_sign_in_and_handles_missing_token(client):
    assert client.post("/me/claim").status_code == 401
    assert client.post("/me/claim", headers=_as("alice")).json() == {"claimed": 0}


def test_list_includes_unclaimed_token_scans_for_a_signed_in_user(client):
    scan, anon = _make_scan(client)
    listed = client.get("/scans", headers={**_as("alice"), **anon}).json()
    assert [s["id"] for s in listed] == [scan["id"]]


# ================================ plans & usage =============================


def test_limits_are_not_enforced_by_default(client):
    for _ in range(7):
        assert client.post("/scans", json={"target": REPO}).status_code == 202


def test_free_plan_blocks_the_sixth_scan_when_enforced(client, monkeypatch):
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    alice = _as("alice")
    for _ in range(5):
        assert client.post("/scans", json={"target": REPO}, headers=alice).status_code == 202

    blocked = client.post("/scans", json={"target": REPO}, headers=alice)
    assert blocked.status_code == 402 and "free plan" in blocked.json()["detail"]

    me = client.get("/me", headers=alice).json()
    assert me["usage"]["scans_this_month"] == 5 and me["enforced"] is True


def test_anonymous_users_are_metered_by_their_token(client, monkeypatch):
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    _, anon = _make_scan(client)
    for _ in range(4):
        assert client.post("/scans", json={"target": REPO}, headers=anon).status_code == 202
    assert client.post("/scans", json={"target": REPO}, headers=anon).status_code == 402
    # a different anonymous visitor is unaffected
    assert client.post("/scans", json={"target": REPO}).status_code == 202


def test_rescans_count_toward_the_monthly_limit(client, monkeypatch):
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    alice = _as("alice")
    scan, _ = _make_scan(client, alice)
    for _ in range(4):
        assert client.post(f"/scans/{scan['id']}/rescan", headers=alice).status_code == 202
    assert client.post(f"/scans/{scan['id']}/rescan", headers=alice).status_code == 402


def test_webhook_runs_are_not_metered(client):
    alice = _as("alice")
    scan, _ = _make_scan(client, alice)
    with db.SessionLocal() as s:
        for _ in range(3):
            s.add(db.ScanRun(scan_id=scan["id"], kind="webhook"))
        s.commit()
    assert client.get("/me", headers=alice).json()["usage"]["scans_this_month"] == 1


def test_pro_plan_lifts_the_monthly_limit(client, monkeypatch):
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    alice = _as("alice")
    uid = _user_id(client, alice)
    with db.SessionLocal() as s:
        _add_sub(s, user_id=uid, plan="pro")
    for _ in range(8):
        assert client.post("/scans", json={"target": REPO}, headers=alice).status_code == 202
    me = client.get("/me", headers=alice).json()
    assert me["plan"] == "pro" and me["limits"]["monthly_scans"] is None and me["limits"]["auto_rescan"] is True


def test_canceled_subscription_stays_active_until_the_paid_period_ends(client):
    alice = _as("alice")
    uid = _user_id(client, alice)
    now = datetime.now(timezone.utc)
    with db.SessionLocal() as s:
        _add_sub(s, user_id=uid, status="canceled", period_end=now + timedelta(days=5))
    assert client.get("/me", headers=alice).json()["plan"] == "pro"

    with db.SessionLocal() as s:
        s.query(db.Subscription).update({"current_period_end": now - timedelta(days=1)})
        s.commit()
    assert client.get("/me", headers=alice).json()["plan"] == "free"


@pytest.mark.parametrize("status", ["expired", "past_due"])
def test_expired_and_past_due_subscriptions_grant_nothing(client, status):
    alice = _as("alice")
    with db.SessionLocal() as s:
        _add_sub(s, user_id=_user_id(client, alice), status=status)
    assert client.get("/me", headers=alice).json()["plan"] == "free"


def test_team_subscription_on_an_org_upgrades_its_members(client):
    owner, member = _as("owner", "o@x.test"), _as("member", "m@x.test")
    client.get("/me", headers=member)
    org = client.post("/orgs", json={"name": "Cohort"}, headers=owner).json()
    client.post(f"/orgs/{org['id']}/members", json={"email": "m@x.test"}, headers=owner)

    assert client.get("/me", headers=member).json()["plan"] == "free"
    with db.SessionLocal() as s:
        _add_sub(s, org_id=org["id"], plan="team")
    assert client.get("/me", headers=member).json()["plan"] == "team"
    assert client.get("/me", headers=_as("outsider")).json()["plan"] == "free"


# ================================ organizations =============================


def _org_with_member(client):
    owner, member = _as("owner", "owner@x.test"), _as("member", "member@x.test")
    client.get("/me", headers=member)
    org = client.post("/orgs", json={"name": "Bootcamp"}, headers=owner).json()
    assert client.post(f"/orgs/{org['id']}/members", json={"email": "member@x.test"}, headers=owner).status_code == 201
    return owner, member, org


def test_creating_an_org_makes_the_creator_owner(client):
    owner = _as("owner")
    org = client.post("/orgs", json={"name": "  Pak Angels  "}, headers=owner).json()
    assert org["name"] == "Pak Angels" and org["role"] == "owner"
    listed = client.get("/orgs", headers=owner).json()
    assert listed == [{"id": org["id"], "name": "Pak Angels", "role": "owner", "member_count": 1}]


def test_org_endpoints_require_sign_in_and_valid_input(client):
    assert client.post("/orgs", json={"name": "x"}).status_code == 401
    assert client.get("/orgs").status_code == 401
    assert client.post("/orgs", json={"name": ""}, headers=_as()).status_code == 422


def test_add_member_rules(client):
    owner, member, org = _org_with_member(client)
    url = f"/orgs/{org['id']}/members"

    assert client.post(url, json={"email": "MEMBER@x.test"}, headers=owner).status_code == 409  # duplicate, case-insensitive
    unknown = client.post(url, json={"email": "nobody@x.test"}, headers=owner)
    assert unknown.status_code == 404 and "sign in" in unknown.json()["detail"]
    assert client.post(url, json={"email": "x@x.test"}, headers=member).status_code == 403  # plain members can't add
    assert client.post(url, json={"email": "x@x.test"}, headers=_as("stranger")).status_code == 404  # org is invisible


def test_seat_limit_applies_only_when_enforced(client, monkeypatch):
    owner, _, org = _org_with_member(client)  # 2 members on a plan with 1 seat, added while not enforcing
    client.get("/me", headers=_as("third", "third@x.test"))
    url = f"/orgs/{org['id']}/members"

    assert client.post(url, json={"email": "third@x.test"}, headers=owner).status_code == 201

    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    client.get("/me", headers=_as("fourth", "fourth@x.test"))
    over = client.post(url, json={"email": "fourth@x.test"}, headers=owner)
    assert over.status_code == 402 and "seat" in over.json()["detail"]

    with db.SessionLocal() as s:
        _add_sub(s, org_id=org["id"], plan="team")
    assert client.post(url, json={"email": "fourth@x.test"}, headers=owner).status_code == 201


def test_remove_member_and_leave_rules(client):
    owner, member, org = _org_with_member(client)
    owner_id, member_id = _user_id(client, owner), _user_id(client, member)
    base = f"/orgs/{org['id']}/members"

    assert client.delete(f"{base}/{owner_id}", headers=owner).status_code == 400  # owner can't be removed
    assert client.delete(f"{base}/{owner_id}", headers=member).status_code == 403  # member can't remove others
    assert client.delete(f"{base}/{member_id}", headers=member).status_code == 204  # but can leave
    assert client.delete(f"{base}/{member_id}", headers=owner).status_code == 404  # already gone
    assert client.get("/orgs", headers=member).json() == []


def test_creating_an_org_scan_requires_membership(client):
    owner, member, org = _org_with_member(client)
    assert client.post("/scans", json={"target": REPO, "org_id": org["id"]}, headers=member).status_code == 202
    assert client.post("/scans", json={"target": REPO, "org_id": org["id"]}, headers=_as("stranger")).status_code == 403
    assert client.post("/scans", json={"target": REPO, "org_id": org["id"]}).status_code == 403  # anonymous


def test_dashboard_shows_latest_scan_per_member_project(client, monkeypatch):
    owner, member, org = _org_with_member(client)
    bad, good = "https://github.com/member/bad-app", "https://github.com/member/clean-app"

    first, _ = _make_scan(client, member, target=bad, org_id=org["id"])
    assert first["status"] == "completed"
    _make_scan(client, member, target=good, org_id=org["id"])
    # the member fixes "bad-app": the newest scan of that project is now clean
    monkeypatch.setattr(main, "run_full_scan", lambda t, **kw: _scan_for("clean"))
    _make_scan(client, member, target=bad, org_id=org["id"])
    # and scans something that is not part of the org
    _make_scan(client, member, target="https://github.com/member/personal")

    dash = client.get(f"/orgs/{org['id']}/dashboard", headers=owner).json()
    assert dash["org"]["name"] == "Bootcamp"
    assert dash["summary"] == {"projects": 2, "passing": 2, "failing": 0, "in_progress": 0}
    member_row = next(m for m in dash["members"] if m["email"] == "member@x.test")
    assert sorted(p["target"] for p in member_row["projects"]) == sorted([bad, good])
    assert all(p["passed"] is True for p in member_row["projects"])
    owner_row = next(m for m in dash["members"] if m["role"] == "owner")
    assert owner_row["projects"] == []


def test_dashboard_reports_failing_and_in_progress_projects(client):
    owner, member, org = _org_with_member(client)
    _make_scan(client, member, target="https://github.com/member/leaky", org_id=org["id"])
    stuck, _ = _make_scan(client, member, target="https://github.com/member/slow", org_id=org["id"])
    with db.SessionLocal() as s:
        s.get(db.Scan, stuck["id"]).status = "running"
        s.commit()

    summary = client.get(f"/orgs/{org['id']}/dashboard", headers=owner).json()["summary"]
    assert summary == {"projects": 2, "passing": 0, "failing": 1, "in_progress": 1}


def test_dashboard_permissions(client):
    owner, member, org = _org_with_member(client)
    url = f"/orgs/{org['id']}/dashboard"
    assert client.get(url, headers=owner).status_code == 200
    assert client.get(url, headers=member).status_code == 403
    assert client.get(url, headers=_as("stranger")).status_code == 404
    assert client.get(url).status_code == 401


def test_org_admins_can_read_member_scans_but_not_rescan_them(client):
    owner, member, org = _org_with_member(client)
    scan, _ = _make_scan(client, member, org_id=org["id"])

    assert client.get(f"/scans/{scan['id']}", headers=owner).status_code == 200
    assert client.get(f"/scans/{scan['id']}/badge", headers=owner).status_code == 200
    assert client.post(f"/scans/{scan['id']}/rescan", headers=owner).status_code == 404
    assert client.get(f"/scans/{scan['id']}", headers=_as("stranger")).status_code == 404


def test_org_scan_is_not_visible_to_plain_teammates(client):
    owner, member, org = _org_with_member(client)
    scan, _ = _make_scan(client, owner, org_id=org["id"])
    assert client.get(f"/scans/{scan['id']}", headers=member).status_code == 404


# =============================== billing webhook ============================


def _bill(client, payload, secret=BILLING_SECRET, signature=None):
    body = json.dumps(payload).encode()
    sig = signature or "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return client.post(
        "/webhooks/billing", content=body,
        headers={"X-Billing-Signature": sig, "Content-Type": "application/json"},
    )


def _pro_event(**over):
    return {
        "event": "subscription.activated", "provider": "whop", "plan": "pro",
        "provider_subscription_id": "sub_1", "provider_customer_id": "cus_1",
        "user": {"clerk_user_id": "alice"}, **over,
    }


@pytest.fixture()
def billing(monkeypatch):
    monkeypatch.setenv("BILLING_WEBHOOK_SECRET", BILLING_SECRET)


def test_billing_webhook_is_disabled_without_a_secret(client):
    assert _bill(client, _pro_event()).status_code == 503


def test_billing_webhook_rejects_bad_signatures(client, billing):
    assert _bill(client, _pro_event(), signature="sha256=00").status_code == 401
    assert _bill(client, _pro_event(), secret="wrong").status_code == 401
    assert client.post("/webhooks/billing", content=b"{}").status_code == 401


def test_billing_webhook_rejects_malformed_events(client, billing):
    assert _bill(client, {"event": "nonsense"}).status_code == 400
    assert _bill(client, _pro_event(plan="enterprise")).status_code == 400
    assert _bill(client, _pro_event(user=None)).status_code == 400
    assert _bill(client, {**_pro_event(), "plan": "team"}).status_code == 400  # team needs org_id
    assert _bill(client, {**_pro_event(), "plan": "team", "org_id": "missing"}).status_code == 404


def test_activation_upgrades_the_user_by_clerk_id_or_email(client, billing):
    client.get("/me", headers=_as("alice", "alice@x.test"))
    assert _bill(client, _pro_event()).json() == {"ok": True, "status": "active"}
    assert client.get("/me", headers=_as("alice")).json()["plan"] == "pro"

    client.get("/me", headers=_as("bob", "bob@x.test"))
    by_email = _pro_event(provider_subscription_id="sub_2", user={"email": "BOB@x.test"})
    assert _bill(client, by_email).status_code == 200
    assert client.get("/me", headers=_as("bob")).json()["plan"] == "pro"


def test_activation_for_an_unknown_user_is_retryable(client, billing):
    resp = _bill(client, _pro_event(user={"clerk_user_id": "not-signed-up-yet"}))
    assert resp.status_code == 404
    client.get("/me", headers=_as("not-signed-up-yet"))
    assert _bill(client, _pro_event(user={"clerk_user_id": "not-signed-up-yet"})).status_code == 200


def test_subscription_events_are_idempotent_and_move_through_the_lifecycle(client, billing):
    client.get("/me", headers=_as("alice"))
    alice = _as("alice")
    end = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

    for _ in range(2):  # a redelivered event changes nothing
        _bill(client, _pro_event(current_period_end=end))
    with db.SessionLocal() as s:
        assert s.query(db.Subscription).count() == 1

    assert _bill(client, _pro_event(event="subscription.canceled", current_period_end=end)).json()["status"] == "canceled"
    assert client.get("/me", headers=alice).json()["plan"] == "pro"  # paid through the period

    assert _bill(client, _pro_event(event="subscription.expired")).json()["status"] == "expired"
    assert client.get("/me", headers=alice).json()["plan"] == "free"

    assert _bill(client, _pro_event(event="subscription.updated", status="active")).json()["status"] == "active"
    assert client.get("/me", headers=alice).json()["plan"] == "pro"
    with db.SessionLocal() as s:
        assert s.query(db.Subscription).count() == 1


def test_team_subscription_attaches_to_the_organization(client, billing):
    owner = _as("owner", "o@x.test")
    org = client.post("/orgs", json={"name": "Cohort"}, headers=owner).json()
    event = {
        "event": "subscription.activated", "provider": "whop", "plan": "team",
        "provider_subscription_id": "team_1", "org_id": org["id"],
    }
    assert _bill(client, event).status_code == 200
    assert client.get("/me", headers=owner).json()["plan"] == "team"
    with db.SessionLocal() as s:
        sub = s.query(db.Subscription).one()
        assert sub.org_id == org["id"] and sub.user_id is None


# ================================ push webhook x plans ======================


def test_push_rescans_only_paid_owners_when_plans_are_enforced(client, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s3cret")
    monkeypatch.setenv("ENFORCE_PLAN_LIMITS", "1")
    alice = _as("alice")
    _make_scan(client, alice)

    payload = {
        "ref": "refs/heads/main",
        "repository": {"full_name": "example/app", "html_url": REPO, "default_branch": "main"},
    }
    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": "push", "Content-Type": "application/json",
        "X-Hub-Signature-256": "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest(),
    }

    assert client.post("/webhooks/github", content=body, headers=headers).json() == {"triggered": 0}

    with db.SessionLocal() as s:
        _add_sub(s, user_id=_user_id(client, alice), plan="pro")
    assert client.post("/webhooks/github", content=body, headers=headers).json() == {"triggered": 1}


# =============================== database / migrations ======================


def test_deleting_an_org_removes_memberships_but_keeps_scans(client):
    owner, member, org = _org_with_member(client)
    scan, _ = _make_scan(client, member, org_id=org["id"])
    with db.SessionLocal() as s:
        s.query(db.Scan).filter_by(id=scan["id"]).update({"org_id": None})
        s.delete(s.get(db.Organization, org["id"]))
        s.commit()
        assert s.query(db.Membership).count() == 0
        assert s.get(db.Scan, scan["id"]) is not None

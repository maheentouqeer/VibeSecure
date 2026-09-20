"""Checkout: request shape against Whop's documented API, safety of what the
client can influence, and the full purchase round trip through the webhook."""
import json
from datetime import datetime, timezone

import pytest
import requests
from fastapi.testclient import TestClient

from backend import auth, billing, db, limits, main
from backend.db import Base, engine
from test_accounts import _add_sub, _as, _FakeJwks, _user_id
from test_whop import SECRET as WHOP_SECRET, _sign

PLAN_MAP = {"plan_pro_monthly": "pro", "plan_pro_yearly": "pro", "plan_team": "team", "prod_ignored": "team"}
URL = "https://whop.com/checkout/plan_abc?session=xyz"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    for var in ("FRONTEND_URL", "WHOP_API_BASE", "CHECKOUT_RATE_LIMIT_PER_HOUR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("WHOP_API_KEY", "whop_secret_key_123")
    monkeypatch.setenv("WHOP_PLAN_MAP", json.dumps(PLAN_MAP))
    monkeypatch.setenv("WHOP_WEBHOOK_SECRET", WHOP_SECRET)
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


@pytest.fixture()
def sent(monkeypatch):
    """Replaces the network call; records what we would have sent to Whop."""
    calls = []

    def fake(payload):
        calls.append(payload)
        return {"id": "ch_123", "purchase_url": URL}

    monkeypatch.setattr(billing, "_create_checkout", fake)
    return calls


def _checkout(client, headers, **body):
    return client.post("/billing/checkout", json=body, headers=headers)


def _org(client, owner="owner"):
    h = _as(owner, f"{owner}@x.test")
    return h, client.post("/orgs", json={"name": "Cohort"}, headers=h).json()["id"]


# ================================ availability ==============================


def test_checkout_requires_sign_in(client, sent):
    assert client.post("/billing/checkout", json={"plan": "pro"}).status_code == 401
    assert sent == []


def test_checkout_is_off_without_an_api_key(client, sent, monkeypatch):
    monkeypatch.delenv("WHOP_API_KEY")
    assert _checkout(client, _as("alice"), plan="pro").status_code == 503
    assert sent == []


def test_a_plan_with_no_purchasable_whop_plan_is_unavailable(client, sent, monkeypatch):
    monkeypatch.setenv("WHOP_PLAN_MAP", json.dumps({"prod_only": "pro"}))  # product ids can't be bought directly
    resp = _checkout(client, _as("alice"), plan="pro")
    assert resp.status_code == 503 and "not available" in resp.json()["detail"]


def test_request_validation(client, sent):
    alice = _as("alice")
    assert _checkout(client, alice, plan="enterprise").status_code == 422
    assert _checkout(client, alice).status_code == 422
    assert sent == []


# ================================= pro plan =================================


def test_pro_checkout_sends_a_server_built_request_and_returns_the_url(client, sent):
    alice = _as("alice", "alice@x.test")
    resp = _checkout(client, alice, plan="pro")

    assert resp.status_code == 200
    assert resp.json() == {"url": URL, "checkout_id": "ch_123", "plan": "pro"}
    assert sent == [{"plan_id": "plan_pro_monthly", "metadata": {"clerk_user_id": "alice", "source": "secure-vibecode"}}]


def test_a_specific_configured_plan_option_can_be_chosen(client, sent):
    _checkout(client, _as("alice"), plan="pro", whop_plan_id="plan_pro_yearly")
    assert sent[0]["plan_id"] == "plan_pro_yearly"


@pytest.mark.parametrize("bad", ["plan_team", "plan_random", "prod_ignored", ""])
def test_the_client_cannot_pick_an_arbitrary_or_wrong_whop_plan(client, sent, bad):
    resp = _checkout(client, _as("alice"), plan="pro", whop_plan_id=bad)
    assert resp.status_code in (200, 400)
    if bad:
        assert resp.status_code == 400 and sent == []


def test_the_client_cannot_inject_or_override_metadata(client, sent):
    _checkout(
        client, _as("alice"), plan="pro",
        metadata={"clerk_user_id": "victim", "org_id": "someone-elses"}, clerk_user_id="victim", user_id="victim",
    )
    assert sent[0]["metadata"] == {"clerk_user_id": "alice", "source": "secure-vibecode"}


def test_pro_rejects_an_org_and_existing_subscribers(client, sent):
    alice = _as("alice")
    assert _checkout(client, alice, plan="pro", org_id="anything").status_code == 400
    with db.SessionLocal() as s:
        _add_sub(s, user_id=_user_id(client, alice), plan="pro")
    resp = _checkout(client, alice, plan="pro")
    assert resp.status_code == 409 and "already" in resp.json()["detail"]
    assert sent == []


def test_expired_subscribers_can_buy_again(client, sent):
    alice = _as("alice")
    with db.SessionLocal() as s:
        _add_sub(s, user_id=_user_id(client, alice), plan="pro", status="expired")
    assert _checkout(client, alice, plan="pro").status_code == 200


# ================================= team plan ================================


def test_team_checkout_carries_the_org_and_needs_the_owner(client, sent):
    owner, org = _org(client)
    resp = _checkout(client, owner, plan="team", org_id=org)

    assert resp.status_code == 200
    assert sent[0] == {
        "plan_id": "plan_team",
        "metadata": {"clerk_user_id": "owner", "source": "secure-vibecode", "org_id": org},
    }


def test_team_checkout_rules(client, sent):
    owner, org = _org(client)
    member = _as("member", "member@x.test")
    client.get("/me", headers=member)
    client.post(f"/orgs/{org}/members", json={"email": "member@x.test"}, headers=owner)

    assert _checkout(client, owner, plan="team").status_code == 400  # org_id missing
    assert _checkout(client, member, plan="team", org_id=org).status_code == 403  # not the owner
    assert _checkout(client, _as("stranger"), plan="team", org_id=org).status_code == 404  # org is invisible
    assert _checkout(client, owner, plan="team", org_id="nope").status_code == 404
    assert sent == []

    with db.SessionLocal() as s:
        _add_sub(s, org_id=org, plan="team")
    assert _checkout(client, owner, plan="team", org_id=org).status_code == 409  # already subscribed
    assert sent == []


def test_after_an_ownership_transfer_only_the_new_owner_can_buy(client, sent):
    owner, org = _org(client)
    new_owner = _as("new", "new@x.test")
    client.get("/me", headers=new_owner)
    client.post(f"/orgs/{org}/members", json={"email": "new@x.test"}, headers=owner)
    client.post(f"/orgs/{org}/transfer", json={"user_id": _user_id(client, new_owner)}, headers=owner)

    assert _checkout(client, owner, plan="team", org_id=org).status_code == 403
    assert _checkout(client, new_owner, plan="team", org_id=org).status_code == 200


# ================================ redirect & limits =========================


def test_the_return_url_is_set_only_from_a_valid_frontend_url(client, sent, monkeypatch):
    _checkout(client, _as("alice"), plan="pro")
    assert "redirect_url" not in sent[-1]

    monkeypatch.setenv("FRONTEND_URL", "https://app.example.test/")
    _checkout(client, _as("bob"), plan="pro")
    assert sent[-1]["redirect_url"] == "https://app.example.test?checkout=success"

    monkeypatch.setenv("FRONTEND_URL", "javascript:alert(1)")
    _checkout(client, _as("carol"), plan="pro")
    assert "redirect_url" not in sent[-1]


def test_checkout_attempts_are_throttled_per_user(client, sent, monkeypatch):
    monkeypatch.setenv("CHECKOUT_RATE_LIMIT_PER_HOUR", "2")
    alice = _as("alice")
    assert [_checkout(client, alice, plan="pro").status_code for _ in range(3)] == [200, 200, 429]
    assert _checkout(client, _as("bob"), plan="pro").status_code == 200


# ============================= the call to Whop itself ======================


class _Resp:
    def __init__(self, status=200, body=None, text=""):
        self.status_code, self._body, self.text = status, body, text

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


@pytest.fixture()
def http(monkeypatch):
    calls = []
    behaviour = {"resp": _Resp(200, {"id": "ch_1", "purchase_url": URL})}

    def fake_post(url, **kw):
        calls.append({"url": url, **kw})
        if isinstance(behaviour["resp"], Exception):
            raise behaviour["resp"]
        return behaviour["resp"]

    monkeypatch.setattr(billing.requests, "post", fake_post)
    return calls, behaviour


def test_the_request_matches_whops_documented_api(client, http):
    calls, _ = http
    assert _checkout(client, _as("alice"), plan="pro").status_code == 200

    call = calls[0]
    assert call["url"] == "https://api.whop.com/api/v1/checkout_configurations"
    assert call["headers"]["Authorization"] == "Bearer whop_secret_key_123"
    assert call["json"] == {"plan_id": "plan_pro_monthly", "metadata": {"clerk_user_id": "alice", "source": "secure-vibecode"}}
    assert call["timeout"] == 10


def test_the_api_base_can_be_overridden(client, http, monkeypatch):
    monkeypatch.setenv("WHOP_API_BASE", "https://staging.example.test/api/v1/")
    _checkout(client, _as("alice"), plan="pro")
    assert http[0][0]["url"] == "https://staging.example.test/api/v1/checkout_configurations"


def test_whop_errors_become_a_502_that_leaks_nothing(client, http):
    _, behaviour = http
    behaviour["resp"] = _Resp(401, {"error": "bad key whop_secret_key_123"}, text="Unauthorized: key whop_secret_key_123")
    resp = _checkout(client, _as("alice"), plan="pro")
    assert resp.status_code == 502
    assert "whop_secret_key_123" not in resp.text and "Unauthorized" not in resp.text


@pytest.mark.parametrize(
    "resp",
    [
        requests.ConnectionError("dns failure"),
        requests.Timeout("slow"),
        _Resp(200, None),  # not JSON
        _Resp(200, {"id": "ch_1"}),  # no purchase_url
        _Resp(200, {"id": "ch_1", "purchase_url": None}),
        _Resp(200, {"id": "ch_1", "purchase_url": "http://insecure.example/x"}),
        _Resp(200, {"id": "ch_1", "purchase_url": "javascript:alert(1)"}),
        _Resp(200, {"id": "ch_1", "purchase_url": 12345}),
        _Resp(500, {"error": "boom"}),
    ],
)
def test_every_bad_answer_from_whop_is_a_clean_502(client, http, resp):
    _, behaviour = http
    behaviour["resp"] = resp
    out = _checkout(client, _as("alice"), plan="pro")
    assert out.status_code == 502 and "url" not in out.json()


# =========================== purchase round trip ============================


def _membership_event(metadata, plan_id, mid="mem_1"):
    return {
        "id": "evt_1", "type": "membership.activated", "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "id": mid, "status": "active", "plan_id": plan_id, "product_id": "prod_x", "user_id": "whop_user",
            "current_period_end": "2027-01-01T00:00:00Z", "metadata": metadata,  # what Whop copies from the checkout
        },
    }


def _deliver(client, envelope):
    body = json.dumps(envelope).encode()
    return client.post("/webhooks/whop", content=body, headers=_sign(body))


def test_a_pro_purchase_round_trips_from_checkout_to_plan(client, sent):
    alice = _as("alice", "alice@x.test")
    assert client.get("/me", headers=alice).json()["plan"] == "free"

    _checkout(client, alice, plan="pro")
    checkout = sent[0]
    # Whop copies checkout metadata onto the membership it creates:
    assert _deliver(client, _membership_event(checkout["metadata"], checkout["plan_id"])).status_code == 200

    assert client.get("/me", headers=alice).json()["plan"] == "pro"
    assert _checkout(client, alice, plan="pro").status_code == 409  # and now she can't double-buy


def test_a_team_purchase_round_trips_to_the_organization(client, sent):
    owner, org = _org(client)
    member = _as("member", "member@x.test")
    client.get("/me", headers=member)
    client.post(f"/orgs/{org}/members", json={"email": "member@x.test"}, headers=owner)

    _checkout(client, owner, plan="team", org_id=org)
    checkout = sent[0]
    assert _deliver(client, _membership_event(checkout["metadata"], checkout["plan_id"], mid="mem_team")).status_code == 200

    assert client.get("/me", headers=owner).json()["plan"] == "team"
    assert client.get("/me", headers=member).json()["plan"] == "team"  # members inherit the org's plan
    with db.SessionLocal() as s:
        sub = s.query(db.Subscription).one()
        assert sub.org_id == org and sub.user_id is None

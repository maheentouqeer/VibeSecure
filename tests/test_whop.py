"""Whop adapter: signature scheme (cross-checked against the reference
Standard Webhooks library the way Whop's own SDK uses it) and event mapping."""
import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend import auth, db, limits, main, whop
from backend.db import Base, engine
from test_accounts import _as, _FakeJwks, _user_id

SECRET = "ws_test_secret_value_123"
PLAN_MAP = {"plan_pro": "pro", "prod_team": "team"}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    monkeypatch.setenv("WHOP_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("WHOP_PLAN_MAP", json.dumps(PLAN_MAP))
    monkeypatch.delenv("ENFORCE_PLAN_LIMITS", raising=False)
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


def _sign(body: bytes, secret=SECRET, msg_id="msg_1", ts=None) -> dict:
    """Signs the way Whop's backend does, per the SDK's documented behaviour."""
    ts = str(int(time.time()) if ts is None else ts)
    signed = f"{msg_id}.{ts}.".encode() + body
    sig = base64.b64encode(hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).digest()).decode()
    return {"webhook-id": msg_id, "webhook-timestamp": ts, "webhook-signature": f"v1,{sig}"}


def _post(client, envelope, secret=SECRET, **sign_kw):
    body = json.dumps(envelope).encode()
    return client.post("/webhooks/whop", content=body, headers={**_sign(body, secret, **sign_kw), "Content-Type": "application/json"})


def _event(kind="membership.activated", *, status="active", clerk="user_alice", mid="mem_1", plan_id="plan_pro",
           at=None, extra=None, **data_over):
    data = {
        "id": mid, "status": status, "plan_id": plan_id, "product_id": "prod_x", "user_id": "user_whop_1",
        "current_period_end": "2026-12-01T00:00:00Z", "cancel_at_period_end": False,
        "metadata": {"clerk_user_id": clerk} if clerk else {},
    }
    data.update(data_over)
    env = {"id": "evt_1", "type": kind, "api_version": "v1", "timestamp": at or datetime.now(timezone.utc).isoformat(), "data": data}
    env.update(extra or {})
    return env


def _plan_of(client, sub="user_alice"):
    return client.get("/me", headers=_as(sub)).json()["plan"]


# ================================ signatures ================================


def test_signatures_interoperate_with_the_reference_standard_webhooks_library():
    standardwebhooks = pytest.importorskip("standardwebhooks")
    body = b'{"type":"membership.activated","data":{"id":"mem_1"}}'
    # exactly how whop_sdk.lib.verify_webhook derives the key for the reference library
    reference = standardwebhooks.Webhook(base64.b64encode(SECRET.encode()).decode())

    # the reference signs -> we accept
    ts = datetime.now(timezone.utc)
    ref_sig = reference.sign("msg_9", ts, body.decode())
    headers = {"webhook-id": "msg_9", "webhook-timestamp": str(int(ts.timestamp())), "webhook-signature": ref_sig}
    assert whop.verify_signature(body, headers, SECRET) is True

    # we sign -> the reference accepts
    reference.verify(body, _sign(body, msg_id="msg_10"))


def test_valid_signature_is_accepted_even_among_several():
    body = b"{}"
    headers = _sign(body)
    headers["webhook-signature"] = "v1,AAAA v2,BBBB " + headers["webhook-signature"]
    assert whop.verify_signature(body, headers, SECRET) is True


def test_header_names_are_case_insensitive():
    body = b"{}"
    headers = {k.title(): v for k, v in _sign(body).items()}
    assert whop.verify_signature(body, headers, SECRET) is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda h, b: (h, b"{ }"),  # tampered body
        lambda h, b: ({**h, "webhook-id": "other"}, b),  # id is part of the signed string
        lambda h, b: ({**h, "webhook-timestamp": str(int(h["webhook-timestamp"]) + 1)}, b),
        lambda h, b: ({k: v for k, v in h.items() if k != "webhook-signature"}, b),
        lambda h, b: ({k: v for k, v in h.items() if k != "webhook-id"}, b),
        lambda h, b: ({**h, "webhook-signature": "v2," + h["webhook-signature"][3:]}, b),  # wrong version
        lambda h, b: ({**h, "webhook-signature": h["webhook-signature"] + "x"}, b),
        lambda h, b: ({**h, "webhook-timestamp": "not-a-number"}, b),
    ],
)
def test_bad_signatures_are_rejected(mutate):
    body = b'{"a":1}'
    headers, body = mutate(_sign(body), body)
    assert whop.verify_signature(body, headers, SECRET) is False


def test_wrong_secret_is_rejected_and_prefix_matters():
    body = b"{}"
    assert whop.verify_signature(body, _sign(body, secret="ws_other"), SECRET) is False
    # the key is the WHOLE secret string, `ws_` prefix included
    assert whop.verify_signature(body, _sign(body, secret=SECRET[3:]), SECRET) is False


def test_timestamps_outside_five_minutes_are_rejected_both_ways():
    body = b"{}"
    now = time.time()
    assert whop.verify_signature(body, _sign(body, ts=int(now) - 200), SECRET, now=now) is True
    assert whop.verify_signature(body, _sign(body, ts=int(now) - 400), SECRET, now=now) is False  # replayed
    assert whop.verify_signature(body, _sign(body, ts=int(now) + 400), SECRET, now=now) is False  # from the future


# ================================= endpoint =================================


def test_endpoint_needs_a_configured_secret_and_a_valid_signature(client, monkeypatch):
    assert _post(client, _event(), secret="ws_wrong").status_code == 401
    assert client.post("/webhooks/whop", content=b"{}").status_code == 401
    assert _post(client, _event(), ts=int(time.time()) - 3600).status_code == 401
    monkeypatch.delenv("WHOP_WEBHOOK_SECRET")
    assert _post(client, _event()).status_code == 503


def test_signed_but_malformed_bodies_are_400(client):
    for body in (b"not json", b"[1,2,3]"):
        resp = client.post("/webhooks/whop", content=body, headers=_sign(body))
        assert resp.status_code == 400


def test_activation_upgrades_the_user_named_in_the_checkout_metadata(client):
    client.get("/me", headers=_as("user_alice", "alice@x.test"))
    assert _plan_of(client) == "free"

    resp = _post(client, _event())
    assert resp.status_code == 200 and resp.json()["status"] == "active"
    assert _plan_of(client) == "pro"
    with db.SessionLocal() as s:
        sub = s.query(db.Subscription).one()
    assert (sub.provider, sub.provider_subscription_id, sub.plan) == ("whop", "mem_1", "pro")
    assert sub.provider_customer_id == "user_whop_1"
    assert sub.current_period_end.replace(tzinfo=timezone.utc) == datetime(2026, 12, 1, tzinfo=timezone.utc)


def test_a_purchase_before_first_sign_in_is_not_lost(client):
    """Whop disables webhooks that keep failing, so an unknown user must not be an error."""
    assert _post(client, _event(clerk="user_early")).status_code == 200
    with db.SessionLocal() as s:
        assert s.query(db.User).filter_by(clerk_user_id="user_early").count() == 1

    me = client.get("/me", headers=_as("user_early", "early@x.test")).json()  # first sign-in
    assert me["plan"] == "pro" and me["user"]["email"] == "early@x.test"
    with db.SessionLocal() as s:
        assert s.query(db.User).count() == 1  # completed, not duplicated


def test_nested_legacy_payload_shape_is_understood(client):
    client.get("/me", headers=_as("user_alice", "alice@x.test"))
    env = _event(clerk=None, plan_id=None, mid="mem_legacy")
    env["data"].pop("plan_id")
    env["data"].update(
        plan={"id": "plan_pro"}, product={"id": "prod_x"}, user={"id": "user_whop_1", "email": "ALICE@x.test"},
        renewal_period_end="2026-11-15T12:00:00+00:00",
    )
    env["data"].pop("current_period_end")
    assert _post(client, env).status_code == 200
    assert _plan_of(client) == "pro"


def test_product_id_can_be_used_in_the_plan_map(client):
    client.get("/me", headers=_as("user_alice"))
    env = _event(plan_id="plan_unknown", product_id="prod_team", extra=None, metadata={"clerk_user_id": "u", "org_id": "nope"})
    assert _post(client, env).json()["ignored"]  # mapped to team, but that org doesn't exist -> acknowledged


def test_team_membership_attaches_to_the_organization(client):
    owner = _as("owner", "o@x.test")
    org = client.post("/orgs", json={"name": "Cohort"}, headers=owner).json()
    env = _event(clerk="owner", plan_id="prod_team", mid="mem_team", metadata={"clerk_user_id": "owner", "org_id": org["id"]})

    assert _post(client, env).status_code == 200
    assert client.get("/me", headers=owner).json()["plan"] == "team"
    with db.SessionLocal() as s:
        sub = s.query(db.Subscription).one()
    assert sub.org_id == org["id"] and sub.user_id is None


@pytest.mark.parametrize(
    "envelope, why",
    [
        (_event("membership.trial_ending_soon"), "ignored event type"),
        (_event("payment.succeeded"), "ignored event type"),
        (_event(plan_id="plan_not_ours"), "WHOP_PLAN_MAP"),
        (_event(clerk=None), "clerk_user_id"),
        (_event(plan_id="prod_team", metadata={"clerk_user_id": "u"}), "org_id"),
        (_event(status="drafted"), "not a subscription state"),
        ({"type": "membership.activated", "data": {}}, "no membership"),
        ({"type": "membership.activated"}, "no membership"),
    ],
)
def test_events_that_cannot_help_are_acknowledged_with_a_reason(client, envelope, why):
    resp = _post(client, envelope)
    assert resp.status_code == 200 and why in resp.json()["ignored"]
    with db.SessionLocal() as s:
        assert s.query(db.Subscription).count() == 0


def test_invalid_plan_map_grants_nothing(client, monkeypatch):
    for bad in ("not json", "[]", json.dumps({"plan_pro": "enterprise"})):
        monkeypatch.setenv("WHOP_PLAN_MAP", bad)
        assert "WHOP_PLAN_MAP" in _post(client, _event()).json()["ignored"]


def test_deactivation_ends_the_plan_and_status_maps_sensibly(client):
    client.get("/me", headers=_as("user_alice"))
    _post(client, _event())
    assert _plan_of(client) == "pro"

    _post(client, _event("membership.deactivated", status="expired"))
    assert _plan_of(client) == "free"

    _post(client, _event("membership.activated", status="trialing"))
    assert _plan_of(client) == "pro"

    # "completed" and any still-"active" status on a deactivation both end the plan
    _post(client, _event("membership.deactivated", status="completed"))
    assert _plan_of(client) == "free"
    _post(client, _event("membership.activated"))
    _post(client, _event("membership.deactivated", status="active"))
    assert _plan_of(client) == "free"


def test_cancelling_keeps_access_until_the_paid_period_ends(client):
    client.get("/me", headers=_as("user_alice"))
    future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    _post(client, _event())

    _post(client, _event("membership.cancel_at_period_end_changed", status="canceling", cancel_at_period_end=True, current_period_end=future))
    assert _plan_of(client) == "pro"

    _post(client, _event("membership.deactivated", status="canceled", current_period_end=future))
    assert _plan_of(client) == "pro"  # canceled, but paid through the period
    with db.SessionLocal() as s:
        s.query(db.Subscription).update({"current_period_end": datetime.now(timezone.utc) - timedelta(days=1)})
        s.commit()
    assert _plan_of(client) == "free"


def test_past_due_memberships_do_not_grant_the_plan(client):
    client.get("/me", headers=_as("user_alice"))
    _post(client, _event(status="past_due"))
    assert _plan_of(client) == "free"


def test_redelivery_is_idempotent(client):
    client.get("/me", headers=_as("user_alice"))
    env = _event()
    for i in range(3):
        assert _post(client, env, msg_id=f"msg_{i}").status_code == 200
    with db.SessionLocal() as s:
        assert s.query(db.Subscription).count() == 1


def test_a_late_retry_of_an_old_event_cannot_undo_a_newer_one(client):
    client.get("/me", headers=_as("user_alice"))
    t0 = datetime.now(timezone.utc) - timedelta(hours=5)
    _post(client, _event(at=t0.isoformat()))
    _post(client, _event("membership.deactivated", status="expired", at=(t0 + timedelta(hours=1)).isoformat()))
    assert _plan_of(client) == "free"

    # the original "activated" is retried by Whop hours later, out of order
    retry = _post(client, _event(at=t0.isoformat()))
    assert retry.json()["note"] == "stale event ignored"
    assert _plan_of(client) == "free"

    # a genuinely newer event still applies
    _post(client, _event(at=datetime.now(timezone.utc).isoformat()))
    assert _plan_of(client) == "pro"


def test_events_without_a_parsable_timestamp_are_still_applied(client):
    client.get("/me", headers=_as("user_alice"))
    env = _event()
    env["timestamp"] = "garbage"
    assert _post(client, env).status_code == 200
    assert _plan_of(client) == "pro"


def test_the_generic_billing_endpoint_still_404s_for_unknown_users(client, monkeypatch):
    """Only the Whop adapter pre-creates users; the neutral endpoint keeps its retry semantics."""
    monkeypatch.setenv("BILLING_WEBHOOK_SECRET", "bs")
    body = json.dumps(
        {"event": "subscription.activated", "plan": "pro", "provider_subscription_id": "s1", "user": {"clerk_user_id": "ghost"}}
    ).encode()
    sig = "sha256=" + hmac.new(b"bs", body, hashlib.sha256).hexdigest()
    assert client.post("/webhooks/billing", content=body, headers={"X-Billing-Signature": sig}).status_code == 404

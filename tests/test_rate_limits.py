"""Database-backed rate limiting and the throttles on the newer endpoints."""
import hashlib
import hmac
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend import auth, db, jobs, limits, main
from backend.db import Base, engine
from test_accounts import REPO, _as, _FakeJwks, _scan_for

STORE = limits.db_store


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limits.ip_limiter.reset()
    for var in (
        "RATE_LIMIT_STORE", "OAUTH_RATE_LIMIT_PER_HOUR", "MUTATION_RATE_LIMIT_PER_HOUR",
        "WEBHOOK_FAIL_LIMIT_PER_HOUR", "SCAN_RATE_LIMIT_PER_HOUR", "DAILY_SCAN_CAP", "ENFORCE_PLAN_LIMITS",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(auth, "_get_jwks_client", lambda: _FakeJwks())
    monkeypatch.setattr(main, "run_full_scan", lambda target, **kw: _scan_for(target))
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    return TestClient(main.app)


def _events(bucket=None):
    with db.SessionLocal() as s:
        q = s.query(db.RateEvent)
        return (q.filter_by(bucket=bucket) if bucket else q).count()


# ================================= the store ================================


def test_allows_up_to_the_limit_then_reports_when_to_retry():
    assert [STORE.hit("b", "k", 3) for _ in range(3)] == [None, None, None]
    retry = STORE.hit("b", "k", 3)
    assert retry is not None and 1 <= retry <= 3601
    assert _events("b") == 3  # a refused hit is not recorded


def test_keys_and_buckets_are_independent():
    for _ in range(2):
        STORE.hit("scan", "1.1.1.1", 2)
    assert STORE.hit("scan", "1.1.1.1", 2) is not None
    assert STORE.hit("scan", "2.2.2.2", 2) is None
    assert STORE.hit("oauth", "1.1.1.1", 2) is None


def test_hits_outside_the_window_do_not_count():
    with db.SessionLocal() as s:
        for _ in range(5):
            s.add(db.RateEvent(bucket="b", key="k", ts=datetime.now(timezone.utc) - timedelta(hours=2)))
        s.commit()
    assert STORE.hit("b", "k", 2) is None  # five old hits, but none inside the hour


def test_retry_after_counts_down_from_the_oldest_hit_in_the_window():
    with db.SessionLocal() as s:
        s.add(db.RateEvent(bucket="b", key="k", ts=datetime.now(timezone.utc) - timedelta(minutes=58)))
        s.commit()
    retry = STORE.hit("b", "k", 1)
    assert retry is not None and 60 <= retry <= 180  # ~2 minutes until the 58-minute-old hit expires


def test_the_count_stays_exact_under_concurrency():
    results, barrier = [], threading.Barrier(16)

    def go():
        barrier.wait()
        results.append(STORE.hit("b", "k", 5))

    threads = [threading.Thread(target=go) for _ in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert results.count(None) == 5 and len(results) == 16
    assert _events("b") == 5


def test_peek_never_records_and_record_always_does():
    assert STORE.peek("b", "k", 1) is None
    assert _events("b") == 0
    STORE.record("b", "k")
    assert STORE.peek("b", "k", 1) is not None
    assert _events("b") == 1


def test_purge_removes_only_old_events():
    with db.SessionLocal() as s:
        s.add(db.RateEvent(bucket="b", key="old", ts=datetime.now(timezone.utc) - timedelta(days=3)))
        s.add(db.RateEvent(bucket="b", key="new"))
        s.commit()
    assert STORE.purge(older_than_seconds=86400) == 1
    assert _events("b") == 1


def test_a_limit_of_zero_disables_the_check_entirely():
    assert all(limits.hit("b", "k", 0) is None for _ in range(50))
    assert _events() == 0


def test_the_limiter_fails_open_when_its_store_is_down(client, monkeypatch):
    def down(*a, **k):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(STORE, "hit", down)
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "1")
    for _ in range(3):
        assert client.post("/scans", json={"target": REPO}).status_code == 202


def test_memory_store_is_selectable_and_writes_nothing_to_the_database(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_STORE", "memory")
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "2")
    codes = [client.post("/scans", json={"target": REPO}).status_code for _ in range(3)]
    assert codes == [202, 202, 429]
    assert _events() == 0


def test_housekeeping_purges_old_events(client):
    with db.SessionLocal() as s:
        s.add(db.RateEvent(bucket="b", key="old", ts=datetime.now(timezone.utc) - timedelta(days=3)))
        s.commit()
    jobs._housekeeping()
    assert _events() == 0


# =============================== scan endpoint ==============================


def test_concurrent_scan_requests_never_exceed_the_limit(client, monkeypatch):
    """The reason for a shared store: several API instances can't each allow `limit`."""
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "4")
    codes, barrier = [], threading.Barrier(12)

    def go():
        barrier.wait()
        codes.append(client.post("/scans", json={"target": REPO}).status_code)

    threads = [threading.Thread(target=go) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(codes) == [202] * 4 + [429] * 8


def test_429_carries_retry_after_and_a_readable_message(client, monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "1")
    client.post("/scans", json={"target": REPO})
    resp = client.post("/scans", json={"target": REPO})
    assert resp.status_code == 429 and int(resp.headers["Retry-After"]) >= 1
    assert "Too many scans" in resp.json()["detail"]


def test_limits_are_per_ip_using_the_rightmost_forwarded_address(client, monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "1")
    a = {"X-Forwarded-For": "9.9.9.9, 1.1.1.1"}
    b = {"X-Forwarded-For": "9.9.9.9, 2.2.2.2"}
    assert client.post("/scans", json={"target": REPO}, headers=a).status_code == 202
    assert client.post("/scans", json={"target": REPO}, headers=a).status_code == 429
    assert client.post("/scans", json={"target": REPO}, headers=b).status_code == 202


# ============================== mutation throttle ===========================


def test_org_changes_are_throttled_per_user(client, monkeypatch):
    monkeypatch.setenv("MUTATION_RATE_LIMIT_PER_HOUR", "3")
    alice, bob = _as("alice"), _as("bob")
    assert [client.post("/orgs", json={"name": f"o{i}"}, headers=alice).status_code for i in range(4)] == [201, 201, 201, 429]
    assert client.post("/orgs", json={"name": "bobs"}, headers=bob).status_code == 201  # other users unaffected


def test_deletions_share_the_mutation_budget(client, monkeypatch):
    monkeypatch.setenv("MUTATION_RATE_LIMIT_PER_HOUR", "2")
    alice = _as("alice")
    ids = [client.post("/scans", json={"target": REPO}, headers=alice).json()["id"] for _ in range(3)]
    codes = [client.delete(f"/scans/{i}", headers=alice).status_code for i in ids]
    assert codes == [204, 204, 429]


def test_reads_are_never_throttled_by_the_mutation_bucket(client, monkeypatch):
    monkeypatch.setenv("MUTATION_RATE_LIMIT_PER_HOUR", "1")
    alice = _as("alice")
    client.post("/orgs", json={"name": "x"}, headers=alice)
    assert all(client.get("/orgs", headers=alice).status_code == 200 for _ in range(5))
    assert all(client.get("/me", headers=alice).status_code == 200 for _ in range(5))


# ================================ oauth throttle ============================


def test_the_github_connect_flow_is_throttled_per_ip_before_authentication(client, monkeypatch):
    monkeypatch.setenv("OAUTH_RATE_LIMIT_PER_HOUR", "2")
    first = [client.get("/integrations/github/authorize").status_code for _ in range(2)]
    assert first == [401, 401]
    assert client.get("/integrations/github/authorize").status_code == 429  # even unauthenticated guessing is capped
    assert client.get("/integrations/github/callback", params={"state": "x"}).status_code == 429  # shared bucket


# ============================ webhook failure throttle ======================


def _sig_github(body, secret="s3cret"):
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _github(client, body=b"{}", sig=None, ip=None):
    headers = {"X-GitHub-Event": "ping", "X-Hub-Signature-256": sig or _sig_github(body)}
    if ip:
        headers["X-Forwarded-For"] = ip
    return client.post("/webhooks/github", content=body, headers=headers)


def test_repeated_bad_signatures_lock_an_ip_out_even_for_valid_ones(client, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s3cret")
    monkeypatch.setenv("WEBHOOK_FAIL_LIMIT_PER_HOUR", "3")

    assert [_github(client, sig="sha256=00").status_code for _ in range(3)] == [401, 401, 401]
    blocked = _github(client)  # a VALID delivery from the same IP
    assert blocked.status_code == 429 and "Retry-After" in blocked.headers
    assert _events("webhook_fail") == 3  # blocked requests are not counted again
    assert _github(client, ip="8.8.8.8").status_code == 200  # a different IP is fine


def test_successful_deliveries_never_count_against_the_limit(client, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s3cret")
    monkeypatch.setenv("WEBHOOK_FAIL_LIMIT_PER_HOUR", "2")
    assert all(_github(client).status_code == 200 for _ in range(10))
    assert _events("webhook_fail") == 0


def test_an_unconfigured_webhook_is_503_and_counts_nothing(client, monkeypatch):
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    for _ in range(5):
        assert _github(client).status_code == 503
    assert _events("webhook_fail") == 0


def test_all_three_webhooks_share_one_failure_budget(client, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s3cret")
    monkeypatch.setenv("BILLING_WEBHOOK_SECRET", "bs")
    monkeypatch.setenv("WHOP_WEBHOOK_SECRET", "ws_x")
    monkeypatch.setenv("WEBHOOK_FAIL_LIMIT_PER_HOUR", "3")

    assert _github(client, sig="sha256=00").status_code == 401
    assert client.post("/webhooks/billing", content=b"{}", headers={"X-Billing-Signature": "sha256=00"}).status_code == 401
    assert client.post("/webhooks/whop", content=b"{}", headers={"webhook-id": "x"}).status_code == 401

    for path in ("/webhooks/github", "/webhooks/billing", "/webhooks/whop"):
        assert client.post(path, content=b"{}").status_code == 429


def test_webhook_throttle_can_be_disabled(client, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s3cret")
    monkeypatch.setenv("WEBHOOK_FAIL_LIMIT_PER_HOUR", "0")
    assert all(_github(client, sig="sha256=00").status_code == 401 for _ in range(10))
    assert _events() == 0


def test_a_limits_json_sanity_check_of_the_signed_payload_path(client, monkeypatch):
    """A valid signed delivery still works normally alongside the gate."""
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s3cret")
    body = json.dumps({"zen": "hi"}).encode()
    resp = client.post(
        "/webhooks/github", content=body,
        headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": _sig_github(body)},
    )
    assert resp.status_code == 200 and resp.json() == {"ok": True}

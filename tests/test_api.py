"""API tests for the backend/persistence layer.

Uses a throwaway SQLite file per test session so tests never touch the
real DATABASE_URL, and monkeypatches `main.run_full_scan` so results are
deterministic instead of depending on a live clone/Semgrep/Gemini run.
"""
import os
import sys

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite:///./test_secure_vibecode.db")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

from backend import limits, main
from backend.db import Base, engine


FAKE_FINDINGS = [
    {
        "category": "missing_access_control",
        "label": "Row-Level Security not enabled",
        "file": "supabase migrations",
        "severity": "critical",
        "what_it_means": "No RLS policy on 'profiles'.",
        "why_it_matters": "Any user can read any row.",
        "fix_prompt": "Enable RLS and add a policy.",
    },
]

VALID_TARGET = "https://github.com/example/app"


def _scan_result(findings, platform="lovable", target=VALID_TARGET):
    return {"target": target, "platform": platform, "findings": findings}


@pytest.fixture(autouse=True)
def _fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def _deterministic_scan(monkeypatch):
    monkeypatch.setattr(main, "run_full_scan", lambda target: _scan_result(list(FAKE_FINDINGS)))


@pytest.fixture(autouse=True)
def _reset_limits(monkeypatch):
    limits.ip_limiter.reset()
    monkeypatch.delenv("SCAN_RATE_LIMIT_PER_HOUR", raising=False)
    monkeypatch.delenv("DAILY_SCAN_CAP", raising=False)
    yield
    limits.ip_limiter.reset()


@pytest.fixture()
def client():
    return TestClient(main.app)


def _create_scan(client, target=VALID_TARGET, owner_token=None):
    """Creates a scan and returns (finished_scan, owner_token). POST /scans
    only queues the job (202); TestClient runs the background task before
    returning, so a follow-up GET sees the finished scan. The token comes
    back on the X-Owner-Token response header, never in the JSON body."""
    headers = {"X-Owner-Token": owner_token} if owner_token else {}
    resp = client.post("/scans", json={"target": target}, headers=headers)
    assert resp.status_code == 202
    token = resp.headers["X-Owner-Token"]
    done = client.get(f"/scans/{resp.json()['id']}", headers={"X-Owner-Token": token})
    assert done.status_code == 200
    return done.json(), token


def _rescan(client, scan_id, token):
    resp = client.post(f"/scans/{scan_id}/rescan", headers={"X-Owner-Token": token})
    assert resp.status_code == 202
    done = client.get(f"/scans/{scan_id}", headers={"X-Owner-Token": token})
    return done.json()


def test_create_scan(client):
    body, token = _create_scan(client, target="https://github.com/example/lovable-app")
    assert body["target"] == "https://github.com/example/lovable-app"
    assert body["platform"] == "lovable"
    assert len(body["findings"]) == 1
    assert body["findings"][0]["category"] == "missing_access_control"
    assert body["findings"][0]["status"] == "open"
    assert token  # a token was minted
    assert "owner_token" not in body  # never leaked into the response body


def test_create_scan_reuses_supplied_owner_token(client):
    _, token = _create_scan(client, owner_token="my-existing-session-token")
    assert token == "my-existing-session-token"


def test_create_scan_invalid_target_url(client):
    resp = client.post("/scans", json={"target": "not-a-url"})
    assert resp.status_code == 422


def test_list_scans_returns_only_own_scans_newest_first(client):
    first, token = _create_scan(client, target="https://github.com/example/one")
    second, _ = _create_scan(client, target="https://github.com/example/two", owner_token=token)
    _create_scan(client, target="https://github.com/example/other-users")

    resp = client.get("/scans", headers={"X-Owner-Token": token})
    assert resp.status_code == 200
    ids = [s["id"] for s in resp.json()]
    assert ids == [second["id"], first["id"]]
    assert len(resp.json()[0]["findings"]) == 1


def test_list_scans_without_token_returns_empty_list(client):
    _create_scan(client)
    resp = client.get("/scans")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_scans_respects_limit_and_offset(client):
    _, token = _create_scan(client, target="https://github.com/example/a")
    _create_scan(client, target="https://github.com/example/b", owner_token=token)
    _create_scan(client, target="https://github.com/example/c", owner_token=token)

    resp = client.get("/scans?limit=1&offset=1", headers={"X-Owner-Token": token})
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    assert client.get("/scans?limit=0", headers={"X-Owner-Token": token}).status_code == 422


def test_get_scan_by_id(client):
    created, token = _create_scan(client)

    resp = client.get(f"/scans/{created['id']}", headers={"X-Owner-Token": token})
    assert resp.status_code == 200
    assert resp.json()["id"] == created["id"]
    assert len(resp.json()["findings"]) == 1


def test_get_scan_without_owner_token_returns_404(client):
    created, _ = _create_scan(client)

    resp = client.get(f"/scans/{created['id']}")
    assert resp.status_code == 404


def test_get_scan_with_wrong_owner_token_returns_404(client):
    created, _ = _create_scan(client)

    resp = client.get(f"/scans/{created['id']}", headers={"X-Owner-Token": "someone-elses-token"})
    assert resp.status_code == 404


def test_get_scan_not_found(client):
    resp = client.get("/scans/does-not-exist", headers={"X-Owner-Token": "anything"})
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


def test_create_scan_malformed_request(client):
    resp = client.post("/scans", json={})
    assert resp.status_code == 422


def test_create_scan_empty_target(client):
    resp = client.post("/scans", json={"target": ""})
    assert resp.status_code == 422


def test_rescan_resolves_missing_findings(client, monkeypatch):
    created, token = _create_scan(client)
    assert created["findings"][0]["status"] == "open"
    headers = {"X-Owner-Token": token}

    # Simulate the fix landing: the fresh scan now returns zero findings.
    monkeypatch.setattr(main, "run_full_scan", lambda target: _scan_result([]))

    body = _rescan(client, created["id"], token)
    assert len(body["findings"]) == 1
    assert body["findings"][0]["status"] == "resolved"


def test_rescan_keeps_still_present_findings_open(client, monkeypatch):
    created, token = _create_scan(client)
    headers = {"X-Owner-Token": token}

    # Nothing changed: the fresh scan returns the same finding again.
    monkeypatch.setattr(main, "run_full_scan", lambda target: _scan_result(list(FAKE_FINDINGS)))

    body = _rescan(client, created["id"], token)
    assert len(body["findings"]) == 1
    assert body["findings"][0]["status"] == "open"


def test_rescan_adds_newly_discovered_findings(client, monkeypatch):
    created, token = _create_scan(client)
    headers = {"X-Owner-Token": token}

    new_finding = {
        "category": "hardcoded_secret",
        "label": "Hardcoded API key",
        "file": "src/lib/config.ts",
        "severity": "high",
        "what_it_means": "A live API key is committed directly in source code.",
        "why_it_matters": "Anyone with repo access can use the key.",
        "fix_prompt": "Move the key to an environment variable.",
    }
    monkeypatch.setattr(
        main, "run_full_scan", lambda target: _scan_result([*FAKE_FINDINGS, new_finding])
    )

    body = _rescan(client, created["id"], token)
    assert len(body["findings"]) == 2
    categories = {f["category"] for f in body["findings"]}
    assert categories == {"missing_access_control", "hardcoded_secret"}


def test_rescan_not_found(client):
    resp = client.post("/scans/does-not-exist/rescan", headers={"X-Owner-Token": "anything"})
    assert resp.status_code == 404


def test_rescan_without_owner_token_returns_404(client):
    created, _ = _create_scan(client)
    resp = client.post(f"/scans/{created['id']}/rescan")
    assert resp.status_code == 404


def test_badge_fails_with_open_critical(client):
    created, token = _create_scan(client)

    resp = client.get(f"/scans/{created['id']}/badge", headers={"X-Owner-Token": token})
    assert resp.status_code == 200
    body = resp.json()
    assert body["passed"] is False
    assert body["open_critical"] == 1


def test_badge_passes_once_resolved(client, monkeypatch):
    created, token = _create_scan(client)
    headers = {"X-Owner-Token": token}
    monkeypatch.setattr(main, "run_full_scan", lambda target: _scan_result([]))
    _rescan(client, created["id"], token)

    resp = client.get(f"/scans/{created['id']}/badge", headers=headers)
    body = resp.json()
    assert body["passed"] is True
    assert body["open_critical"] == 0


def test_badge_not_found(client):
    resp = client.get("/scans/does-not-exist/badge", headers={"X-Owner-Token": "anything"})
    assert resp.status_code == 404


def test_badge_without_owner_token_returns_404(client):
    created, _ = _create_scan(client)
    resp = client.get(f"/scans/{created['id']}/badge")
    assert resp.status_code == 404


def test_create_scan_returns_queued_scan_without_waiting_for_results(client, monkeypatch):
    seen = {}

    def fake_scan(target):
        seen["called_with"] = target
        return _scan_result(list(FAKE_FINDINGS))

    monkeypatch.setattr(main, "run_full_scan", fake_scan)
    resp = client.post("/scans", json={"target": VALID_TARGET})

    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued"
    assert body["findings"] == []
    assert body["error"] is None
    assert seen["called_with"] == VALID_TARGET  # the job did run afterwards


def test_failed_scan_is_marked_failed_with_error(client, monkeypatch):
    def boom(target):
        raise RuntimeError("clone exploded")

    monkeypatch.setattr(main, "run_full_scan", boom)
    body, _ = _create_scan(client)

    assert body["status"] == "failed"
    assert "clone exploded" in body["error"]
    assert body["findings"] == []


def test_failed_rescan_keeps_existing_findings_and_records_error(client, monkeypatch):
    created, token = _create_scan(client)

    def boom(target):
        raise RuntimeError("semgrep timed out")

    monkeypatch.setattr(main, "run_full_scan", boom)
    body = _rescan(client, created["id"], token)

    assert body["status"] == "completed"
    assert "semgrep timed out" in body["error"]
    assert len(body["findings"]) == 1
    assert body["findings"][0]["status"] == "open"


def test_successful_rescan_clears_previous_error(client, monkeypatch):
    created, token = _create_scan(client)
    monkeypatch.setattr(main, "run_full_scan", lambda t: (_ for _ in ()).throw(RuntimeError("x")))
    assert _rescan(client, created["id"], token)["error"]

    monkeypatch.setattr(main, "run_full_scan", lambda t: _scan_result(list(FAKE_FINDINGS)))
    assert _rescan(client, created["id"], token)["error"] is None


def test_rescan_while_scan_in_progress_returns_409(client):
    created, token = _create_scan(client)
    with main.db.SessionLocal() as session:
        session.get(main.db.Scan, created["id"]).status = "running"
        session.commit()

    resp = client.post(f"/scans/{created['id']}/rescan", headers={"X-Owner-Token": token})
    assert resp.status_code == 409


def test_orphaned_jobs_are_failed_on_startup(client):
    created, token = _create_scan(client)
    with main.db.SessionLocal() as session:
        session.get(main.db.Scan, created["id"]).status = "running"
        session.commit()

    main._fail_orphaned_jobs()

    body = client.get(f"/scans/{created['id']}", headers={"X-Owner-Token": token}).json()
    assert body["status"] == "failed"
    assert "restart" in body["error"]


def test_per_ip_rate_limit_returns_429_with_retry_after(client, monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "2")
    for _ in range(2):
        assert client.post("/scans", json={"target": VALID_TARGET}).status_code == 202

    resp = client.post("/scans", json={"target": VALID_TARGET})
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) > 0
    assert "Too many scans" in resp.json()["detail"]


def test_rate_limit_is_per_client_ip_using_rightmost_forwarded_entry(client, monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "1")
    a = {"X-Forwarded-For": "6.6.6.6, 1.1.1.1"}  # leftmost is client-supplied, ignored
    b = {"X-Forwarded-For": "6.6.6.6, 2.2.2.2"}

    assert client.post("/scans", json={"target": VALID_TARGET}, headers=a).status_code == 202
    assert client.post("/scans", json={"target": VALID_TARGET}, headers=a).status_code == 429
    assert client.post("/scans", json={"target": VALID_TARGET}, headers=b).status_code == 202


def test_rate_limit_can_be_disabled(client, monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    for _ in range(15):
        assert client.post("/scans", json={"target": VALID_TARGET}).status_code == 202


def test_rescans_count_toward_the_rate_limit(client, monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "2")
    created, token = _create_scan(client)  # run 1
    resp = client.post(f"/scans/{created['id']}/rescan", headers={"X-Owner-Token": token})  # run 2
    assert resp.status_code == 202
    resp = client.post(f"/scans/{created['id']}/rescan", headers={"X-Owner-Token": token})
    assert resp.status_code == 429


def test_daily_cap_returns_503_and_counts_rescans(client, monkeypatch):
    monkeypatch.setenv("DAILY_SCAN_CAP", "2")
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    created, token = _create_scan(client)  # run 1
    assert client.post(f"/scans/{created['id']}/rescan", headers={"X-Owner-Token": token}).status_code == 202  # run 2

    resp = client.post("/scans", json={"target": VALID_TARGET})
    assert resp.status_code == 503
    assert int(resp.headers["Retry-After"]) > 0
    assert "capacity" in resp.json()["detail"]

    resp = client.post(f"/scans/{created['id']}/rescan", headers={"X-Owner-Token": token})
    assert resp.status_code == 503


def test_blocked_request_does_not_create_a_scan(client, monkeypatch):
    monkeypatch.setenv("DAILY_SCAN_CAP", "1")
    _, token = _create_scan(client)
    assert client.post("/scans", json={"target": VALID_TARGET}, headers={"X-Owner-Token": token}).status_code == 503
    assert len(client.get("/scans", headers={"X-Owner-Token": token}).json()) == 1


def test_public_badge_is_unauthenticated_and_shows_not_verified_with_open_criticals(client):
    created, _ = _create_scan(client)

    resp = client.get(f"/badge/{created['id']}.svg")  # no owner token
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("image/svg+xml")
    assert "not verified" in resp.text
    assert "critical" not in resp.text.lower().replace("secure-vibecode", "")  # no finding details leak


def test_public_badge_shows_verified_once_resolved(client, monkeypatch):
    created, token = _create_scan(client)
    monkeypatch.setattr(main, "run_full_scan", lambda target: _scan_result([]))
    _rescan(client, created["id"], token)

    resp = client.get(f"/badge/{created['id']}.svg")
    assert resp.status_code == 200
    assert ">verified<" in resp.text
    assert "#22c55e" in resp.text


def test_public_badge_is_not_verified_for_failed_scan(client, monkeypatch):
    monkeypatch.setattr(main, "run_full_scan", lambda t: (_ for _ in ()).throw(RuntimeError("x")))
    created, _ = _create_scan(client)
    assert created["status"] == "failed"

    assert "not verified" in client.get(f"/badge/{created['id']}.svg").text


def test_public_badge_unknown_scan_returns_404_svg(client):
    resp = client.get("/badge/does-not-exist.svg")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("image/svg+xml")
    assert "unknown" in resp.text


def _entropy_finding(score):
    return {
        "category": "hardcoded_secret",
        "label": f"High Entropy Secret (entropy: {score})",
        "file": "src/lib/auth.ts",
        "severity": "high",
        "what_it_means": "x",
        "why_it_matters": "y",
        "fix_prompt": "z",
    }


def test_rescan_matches_finding_whose_entropy_value_changed(client, monkeypatch):
    monkeypatch.setattr(main, "run_full_scan", lambda t: _scan_result([_entropy_finding("4.71")]))
    created, token = _create_scan(client)

    # Same secret location, slightly different entropy: still the same issue.
    monkeypatch.setattr(main, "run_full_scan", lambda t: _scan_result([_entropy_finding("4.90")]))
    body = _rescan(client, created["id"], token)

    assert len(body["findings"]) == 1
    assert body["findings"][0]["status"] == "open"


def test_rescan_tracks_each_table_separately(client, monkeypatch):
    def rls(table):
        return {**FAKE_FINDINGS[0], "table": table}

    monkeypatch.setattr(main, "run_full_scan", lambda t: _scan_result([rls("users"), rls("orders")]))
    created, token = _create_scan(client)
    assert len(created["findings"]) == 2

    # Only "orders" is fixed.
    monkeypatch.setattr(main, "run_full_scan", lambda t: _scan_result([rls("users")]))
    body = _rescan(client, created["id"], token)

    assert len(body["findings"]) == 2
    assert sorted(f["status"] for f in body["findings"]) == ["open", "resolved"]


def test_rescan_handles_rows_saved_before_fingerprints_existed(client, monkeypatch):
    created, token = _create_scan(client)
    with main.db.SessionLocal() as session:
        for f in session.get(main.db.Scan, created["id"]).findings:
            f.fingerprint = None
        session.commit()

    monkeypatch.setattr(main, "run_full_scan", lambda t: _scan_result([]))
    body = _rescan(client, created["id"], token)
    assert body["findings"][0]["status"] == "resolved"


def test_sentry_is_not_initialised_without_dsn(monkeypatch):
    import sentry_sdk

    calls = []
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.setattr(sentry_sdk, "init", lambda **kw: calls.append(kw))
    main._init_sentry()
    assert calls == []


def test_sentry_initialised_with_dsn_and_no_pii(monkeypatch):
    import sentry_sdk

    calls = []
    monkeypatch.setenv("SENTRY_DSN", "https://key@example.ingest.sentry.io/1")
    monkeypatch.setattr(sentry_sdk, "init", lambda **kw: calls.append(kw))
    main._init_sentry()
    assert calls[0]["dsn"] == "https://key@example.ingest.sentry.io/1"
    assert calls[0]["send_default_pii"] is False


def test_failed_scan_job_is_reported_to_sentry(client, monkeypatch):
    import sentry_sdk

    captured = []
    monkeypatch.setattr(sentry_sdk, "capture_exception", lambda exc: captured.append(exc))
    monkeypatch.setattr(main, "run_full_scan", lambda t: (_ for _ in ()).throw(RuntimeError("boom")))
    _create_scan(client)
    assert len(captured) == 1 and str(captured[0]) == "boom"


# --- commit-SHA skip -----------------------------------------------------------


def _with_sha(findings, sha):
    return {**_scan_result(findings), "commit_sha": sha, "unchanged": False}


def test_scan_stores_commit_sha(client, monkeypatch):
    monkeypatch.setattr(main, "run_full_scan", lambda t, **kw: _with_sha(list(FAKE_FINDINGS), "sha1"))
    created, _ = _create_scan(client)
    with main.db.SessionLocal() as session:
        assert session.get(main.db.Scan, created["id"]).commit_sha == "sha1"


def test_rescan_of_unchanged_commit_skips_scan_work_and_keeps_results(client, monkeypatch):
    monkeypatch.setattr(main, "run_full_scan", lambda t, **kw: _with_sha(list(FAKE_FINDINGS), "sha1"))
    created, token = _create_scan(client)

    seen = {}

    def unchanged(target, unchanged_since=None):
        seen["since"] = unchanged_since
        return {"target": target, "platform": None, "findings": [], "commit_sha": "sha1", "unchanged": True}

    monkeypatch.setattr(main, "run_full_scan", unchanged)
    body = _rescan(client, created["id"], token)

    assert seen["since"] == "sha1"
    assert body["status"] == "completed" and body["error"] is None
    # An empty "unchanged" result must NOT be read as "everything was fixed".
    assert [f["status"] for f in body["findings"]] == ["open"]


def test_rescan_after_new_commit_scans_and_updates_sha(client, monkeypatch):
    monkeypatch.setattr(main, "run_full_scan", lambda t, **kw: _with_sha(list(FAKE_FINDINGS), "sha1"))
    created, token = _create_scan(client)

    monkeypatch.setattr(main, "run_full_scan", lambda t, **kw: _with_sha([], "sha2"))
    body = _rescan(client, created["id"], token)

    assert body["findings"][0]["status"] == "resolved"
    with main.db.SessionLocal() as session:
        assert session.get(main.db.Scan, created["id"]).commit_sha == "sha2"


def test_rescan_is_a_real_retry_when_last_scan_was_incomplete(client, monkeypatch):
    incomplete = {
        "category": "scan_incomplete", "label": "Static analysis (Semgrep) did not complete", "file": "",
        "severity": "low", "what_it_means": "x", "why_it_matters": "y", "fix_prompt": "z",
    }
    monkeypatch.setattr(main, "run_full_scan", lambda t, **kw: _with_sha([incomplete], "sha1"))
    created, token = _create_scan(client)

    seen = {}

    def spy(target, **kw):
        seen["kwargs"] = kw
        return _with_sha([], "sha1")

    monkeypatch.setattr(main, "run_full_scan", spy)
    _rescan(client, created["id"], token)
    assert seen["kwargs"] == {}  # no unchanged_since, so the scan really runs


# --- GitHub webhook ------------------------------------------------------------

import hashlib
import hmac as _hmac
import json as _json

WEBHOOK_SECRET = "s3cret"


def _push(repo="example/app", ref="refs/heads/main", default_branch="main", url=None):
    return {
        "ref": ref,
        "repository": {
            "full_name": repo,
            "html_url": url or f"https://github.com/{repo}",
            "default_branch": default_branch,
        },
    }


def _post_hook(client, payload, event="push", secret=WEBHOOK_SECRET, signature=None):
    body = _json.dumps(payload).encode()
    sig = signature or "sha256=" + _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return client.post(
        "/webhooks/github",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": event, "Content-Type": "application/json"},
    )


@pytest.fixture()
def hook_secret(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", WEBHOOK_SECRET)


def test_webhook_is_disabled_without_a_configured_secret(client, monkeypatch):
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    assert _post_hook(client, _push()).status_code == 503


def test_webhook_rejects_bad_or_missing_signature(client, hook_secret):
    assert _post_hook(client, _push(), signature="sha256=deadbeef").status_code == 401
    assert _post_hook(client, _push(), secret="wrong-secret").status_code == 401
    resp = client.post("/webhooks/github", content=b"{}", headers={"X-GitHub-Event": "push"})
    assert resp.status_code == 401


def test_webhook_ping_and_non_push_events_are_acknowledged_without_scanning(client, hook_secret):
    assert _post_hook(client, {"zen": "hi"}, event="ping").json() == {"ok": True}
    assert _post_hook(client, _push(), event="issues").json()["triggered"] == 0


def test_webhook_rejects_malformed_push_payload(client, hook_secret):
    assert _post_hook(client, {"ref": "refs/heads/main"}).status_code == 400


def test_push_to_default_branch_rescans_matching_scan(client, hook_secret, monkeypatch):
    created, token = _create_scan(client, target="https://github.com/example/app")
    assert created["findings"][0]["status"] == "open"

    monkeypatch.setattr(main, "run_full_scan", lambda t, **kw: _scan_result([]))  # the fix landed
    resp = _post_hook(client, _push(repo="example/app"))

    assert resp.status_code == 200 and resp.json() == {"triggered": 1}
    body = client.get(f"/scans/{created['id']}", headers={"X-Owner-Token": token}).json()
    assert body["findings"][0]["status"] == "resolved"


def test_push_to_other_branch_or_other_repo_triggers_nothing(client, hook_secret):
    _create_scan(client, target="https://github.com/example/app")
    assert _post_hook(client, _push(ref="refs/heads/feature")).json()["triggered"] == 0
    assert _post_hook(client, _push(repo="example/unrelated")).json() == {"triggered": 0}


def test_webhook_matches_url_variants_and_only_latest_scan_per_owner(client, hook_secret):
    first, token = _create_scan(client, target="https://github.com/Example/App.git")
    second, _ = _create_scan(client, target="https://github.com/example/app/", owner_token=token)
    _, other_token = _create_scan(client, target="https://github.com/example/app")

    resp = _post_hook(client, _push(repo="example/app"))
    assert resp.json() == {"triggered": 2}  # newest scan of each of the two owners

    runs = []
    with main.db.SessionLocal() as session:
        runs = [r.scan_id for r in session.query(main.db.ScanRun).filter_by(kind="webhook")]
    assert first["id"] not in runs and second["id"] in runs
    assert other_token != token


def test_webhook_skips_scans_already_in_progress(client, hook_secret):
    created, _ = _create_scan(client, target="https://github.com/example/app")
    with main.db.SessionLocal() as session:
        session.get(main.db.Scan, created["id"]).status = "running"
        session.commit()
    assert _post_hook(client, _push()).json() == {"triggered": 0}


def test_webhook_respects_daily_cap_and_records_runs(client, hook_secret, monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    _create_scan(client, target="https://github.com/example/app")  # uses 1 of 1
    monkeypatch.setenv("DAILY_SCAN_CAP", "1")
    assert _post_hook(client, _push()).json() == {"triggered": 0}

    monkeypatch.setenv("DAILY_SCAN_CAP", "5")
    assert _post_hook(client, _push()).json() == {"triggered": 1}
    with main.db.SessionLocal() as session:
        assert session.query(main.db.ScanRun).filter_by(kind="webhook").count() == 1


# --- concurrency / resource regressions -----------------------------------------


def test_only_one_of_many_concurrent_rescans_is_accepted(client, monkeypatch):
    import threading
    import time

    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_HOUR", "0")
    created, token = _create_scan(client)

    runs = []

    def slow_scan(target, **kw):
        runs.append(target)
        time.sleep(0.5)
        return _scan_result(list(FAKE_FINDINGS))

    monkeypatch.setattr(main, "run_full_scan", slow_scan)

    codes, barrier = [], threading.Barrier(8)

    def hit():
        barrier.wait()
        codes.append(client.post(f"/scans/{created['id']}/rescan", headers={"X-Owner-Token": token}).status_code)

    threads = [threading.Thread(target=hit) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert sorted(codes) == [202] + [409] * 7
    assert len(runs) == 1
    with main.db.SessionLocal() as session:
        assert session.query(main.db.ScanRun).filter_by(kind="rescan").count() == 1


def test_claim_scan_for_rescan_is_exclusive(client):
    created, _ = _create_scan(client)
    with main.db.SessionLocal() as session:
        assert main._claim_scan_for_rescan(session, created["id"]) is True
        session.commit()
    with main.db.SessionLocal() as session:
        assert main._claim_scan_for_rescan(session, created["id"]) is False


def test_rate_limiter_forgets_idle_addresses(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(limits.time, "monotonic", lambda: clock["now"])
    limiter = limits.SlidingWindowLimiter(window_seconds=60)

    for i in range(499):
        limiter.check(f"ip-{i}", limit=5)
    assert len(limiter._hits) == 499

    clock["now"] += 61  # every earlier address is now idle
    limiter.check("fresh-ip", limit=5)  # 500th call triggers the sweep
    assert set(limiter._hits) == {"fresh-ip"}

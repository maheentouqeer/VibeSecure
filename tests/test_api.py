"""API tests for the backend/persistence layer.

Uses a throwaway SQLite file per test session so tests never touch the
real DATABASE_URL, and monkeypatches `main.run_full_scan` so results are
deterministic instead of depending on a live clone/Semgrep/Gemini run.
"""
import os
import sys

os.environ["DATABASE_URL"] = "sqlite:///./test_secure_vibecode.db"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

from backend import main
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


@pytest.fixture()
def client():
    return TestClient(main.app)


def _create_scan(client, target=VALID_TARGET, owner_token=None):
    """Creates a scan and returns (body, owner_token) -- the token comes
    back on the X-Owner-Token response header, never in the JSON body."""
    headers = {"X-Owner-Token": owner_token} if owner_token else {}
    resp = client.post("/scans", json={"target": target}, headers=headers)
    assert resp.status_code == 201
    return resp.json(), resp.headers["X-Owner-Token"]


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

    resp = client.post(f"/scans/{created['id']}/rescan", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["findings"]) == 1
    assert body["findings"][0]["status"] == "resolved"


def test_rescan_keeps_still_present_findings_open(client, monkeypatch):
    created, token = _create_scan(client)
    headers = {"X-Owner-Token": token}

    # Nothing changed: the fresh scan returns the same finding again.
    monkeypatch.setattr(main, "run_full_scan", lambda target: _scan_result(list(FAKE_FINDINGS)))

    resp = client.post(f"/scans/{created['id']}/rescan", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
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

    resp = client.post(f"/scans/{created['id']}/rescan", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
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
    client.post(f"/scans/{created['id']}/rescan", headers=headers)

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

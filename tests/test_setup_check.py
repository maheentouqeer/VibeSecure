"""The setup checker: it must flag real misconfigurations, stay quiet about
optional features, and never print a secret."""
import json
import os

import pytest
import requests
from cryptography.fernet import Fernet

from backend import setup_check
from backend.setup_check import run_checks


def _env_with(extra):
    """A minimal environment that still has what git/semgrep lookups need (PATH etc.)."""
    keep = {k: v for k, v in os.environ.items() if k.upper() in ("PATH", "SYSTEMROOT", "PATHEXT", "HOME", "USERPROFILE")}
    return {**keep, **extra}


def _by_name(results):
    out = {}
    for r in results:
        out.setdefault(r.name, []).append(r)
    return out


def _status(results, name):
    return [r.status for r in results if r.name == name]


GOOD = {
    "DATABASE_URL": "postgresql+psycopg2://u:p@host/db",
    "ALLOWED_ORIGINS": "https://app.example.test",
    "FRONTEND_URL": "https://app.example.test",
    "SUPABASE_JWKS_URL": "https://project-ref.supabase.test/auth/v1/.well-known/jwks.json",
    "SUPABASE_URL": "https://project-ref.supabase.test",
    "SUPABASE_AUTHORIZED_PARTIES": "https://app.example.test",
    "GITHUB_OAUTH_CLIENT_ID": "cid",
    "GITHUB_OAUTH_CLIENT_SECRET": "csecret",
    "GITHUB_OAUTH_REDIRECT_URI": "https://api.example.test/integrations/github/callback",
    "TOKEN_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "WHOP_WEBHOOK_SECRET": "ws_abc123",
    "WHOP_PLAN_MAP": json.dumps({"plan_pro": "pro", "plan_team": "team"}),
    "WHOP_API_KEY": "whop_key_value",
    "ADMIN_API_KEY": "a" * 40,
    "SENTRY_DSN": "https://publickey@o1.ingest.sentry.io/123",
    "GEMINI_API_KEY": "gemkey-Zx9-unique-value",
    "ENFORCE_PLAN_LIMITS": "1",
}


def test_a_complete_configuration_has_no_failures_and_no_config_warnings():
    results = run_checks(GOOD)
    assert not [r for r in results if r.status == "FAIL"]
    warned = {r.name for r in results if r.status == "WARN"}
    assert warned <= {"semgrep", "git"}  # only local tooling, which depends on the machine running the check


def test_an_empty_environment_is_skips_and_warnings_not_failures():
    results = run_checks({})
    assert not [r for r in results if r.status == "FAIL"]
    assert _status(results, "supabase sign-in") == ["SKIP"] and _status(results, "whop billing") == ["SKIP"]
    assert _status(results, "database") == ["WARN"]


@pytest.mark.parametrize(
    "env, name, expected",
    [
        ({"DATABASE_URL": "mysql://x"}, "database", "FAIL"),
        ({"DATABASE_URL": "sqlite:///x.db"}, "database", "WARN"),
        ({"ALLOWED_ORIGINS": "http://localhost:3000"}, "cors", "WARN"),
        ({"SUPABASE_JWKS_URL": "http://project.test/jwks.json"}, "supabase jwks url", "FAIL"),
        ({"SUPABASE_JWKS_URL": "https://project.test/jwks.json"}, "supabase url", "WARN"),
        ({"SUPABASE_JWKS_URL": "https://project.test/jwks.json"}, "supabase authorized parties", "WARN"),
        ({"ADMIN_API_KEY": "short"}, "admin api", "FAIL"),
        ({"RATE_LIMIT_STORE": "redis"}, "rate limit store", "FAIL"),
        ({"SCAN_WORKER_MODE": "nonsense"}, "workers", "FAIL"),
        ({"SCAN_WORKER_MODE": "external"}, "workers", "WARN"),
        ({"SENTRY_DSN": "not-a-dsn"}, "sentry", "FAIL"),
        ({"GITHUB_TOKEN": "ghp_x"}, "server github token", "WARN"),
    ],
)
def test_single_misconfigurations_are_flagged(env, name, expected):
    assert expected in _status(run_checks(env), name)


def test_github_oauth_partly_configured_is_a_failure_that_names_what_is_missing():
    results = run_checks({"GITHUB_OAUTH_CLIENT_ID": "x", "GITHUB_OAUTH_REDIRECT_URI": "https://a.test/cb"})
    fail = next(r for r in results if r.name == "github private repos")
    assert fail.status == "FAIL"
    assert "GITHUB_OAUTH_CLIENT_SECRET" in fail.detail and "TOKEN_ENCRYPTION_KEY" in fail.detail


def test_an_invalid_encryption_key_and_an_insecure_redirect_are_failures():
    env = {**GOOD, "TOKEN_ENCRYPTION_KEY": "not-fernet", "GITHUB_OAUTH_REDIRECT_URI": "http://api.example.test/cb"}
    results = run_checks(env)
    assert _status(results, "token encryption key") == ["FAIL"]
    assert _status(results, "github redirect uri") == ["FAIL"]


def test_a_redirect_uri_with_the_wrong_path_is_warned_about():
    env = {**GOOD, "GITHUB_OAUTH_REDIRECT_URI": "https://api.example.test/somewhere/else"}
    assert _status(run_checks(env), "github redirect uri") == ["WARN"]


@pytest.mark.parametrize(
    "plan_map, name, expected",
    [
        ("not json", "whop plan map", "FAIL"),
        ("{}", "whop plan map", "FAIL"),
        (json.dumps({"plan_x": "enterprise"}), "whop plan map", "FAIL"),
        (json.dumps({"prod_only": "pro", "prod_t": "team"}), "whop checkout (pro)", "WARN"),
        (json.dumps({"plan_pro": "pro"}), "whop checkout (team)", "WARN"),
        (json.dumps({"plan_pro": "pro", "plan_team": "team"}), "whop plan map", "OK"),
    ],
)
def test_whop_plan_map_problems(plan_map, name, expected):
    env = {"WHOP_WEBHOOK_SECRET": "ws_x", "WHOP_PLAN_MAP": plan_map}
    assert expected in _status(run_checks(env), name)


def test_whop_secret_problems():
    assert _status(run_checks({"WHOP_PLAN_MAP": '{"plan_a":"pro"}'}), "whop webhook secret") == ["FAIL"]
    assert _status(run_checks({"WHOP_WEBHOOK_SECRET": "abc", "WHOP_PLAN_MAP": '{"plan_a":"pro"}'}), "whop webhook secret") == ["WARN"]


# ================================== live checks =============================


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body
        self.ok = 200 <= status < 300

    def json(self):
        if self._body is None:
            raise ValueError
        return self._body


def _patch_get(monkeypatch, handler):
    monkeypatch.setattr(setup_check.requests, "get", handler)


def test_live_supabase_auth_reports_the_number_of_signing_keys(monkeypatch):
    _patch_get(monkeypatch, lambda url, **kw: _Resp(200, {"keys": [{"kid": "a"}, {"kid": "b"}]}))
    assert run_checks(GOOD, live=True) and _status(run_checks(GOOD, live=True), "supabase jwks (live)") == ["OK"]


@pytest.mark.parametrize(
    "resp", [_Resp(404, {"error": "no"}), _Resp(200, {"keys": []}), _Resp(200, None), requests.ConnectionError("down")]
)
def test_live_supabase_auth_failures(monkeypatch, resp):
    def get(url, **kw):
        if isinstance(resp, Exception):
            raise resp
        return resp

    _patch_get(monkeypatch, get)
    assert _status(run_checks(GOOD, live=True), "supabase jwks (live)") == ["FAIL"]


@pytest.mark.parametrize("status, expected", [(200, "OK"), (401, "FAIL"), (403, "WARN"), (500, "WARN")])
def test_live_whop_key_statuses(monkeypatch, status, expected):
    seen = {}

    def get(url, **kw):
        seen["url"], seen["headers"] = url, kw.get("headers")
        return _Resp(status, {"keys": [1]} if "jwks" in url else {})

    _patch_get(monkeypatch, get)
    results = run_checks(GOOD, live=True)
    assert _status(results, "whop api key (live)") == [expected]


def test_the_live_whop_check_is_read_only(monkeypatch):
    methods = []
    monkeypatch.setattr(setup_check.requests, "get", lambda url, **kw: methods.append("GET") or _Resp(200, {"keys": [1]}))
    monkeypatch.setattr(setup_check.requests, "post", lambda *a, **k: methods.append("POST") or _Resp(200, {}))
    run_checks(GOOD, live=True)
    assert "POST" not in methods


def test_live_whop_network_failure(monkeypatch):
    def get(url, **kw):
        if "whop" in url:
            raise requests.ConnectionError("down")
        return _Resp(200, {"keys": [1]})

    _patch_get(monkeypatch, get)
    assert _status(run_checks(GOOD, live=True), "whop api key (live)") == ["FAIL"]


def test_api_checks_report_readiness_problems(monkeypatch):
    def get(url, **kw):
        if url.endswith("/healthz"):
            return _Resp(200, {"status": "ok"})
        return _Resp(503, {"problems": ["database migrations are at '0009', expected '0013'"]})

    _patch_get(monkeypatch, get)
    results = run_checks({}, api="https://api.example.test/")
    assert _status(results, "api /healthz") == ["OK"]
    ready = next(r for r in results if r.name == "api /readyz")
    assert ready.status == "FAIL" and "migrations" in ready.detail


def test_nothing_touches_the_network_without_the_flags(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network call without --live/--api")

    monkeypatch.setattr(setup_check.requests, "get", boom)
    monkeypatch.setattr(setup_check.requests, "post", boom)
    run_checks(GOOD)


# ============================ output & exit code ============================


def test_secrets_are_never_printed(monkeypatch, capsys):
    monkeypatch.setattr(setup_check.os, "environ", _env_with(GOOD))
    setup_check.main([])
    printed = capsys.readouterr().out
    for name in ("TOKEN_ENCRYPTION_KEY", "GITHUB_OAUTH_CLIENT_SECRET", "WHOP_WEBHOOK_SECRET", "WHOP_API_KEY", "ADMIN_API_KEY", "GEMINI_API_KEY"):
        assert GOOD[name] not in printed, f"{name} leaked into the output"
    assert "publickey" not in printed  # the Sentry DSN key


def test_exit_code_is_nonzero_only_when_something_fails(monkeypatch, capsys):
    monkeypatch.setattr(setup_check.os, "environ", _env_with({}))
    assert setup_check.main([]) == 0
    monkeypatch.setattr(setup_check.os, "environ", _env_with({"ADMIN_API_KEY": "short"}))
    assert setup_check.main([]) == 1
    assert "1 failures" in capsys.readouterr().out


def test_server_github_token_states_are_described_accurately():
    def state(**env):
        return next(r for r in run_checks(env) if r.name == "server github token")

    assert state().status == "OK"
    ignored = state(GITHUB_TOKEN="x")
    assert ignored.status == "WARN" and "IGNORED" in ignored.detail
    wide = state(GITHUB_TOKEN="x", ALLOW_SERVER_GITHUB_TOKEN="1")
    assert wide.status == "WARN" and "EVERY repository" in wide.detail
    limited = state(GITHUB_TOKEN="x", ALLOW_SERVER_GITHUB_TOKEN="1", SERVER_GITHUB_TOKEN_OWNERS="my-org, me")
    assert limited.status == "OK" and "my-org" in limited.detail
    assert state(GITHUB_PAT="x").status == "WARN"


@pytest.mark.parametrize(
    "env, name, expected",
    [
        ({}, "scan concurrency", "OK"),
        ({"SCAN_CONCURRENCY": "4"}, "scan concurrency", "OK"),
        ({"SCAN_CONCURRENCY": "20"}, "scan concurrency", "WARN"),
        ({"SCAN_CONCURRENCY": "abc"}, "scan concurrency", "WARN"),
        ({"SCAN_CONCURRENCY": "0"}, "scan concurrency", "WARN"),
        ({}, "db pool", "OK"),
        ({"DB_POOL_SIZE": "5", "DB_MAX_OVERFLOW": "5"}, "db pool", "WARN"),
        ({"DB_POOL_SIZE": "60", "DB_MAX_OVERFLOW": "40"}, "db pool", "WARN"),
    ],
)
def test_capacity_settings_are_checked(env, name, expected):
    assert _status(run_checks(env), name) == [expected]

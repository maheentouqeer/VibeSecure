"""Security/robustness tests for the scanner layer: SSRF guard, Semgrep path
handling, and entropy false positives."""
import json
import os
import socket
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import requests

import orchestrator
from scanner import code_scanner, live_scanner, url_safety
from scanner.secrets_scanner import scan_secrets
from scanner.url_safety import UnsafeTargetError, assert_public_url

PUBLIC_IP = "93.184.216.34"


def _fake_dns(mapping):
    def getaddrinfo(host, port, *a, **k):
        if host in mapping:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], port))]
        raise socket.gaierror(f"no such host {host}")

    return getaddrinfo


@pytest.fixture(autouse=True)
def _no_escape_hatch(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost:8000/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.1.2.3/",
        "http://192.168.0.10/",
        "http://172.16.5.5/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "ftp://example.com/",
        "file:///etc/passwd",
        "http:///nohost",
    ],
)
def test_unsafe_targets_are_rejected(url):
    with pytest.raises(UnsafeTargetError):
        assert_public_url(url)


def test_public_host_is_allowed(monkeypatch):
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _fake_dns({"ok.test": PUBLIC_IP}))
    assert_public_url("https://ok.test/app")


def test_host_resolving_to_any_private_address_is_rejected(monkeypatch):
    def mixed(host, port, *a, **k):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),
        ]

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", mixed)
    with pytest.raises(UnsafeTargetError):
        assert_public_url("https://sneaky.test/")


def test_escape_hatch_allows_private_targets_for_local_dev(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    assert_public_url("http://127.0.0.1:3000/")


def test_run_full_scan_refuses_internal_targets_before_doing_any_work(monkeypatch):
    def must_not_run(*a, **k):
        raise AssertionError("scan work started for an unsafe target")

    monkeypatch.setattr(orchestrator, "_run_repo_scan", must_not_run)
    monkeypatch.setattr(orchestrator, "scan_live_url", must_not_run)
    with pytest.raises(UnsafeTargetError):
        orchestrator.run_full_scan("http://169.254.169.254/latest/meta-data/")


class _FakeSession:
    """Stands in for safe_session(); the address-level checks are tested in test_dns_rebinding.py."""

    def __init__(self, get):
        self.get = get

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Resp:
    def __init__(self, status=200, headers=None, body=b""):
        self.status_code = status
        self.headers = headers or {}
        self.is_redirect = status in (301, 302, 307, 308)
        self._content = b""

        class Raw:
            def read(_self, n, decode_content=True):
                return body[:n]

        self.raw = Raw()

    @property
    def text(self):
        return self._content.decode()

    def close(self):
        pass


def test_redirect_to_internal_address_is_blocked(monkeypatch):
    monkeypatch.setattr(
        url_safety.socket, "getaddrinfo", _fake_dns({"pub.test": PUBLIC_IP, "internal.test": "127.0.0.1"})
    )
    fetched = []

    def fake_get(url, **kw):
        fetched.append(url)
        assert kw["allow_redirects"] is False
        return _Resp(302, {"Location": "http://internal.test/admin"})

    monkeypatch.setattr(live_scanner, "safe_session", lambda: _FakeSession(fake_get))
    with pytest.raises(UnsafeTargetError):
        live_scanner._safe_get("http://pub.test/")
    assert fetched == ["http://pub.test/"]  # the internal hop was never requested


def test_safe_get_follows_public_redirects_and_caps_body(monkeypatch):
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _fake_dns({"a.test": PUBLIC_IP, "b.test": PUBLIC_IP}))
    big = b"x" * (live_scanner.MAX_BODY_BYTES + 5000)

    def fake_get(url, **kw):
        if url.startswith("http://a.test"):
            return _Resp(301, {"Location": "https://b.test/final"})
        return _Resp(200, {"Content-Security-Policy": "default-src 'self'"}, big)

    monkeypatch.setattr(live_scanner, "safe_session", lambda: _FakeSession(fake_get))
    resp = live_scanner._safe_get("http://a.test/")
    assert resp.status_code == 200
    assert len(resp.text) == live_scanner.MAX_BODY_BYTES


def test_redirect_loop_is_bounded(monkeypatch):
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _fake_dns({"loop.test": PUBLIC_IP}))
    monkeypatch.setattr(live_scanner, "safe_session", lambda: _FakeSession(lambda url, **kw: _Resp(302, {"Location": "http://loop.test/"})))
    with pytest.raises(requests.TooManyRedirects):
        live_scanner._safe_get("http://loop.test/")


def test_scan_live_url_swallows_unsafe_redirect_instead_of_crashing(monkeypatch):
    monkeypatch.setattr(
        url_safety.socket, "getaddrinfo", _fake_dns({"pub.test": PUBLIC_IP, "internal.test": "127.0.0.1"})
    )
    monkeypatch.setattr(live_scanner, "safe_session", lambda: _FakeSession(lambda url, **kw: _Resp(302, {"Location": "http://internal.test/"})))
    assert live_scanner.scan_live_url("http://pub.test") == []


# --- Semgrep path handling -------------------------------------------------


def _semgrep_output(paths):
    return json.dumps(
        {
            "results": [
                {"check_id": "rule.x", "path": p, "start": {"line": 3}, "extra": {"message": "m", "severity": "ERROR"}}
                for p in paths
            ]
        }
    )


def test_semgrep_path_outside_repo_does_not_crash_the_scan(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "elsewhere" / "a.py"
    inside = repo / "src" / "b.py"
    monkeypatch.setattr(
        code_scanner.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a, 0, stdout=_semgrep_output([str(outside), str(inside)]), stderr=""
        ),
    )
    findings = code_scanner.run_semgrep(repo)
    assert len(findings) == 2
    assert findings[1]["file"] == "src/b.py"
    assert findings[0]["file"]  # something sensible, not an exception


def test_semgrep_missing_path_becomes_empty_string(monkeypatch, tmp_path):
    monkeypatch.setattr(
        code_scanner.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a, 0, stdout=json.dumps({"results": [{"check_id": "r", "extra": {}}]}), stderr=""
        ),
    )
    assert code_scanner.run_semgrep(tmp_path)[0]["file"] == ""


# --- entropy false positives ----------------------------------------------

SHA512 = "sha512-" + "Zk3Qv9Yc1LmT7wP2xR8nB5dF6gH0jK4aS+/uEoIiVtNyMbCqXhAlWzDrOfGePsU=="


def _write(repo, rel, text):
    f = repo / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


def test_lockfiles_and_integrity_hashes_produce_no_findings(tmp_path):
    _write(tmp_path, "package-lock.json", json.dumps({"packages": {"x": {"integrity": SHA512}}}))
    _write(tmp_path, "dist.min.js", f'var a = "{SHA512}";')
    _write(tmp_path, "src/deps.json", json.dumps({"integrity": SHA512}))
    _write(
        tmp_path,
        "src/ids.ts",
        'const a = "3f786850e387550fdab836ed7e6dc881de23001b";\n'
        'const id = "123e4567-e89b-12d3-a456-426614174000";',
    )
    assert scan_secrets(tmp_path) == []


def test_real_high_entropy_secret_is_still_detected(tmp_path):
    _write(tmp_path, "src/lib/auth.ts", "const secret = 'Tf8$kR2!vQ9#nJ4@xW7&hL3%bM6*';")
    _write(tmp_path, "src/config/aws.ts", "const key = 'AKIA1234567890ABCDEF';")
    labels = sorted(f["label"] for f in scan_secrets(tmp_path))
    assert any(label.startswith("High Entropy Secret") for label in labels)
    assert "AWS Access Key" in labels

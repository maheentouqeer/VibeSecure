"""DNS-rebinding and address-smuggling protection, tested with real sockets.

The attack: a hostname whose DNS answers "public" to the pre-flight check and
"127.0.0.1" to the connection. A local server stands in for the internal
service; the protection holds if it never sees a connection."""
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import threading

import pytest
import requests

from scanner import repo_utils, url_safety
from scanner.live_scanner import _safe_get
from scanner.url_safety import (
    UnsafeTargetError, assert_public_url, git_pin_env, is_public_address, pin_config, safe_session,
)

PUBLIC = "93.184.216.34"


@pytest.fixture(autouse=True)
def _strict(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(var, raising=False)


class InternalService:
    """A real TCP listener on loopback that records every connection it receives."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.hits = 0
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.hits += 1
            try:
                conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nSECRET")
            finally:
                conn.close()

    def close(self):
        self._stop = True
        self.sock.close()


@pytest.fixture()
def internal():
    service = InternalService()
    yield service
    service.close()


def _rebinding_resolver(first, then):
    """DNS that answers `first` once, then `then` forever (the rebinding trick)."""
    calls = {"n": 0}
    real = socket.getaddrinfo

    def resolver(host, port, *a, **k):
        if host != "rebind.test":
            return real(host, port, *a, **k)
        calls["n"] += 1
        ip = first if calls["n"] == 1 else then
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    return resolver, calls


# ============================ address classification ========================


@pytest.mark.parametrize(
    "address, public",
    [
        ("93.184.216.34", True), ("8.8.8.8", True), ("1.1.1.1", True),
        ("2606:4700:4700::1111", True), ("::ffff:8.8.8.8", True),
        ("127.0.0.1", False), ("127.255.255.254", False), ("10.0.0.1", False), ("172.16.0.1", False),
        ("192.168.1.1", False), ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False),
        ("255.255.255.255", False), ("224.0.0.1", False), ("192.0.2.1", False),
        ("::1", False), ("::", False), ("fe80::1", False), ("fc00::1", False), ("ff02::1", False),
        # IPv4 addresses smuggled inside IPv6 ones
        ("::ffff:127.0.0.1", False), ("::ffff:169.254.169.254", False), ("::ffff:10.0.0.1", False),
        ("64:ff9b::7f00:1", False), ("64:ff9b::a00:1", False), ("64:ff9b::808:808", True),
        ("2002:7f00:1::", False), ("2002:a9fe:a9fe::", False), ("2002:808:808::", True),
    ],
)
def test_address_classification(address, public):
    assert is_public_address(ipaddress.ip_address(address)) is public


def test_numeric_encodings_of_loopback_are_refused_without_special_parsing(internal):
    for host in ("2130706433", "0x7f000001", "0177.0.0.1", "127.1"):
        with pytest.raises((UnsafeTargetError, requests.RequestException, OSError)):
            _safe_get(f"http://{host}:{internal.port}/")
    assert internal.hits == 0


# ================================ the attack ================================


def test_the_old_two_step_approach_really_was_vulnerable(internal, monkeypatch):
    """Control: check-then-connect with two separate resolutions reaches the internal service."""
    resolver, _ = _rebinding_resolver(PUBLIC, "127.0.0.1")
    monkeypatch.setattr(socket, "getaddrinfo", resolver)

    assert_public_url(f"http://rebind.test:{internal.port}/")  # resolution 1: public, passes
    resp = requests.get(f"http://rebind.test:{internal.port}/", timeout=5)  # resolution 2: 127.0.0.1

    assert resp.text == "SECRET" and internal.hits == 1


def test_rebinding_is_blocked_at_connection_time(internal, monkeypatch):
    resolver, calls = _rebinding_resolver(PUBLIC, "127.0.0.1")
    monkeypatch.setattr(socket, "getaddrinfo", resolver)

    with pytest.raises(UnsafeTargetError):
        _safe_get(f"http://rebind.test:{internal.port}/")

    assert calls["n"] >= 2  # it really did get the second, hostile answer
    assert internal.hits == 0  # ...and never connected


def test_a_host_with_one_private_address_among_public_ones_is_refused(internal, monkeypatch):
    def resolver(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in (PUBLIC, "127.0.0.1")]

    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    with pytest.raises(UnsafeTargetError):
        safe_session().get(f"http://mixed.test:{internal.port}/", timeout=5)
    assert internal.hits == 0


def test_rebinding_via_an_ipv4_mapped_ipv6_answer_is_blocked(internal, monkeypatch):
    def resolver(host, port, *a, **k):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", port, 0, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    with pytest.raises(UnsafeTargetError):
        safe_session().get(f"http://mapped.test:{internal.port}/", timeout=5)
    assert internal.hits == 0


def test_an_internal_redirect_target_is_blocked_at_the_connection_too(internal, monkeypatch):
    """Even if the pre-flight check were skipped for a hop, the socket layer refuses."""
    monkeypatch.setattr(url_safety, "assert_public_url", lambda url: None)
    monkeypatch.setattr("scanner.live_scanner.assert_public_url", lambda url: None)
    with pytest.raises(UnsafeTargetError):
        _safe_get(f"http://127.0.0.1:{internal.port}/")
    assert internal.hits == 0


def test_an_environment_proxy_cannot_be_used_to_skip_the_checks(internal, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{internal.port}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{internal.port}")
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, port))])

    session = safe_session()
    assert session.trust_env is False
    # the request targets a public address (which we can't reach in a test), never the "proxy":
    with pytest.raises(requests.RequestException):
        session.get("http://public.test/", timeout=0.3)
    assert internal.hits == 0


# ========================= normal operation still works =====================


def test_requests_work_normally_when_private_targets_are_allowed(internal, monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    resp = _safe_get(f"http://127.0.0.1:{internal.port}/")
    assert resp.status_code == 200 and resp.text == "SECRET" and internal.hits == 1


def test_connection_errors_still_surface_as_ordinary_request_errors(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()  # nothing is listening here now
    with pytest.raises(requests.ConnectionError):
        safe_session().get(f"http://127.0.0.1:{port}/", timeout=2)


def test_unresolvable_hosts_are_a_clean_error():
    with pytest.raises((requests.ConnectionError, UnsafeTargetError)):
        safe_session().get("http://definitely-not-a-real-host.invalid/", timeout=3)


# =============================== git pinning ================================


def _resolver_for(host, addresses):
    def resolver(h, port, *a, **k):
        if h != host:
            raise socket.gaierror("unexpected lookup " + h)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in addresses]

    return resolver


def test_git_pin_env_pins_the_validated_addresses(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_for("repo.test", [PUBLIC, "8.8.8.8", PUBLIC]))
    env = git_pin_env("https://repo.test/owner/repo.git", {"PATH": "x"})
    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "http.curloptResolve"
    assert env["GIT_CONFIG_VALUE_0"] == f"repo.test:443:{PUBLIC},8.8.8.8"  # de-duplicated, order kept
    assert env["PATH"] == "x"


def test_git_pin_env_uses_the_explicit_port_and_default_http_port(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_for("repo.test", [PUBLIC]))
    assert git_pin_env("http://repo.test/r.git", {})["GIT_CONFIG_VALUE_0"] == f"repo.test:80:{PUBLIC}"
    assert git_pin_env("https://repo.test:8443/r.git", {})["GIT_CONFIG_VALUE_0"] == f"repo.test:8443:{PUBLIC}"


def test_git_pin_env_appends_to_existing_git_config_instead_of_clobbering_it(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_for("repo.test", [PUBLIC]))
    base = {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "a.b", "GIT_CONFIG_VALUE_0": "1",
            "GIT_CONFIG_KEY_1": "c.d", "GIT_CONFIG_VALUE_1": "2"}
    env = git_pin_env("https://repo.test/r.git", base)
    assert env["GIT_CONFIG_COUNT"] == "3" and env["GIT_CONFIG_KEY_2"] == "http.curloptResolve"
    assert env["GIT_CONFIG_KEY_0"] == "a.b" and env["GIT_CONFIG_VALUE_1"] == "2"
    assert "GIT_CONFIG_COUNT" not in {} and base["GIT_CONFIG_COUNT"] == "2"  # the caller's dict is untouched


def test_git_pin_env_refuses_hosts_that_resolve_internally(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_for("evil.test", ["127.0.0.1"]))
    with pytest.raises(UnsafeTargetError):
        git_pin_env("https://evil.test/r.git", {})
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_for("mixed.test", [PUBLIC, "10.0.0.5"]))
    with pytest.raises(UnsafeTargetError):
        git_pin_env("https://mixed.test/r.git", {})


def test_git_pin_env_leaves_ip_literals_and_dev_mode_alone(monkeypatch):
    assert git_pin_env("https://93.184.216.34/r.git", {"A": "1"}) == {"A": "1"}
    assert git_pin_env("https://[2606:4700:4700::1111]/r.git", {"A": "1"}) == {"A": "1"}
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    assert git_pin_env("https://anything.test/r.git", {"A": "1"}) == {"A": "1"}


def test_clone_repo_pins_dns_and_refuses_internal_hosts_without_leaving_files(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        repo_utils.git.Repo, "clone_from",
        staticmethod(lambda url, to_path, depth, env: captured.update(env=env, url=url)),
    )
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_for("repo.test", [PUBLIC]))
    repo_utils.cleanup(repo_utils.clone_repo("https://repo.test/owner/repo.git"))
    assert captured["env"]["GIT_CONFIG_VALUE_0"] == f"repo.test:443:{PUBLIC}"

    before = {d for d in os.listdir(tempfile.gettempdir()) if d.startswith("svc_scan_")}
    captured.clear()
    monkeypatch.setattr(socket, "getaddrinfo", _resolver_for("evil.test", ["169.254.169.254"]))
    with pytest.raises(UnsafeTargetError):
        repo_utils.clone_repo("https://evil.test/owner/repo.git")
    assert captured == {}  # git was never even started
    assert {d for d in os.listdir(tempfile.gettempdir()) if d.startswith("svc_scan_")} == before


def _git_version():
    out = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
    return tuple(int(x) for x in re.findall(r"(\d+)\.(\d+)", out)[0])


@pytest.mark.skipif(_git_version() < (2, 37), reason="http.curloptResolve needs git >= 2.37")
def test_real_git_honours_the_pin_format_we_generate(internal):
    """The hostname does not exist in DNS; only the pin can make git reach the local server."""
    seen = []
    original = internal._serve

    key, value = pin_config("pinned.invalid", internal.port, ["127.0.0.1"])
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "1",
           "GIT_CONFIG_KEY_0": key, "GIT_CONFIG_VALUE_0": value}
    result = subprocess.run(
        ["git", "ls-remote", f"http://pinned.invalid:{internal.port}/r.git"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert internal.hits >= 1, result.stderr  # git reached 127.0.0.1 through the pin

    internal.hits = 0
    unpinned = {k: v for k, v in env.items() if not k.startswith("GIT_CONFIG")}
    subprocess.run(["git", "ls-remote", f"http://pinned.invalid:{internal.port}/r.git"],
                   env=unpinned, capture_output=True, text=True, timeout=30)
    assert internal.hits == 0  # without the pin it can't even resolve the name

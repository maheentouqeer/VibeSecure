"""SSRF guard for user-supplied scan targets.

The backend fetches and clones whatever URL a stranger submits, so it must
never be steerable at cloud metadata endpoints, localhost, or private
networks. Three layers:

  1. assert_public_url() -- a pre-flight check with a clear error message.
  2. safe_session() -- HTTP requests whose sockets are only ever opened to
     addresses that were validated *at connect time*, on the exact addresses
     being connected to. That closes DNS rebinding: a hostname that answers
     "public" to the pre-flight check and "127.0.0.1" to the connection is
     refused, because there is no second, unchecked resolution to exploit.
  3. git_pin_env() -- for `git clone`, where we cannot hook sockets, the
     validated addresses are pinned into git's own resolver (http.curloptResolve,
     which still verifies TLS against the hostname). Needs git >= 2.37.

Addresses are judged by is_public_address(), which also unwraps the IPv6 forms
that smuggle an IPv4 address (::ffff:127.0.0.1, NAT64, 6to4, Teredo).

Set ALLOW_PRIVATE_TARGETS=1 to disable all of it for local development only.
Environment proxy settings are ignored by safe_session(), so a configured
proxy can't be used to skip the checks.
"""
import ipaddress
import os
import socket
import sys
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3 import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.util.connection import _set_socket_options, allowed_gai_family

_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class UnsafeTargetError(ValueError):
    pass


def _private_allowed() -> bool:
    return os.getenv("ALLOW_PRIVATE_TARGETS") == "1"


def is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally routable addresses, including any IPv4 address
    embedded in an IPv6 one."""
    if ip.version == 6:
        # These IPv6 forms are just a wrapper around an IPv4 address; what matters
        # is that inner address (the wrapper prefix itself is flagged "reserved").
        if ip.ipv4_mapped is not None:
            return is_public_address(ip.ipv4_mapped)
        if ip in _NAT64:
            return is_public_address(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip.teredo and not all(is_public_address(v4) for v4 in ip.teredo):
            return False
        if ip.sixtofour is not None:
            return is_public_address(ip.sixtofour)

    # is_global alone is not enough: Python reports some multicast ranges as global.
    return not (
        not ip.is_global
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_unspecified
    )


def _parse_ip(text_address: str):
    return ipaddress.ip_address(text_address.split("%")[0])  # drop an IPv6 zone id


def resolve_public(host: str, port: int) -> list[str]:
    """Resolves `host` and returns its addresses, refusing if ANY of them is
    not public (a host with one private address is not trustworthy)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"Could not resolve host '{host}'.") from exc
    addresses = []
    for info in infos:
        address = info[4][0]
        if not is_public_address(_parse_ip(address)):
            raise UnsafeTargetError("Scanning private, loopback, or internal addresses is not allowed.")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise UnsafeTargetError(f"Could not resolve host '{host}'.")
    return addresses


def _split(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError("Only http(s) URLs can be scanned.")
    if not parsed.hostname:
        raise UnsafeTargetError("The URL has no host.")
    return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def assert_public_url(url: str) -> None:
    if _private_allowed():
        return
    host, port = _split(url)
    resolve_public(host, port)


# ------------------------------------------------------------ HTTP requests


def safe_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
    """urllib3's create_connection, except every resolved address is checked
    before any socket is opened, and only those checked addresses are used."""
    host, port = address
    host = host.strip("[]")
    infos = socket.getaddrinfo(host, port, allowed_gai_family(), socket.SOCK_STREAM)
    if not _private_allowed():
        for info in infos:
            if not is_public_address(_parse_ip(info[4][0])):
                raise UnsafeTargetError("Scanning private, loopback, or internal addresses is not allowed.")

    error = None
    for family, socktype, proto, _canon, sockaddr in infos:
        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            _set_socket_options(sock, socket_options)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            error = exc
            if sock is not None:
                sock.close()
    if error is not None:
        raise error
    raise OSError("getaddrinfo returned an empty list")


class _SafeConnectMixin:
    def _new_conn(self) -> socket.socket:
        try:
            sock = safe_create_connection(
                (self._dns_host, self.port), self.timeout,
                source_address=self.source_address, socket_options=self.socket_options,
            )
        except socket.gaierror as exc:
            raise NameResolutionError(self.host, self, exc) from exc
        except socket.timeout as exc:
            raise ConnectTimeoutError(self, f"Connection to {self.host} timed out.") from exc
        except UnsafeTargetError:
            raise  # deliberately not wrapped: the caller must see it was blocked, not "connection failed"
        except OSError as exc:
            raise NewConnectionError(self, f"Failed to establish a new connection: {exc}") from exc
        sys.audit("http.client.connect", self, self.host, self.port)
        return sock


class _SafeHTTPConnection(_SafeConnectMixin, HTTPConnection):
    pass


class _SafeHTTPSConnection(_SafeConnectMixin, HTTPSConnection):
    pass


class _SafeHTTPPool(HTTPConnectionPool):
    ConnectionCls = _SafeHTTPConnection


class _SafeHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _SafeHTTPSConnection


class SafeAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _SafeHTTPPool, "https": _SafeHTTPSPool}


def safe_session() -> requests.Session:
    """A requests Session that can only connect to public addresses."""
    session = requests.Session()
    session.trust_env = False  # no environment proxies: they would resolve and connect on our behalf
    adapter = SafeAdapter(max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ------------------------------------------------------------------ git


def git_pin_env(url: str, base_env: dict[str, str]) -> dict[str, str]:
    """Environment for `git clone <url>` that pins the host to the addresses we
    just validated, so git cannot re-resolve to something else. Returns
    `base_env` unchanged for IP-literal hosts (nothing to rebind) and when
    private targets are allowed. Raises UnsafeTargetError if the host is not public."""
    if _private_allowed():
        return base_env
    host, port = _split(url)
    try:
        ipaddress.ip_address(host.strip("[]"))
        return base_env
    except ValueError:
        pass
    addresses = resolve_public(host, port)

    env = dict(base_env)
    index = int(env.get("GIT_CONFIG_COUNT", "0") or 0)
    env["GIT_CONFIG_COUNT"] = str(index + 1)
    env[f"GIT_CONFIG_KEY_{index}"], env[f"GIT_CONFIG_VALUE_{index}"] = pin_config(host, port, addresses)
    return env


def pin_config(host: str, port: int, addresses: list[str]) -> tuple[str, str]:
    """The git config (key, value) that makes git connect `host:port` only to `addresses`."""
    return "http.curloptResolve", f"{host}:{port}:{','.join(addresses)}"

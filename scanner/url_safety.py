"""SSRF guard for user-supplied scan targets.

The backend fetches and clones whatever URL a stranger submits, so it must
never be steerable at cloud metadata endpoints, localhost, or private
networks. Every hostname is resolved and *all* of its addresses must be
globally routable. Set ALLOW_PRIVATE_TARGETS=1 to disable the check for
local development only.

Limitation: the address is validated at check time, not pinned for the
later connection, so a DNS-rebinding attacker with a very short TTL could
still slip through; defend in depth with network egress rules in production.
"""
import ipaddress
import os
import socket
from urllib.parse import urlparse


class UnsafeTargetError(ValueError):
    pass


def assert_public_url(url: str) -> None:
    if os.getenv("ALLOW_PRIVATE_TARGETS") == "1":
        return

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError("Only http(s) URLs can be scanned.")
    host = parsed.hostname
    if not host:
        raise UnsafeTargetError("The URL has no host.")

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"Could not resolve host '{host}'.") from exc

    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        if not address.is_global:
            raise UnsafeTargetError("Scanning private, loopback, or internal addresses is not allowed.")

"""External, read-only checks against a live deployed app.

No source code access required -- this is the fastest thing to demo
live at a hackathon: paste any public URL and get results in seconds.
"""
from urllib.parse import urljoin

import requests

from scanner.url_safety import UnsafeTargetError, assert_public_url, safe_session

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
]

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 1_000_000


def _safe_get(url: str) -> requests.Response:
    """GET that validates the destination of every redirect hop against the
    SSRF guard (requests' own redirect following would skip that check) and
    never reads more than MAX_BODY_BYTES. The session it uses only opens
    sockets to addresses validated at connect time, so DNS rebinding between
    the pre-flight check and the connection cannot redirect it inward."""
    with safe_session() as session:
        for _ in range(MAX_REDIRECTS + 1):
            assert_public_url(url)
            resp = session.get(url, timeout=6, allow_redirects=False, stream=True)
            if resp.is_redirect and resp.headers.get("Location"):
                url = urljoin(url, resp.headers["Location"])
                resp.close()
                continue
            body = resp.raw.read(MAX_BODY_BYTES, decode_content=True)
            resp._content = body
            resp._content_consumed = True
            resp.close()
            return resp
    raise requests.TooManyRedirects(f"More than {MAX_REDIRECTS} redirects")


def scan_live_url(base_url: str) -> list[dict]:
    base_url = base_url.rstrip("/")
    findings = []

    # 1. Exposed .env / .git
    for path, label in [(".env", "Exposed .env file"), (".git/config", "Exposed .git directory")]:
        try:
            resp = _safe_get(f"{base_url}/{path}")
            if resp.status_code == 200 and len(resp.text.strip()) > 0:
                findings.append({
                    "category": "exposed_file",
                    "label": label,
                    "file": path,
                    "raw_severity": "critical",
                })
        except (requests.RequestException, UnsafeTargetError):
            pass

    # 2. Missing security headers
    try:
        resp = _safe_get(base_url)
        missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
        for h in missing:
            findings.append({
                "category": "missing_header",
                "label": f"Missing {h} header",
                "file": base_url,
                "raw_severity": "medium",
            })

        # 3. Loose CORS
        cors = resp.headers.get("Access-Control-Allow-Origin", "")
        if cors == "*":
            findings.append({
                "category": "cors_misconfig",
                "label": "CORS allows any origin (*)",
                "file": base_url,
                "raw_severity": "high",
            })
    except (requests.RequestException, UnsafeTargetError):
        pass

    return findings

"""External, read-only checks against a live deployed app.

No source code access required -- this is the fastest thing to demo
live at a hackathon: paste any public URL and get results in seconds.
"""
import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
]


def scan_live_url(base_url: str) -> list[dict]:
    base_url = base_url.rstrip("/")
    findings = []

    # 1. Exposed .env / .git
    for path, label in [(".env", "Exposed .env file"), (".git/config", "Exposed .git directory")]:
        try:
            resp = requests.get(f"{base_url}/{path}", timeout=6)
            if resp.status_code == 200 and len(resp.text.strip()) > 0:
                findings.append({
                    "category": "exposed_file",
                    "label": label,
                    "file": path,
                    "raw_severity": "critical",
                })
        except requests.RequestException:
            pass

    # 2. Missing security headers
    try:
        resp = requests.get(base_url, timeout=6)
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
    except requests.RequestException:
        pass

    return findings

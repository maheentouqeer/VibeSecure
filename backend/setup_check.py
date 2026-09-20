"""Checks that the deployment is configured correctly.

    python -m backend.setup_check                      static checks of the environment
    python -m backend.setup_check --live               + read-only network checks (Clerk keys, Whop API key)
    python -m backend.setup_check --api https://...    + call /healthz and /readyz on a running API
    python -m backend.setup_check --sentry-test        + send one test event to Sentry

Run it with the SAME environment variables the server has (e.g. `railway run
python -m backend.setup_check --live`). It never prints a secret, only whether
it looks right. Exits 1 if anything is FAIL, so it can gate a deploy.

Statuses: OK (looks right), WARN (works but worth fixing), FAIL (will not work),
SKIP (feature not configured, which is fine if you don't want it).
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse

import requests


@dataclass
class Result:
    status: str  # OK | WARN | FAIL | SKIP
    name: str
    detail: str = ""


def _has(env: Mapping[str, str], name: str) -> bool:
    return bool((env.get(name) or "").strip())


def _https(url: str) -> bool:
    return urlparse(url).scheme == "https"


# ----------------------------------------------------------------- static


def check_database(env) -> list[Result]:
    url = env.get("DATABASE_URL", "")
    if not url:
        return [Result("WARN", "database", "DATABASE_URL is unset, so a local SQLite file is used. Use Postgres in production.")]
    if url.startswith("sqlite"):
        return [Result("WARN", "database", "SQLite is for development. Production should use Postgres.")]
    if url.startswith(("postgresql", "postgres")):
        return [Result("OK", "database", "Postgres")]
    return [Result("FAIL", "database", "DATABASE_URL is not a Postgres or SQLite URL")]


def check_cors_and_frontend(env) -> list[Result]:
    out = []
    origins = [o.strip() for o in env.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
    if all("localhost" in o or "127.0.0.1" in o for o in origins):
        out.append(Result("WARN", "cors", "ALLOWED_ORIGINS only lists localhost. Add your deployed frontend origin."))
    else:
        out.append(Result("OK", "cors", f"{len(origins)} allowed origin(s)"))
    front = env.get("FRONTEND_URL", "")
    if not front:
        out.append(Result("SKIP", "frontend url", "FRONTEND_URL unset: GitHub connect shows JSON and checkout has no return URL"))
    elif not _https(front) and "localhost" not in front:
        out.append(Result("WARN", "frontend url", "FRONTEND_URL should be https"))
    else:
        out.append(Result("OK", "frontend url", front))
    return out


def check_clerk(env) -> list[Result]:
    if not _has(env, "CLERK_JWKS_URL"):
        return [Result("SKIP", "clerk sign-in", "CLERK_JWKS_URL unset: everyone is anonymous")]
    out = []
    url = env["CLERK_JWKS_URL"]
    out.append(Result("OK" if _https(url) else "FAIL", "clerk jwks url", "https" if _https(url) else "must be https"))
    if not url.rstrip("/").endswith("jwks.json"):
        out.append(Result("WARN", "clerk jwks url", "usually ends in /.well-known/jwks.json"))
    out.append(
        Result("OK", "clerk issuer", "set") if _has(env, "CLERK_ISSUER")
        else Result("WARN", "clerk issuer", "CLERK_ISSUER unset: token issuer is not checked")
    )
    out.append(
        Result("OK", "clerk authorized parties", "set") if _has(env, "CLERK_AUTHORIZED_PARTIES")
        else Result("WARN", "clerk authorized parties", "CLERK_AUTHORIZED_PARTIES unset: any frontend origin's tokens are accepted")
    )
    return out


def check_github_oauth(env) -> list[Result]:
    names = ("GITHUB_OAUTH_CLIENT_ID", "GITHUB_OAUTH_CLIENT_SECRET", "GITHUB_OAUTH_REDIRECT_URI", "TOKEN_ENCRYPTION_KEY")
    present = [n for n in names if _has(env, n)]
    if not present:
        return [Result("SKIP", "github private repos", "not configured")]
    missing = [n for n in names if n not in present]
    if missing:
        return [Result("FAIL", "github private repos", "partly configured, missing: " + ", ".join(missing))]

    out = []
    try:
        from cryptography.fernet import Fernet

        Fernet(env["TOKEN_ENCRYPTION_KEY"].encode())
        out.append(Result("OK", "token encryption key", "valid Fernet key"))
    except Exception:
        out.append(Result("FAIL", "token encryption key", "not a valid Fernet key. Generate one with Fernet.generate_key()"))
    uri = env["GITHUB_OAUTH_REDIRECT_URI"]
    if not _https(uri) and "localhost" not in uri:
        out.append(Result("FAIL", "github redirect uri", "must be https (GitHub tokens travel through it)"))
    elif not uri.rstrip("/").endswith("/integrations/github/callback"):
        out.append(Result("WARN", "github redirect uri", "should end with /integrations/github/callback and match the OAuth app exactly"))
    else:
        out.append(Result("OK", "github redirect uri", uri))
    return out


def check_whop(env) -> list[Result]:
    out = []
    if not any(_has(env, n) for n in ("WHOP_WEBHOOK_SECRET", "WHOP_PLAN_MAP", "WHOP_API_KEY")):
        return [Result("SKIP", "whop billing", "not configured")]

    secret = env.get("WHOP_WEBHOOK_SECRET", "")
    if not secret:
        out.append(Result("FAIL", "whop webhook secret", "WHOP_WEBHOOK_SECRET unset: purchases can never activate a plan"))
    elif not secret.startswith("ws_"):
        out.append(Result("WARN", "whop webhook secret", "Whop secrets start with ws_; paste it exactly as shown (with the prefix)"))
    else:
        out.append(Result("OK", "whop webhook secret", "set"))

    plans = {}
    try:
        raw = json.loads(env.get("WHOP_PLAN_MAP", "") or "{}")
        plans = raw if isinstance(raw, dict) else {}
    except ValueError:
        out.append(Result("FAIL", "whop plan map", "WHOP_PLAN_MAP is not valid JSON"))
        plans = None
    if plans is not None:
        bad = {k: v for k, v in plans.items() if v not in ("pro", "team")}
        if not plans:
            out.append(Result("FAIL", "whop plan map", "WHOP_PLAN_MAP is empty: no purchase maps to a plan"))
        elif bad:
            out.append(Result("FAIL", "whop plan map", f"values must be 'pro' or 'team': {sorted(bad)}"))
        else:
            out.append(Result("OK", "whop plan map", f"{len(plans)} id(s)"))
            for ours in ("pro", "team"):
                buyable = [k for k, v in plans.items() if v == ours and k.startswith("plan_")]
                if not buyable:
                    out.append(Result("WARN", f"whop checkout ({ours})", f"no plan_ id maps to '{ours}', so /billing/checkout can't sell it"))

    out.append(
        Result("OK", "whop api key", "set") if _has(env, "WHOP_API_KEY")
        else Result("WARN", "whop api key", "WHOP_API_KEY unset: /billing/checkout is disabled (webhooks still work)")
    )
    return out


def check_admin_and_limits(env) -> list[Result]:
    out = []
    key = env.get("ADMIN_API_KEY", "")
    if not key:
        out.append(Result("SKIP", "admin api", "ADMIN_API_KEY unset: admin endpoints are off"))
    elif len(key) < 24:
        out.append(Result("FAIL", "admin api", "ADMIN_API_KEY is under 24 characters, so the admin API refuses to start"))
    else:
        out.append(Result("OK", "admin api", "key set"))

    store = env.get("RATE_LIMIT_STORE", "db").lower()
    out.append(
        Result("OK", "rate limit store", store) if store in ("db", "memory")
        else Result("FAIL", "rate limit store", f"RATE_LIMIT_STORE={store!r} (use db or memory)")
    )
    if store == "memory":
        out.append(Result("WARN", "rate limit store", "memory limits are per instance and reset on restart"))

    out.append(
        Result("OK", "plan limits", "enforced") if env.get("ENFORCE_PLAN_LIMITS") == "1"
        else Result("SKIP", "plan limits", "not enforced (ENFORCE_PLAN_LIMITS!=1): everyone gets everything")
    )
    mode = env.get("SCAN_WORKER_MODE", "inline").lower()
    if mode == "external":
        out.append(Result("WARN", "workers", "SCAN_WORKER_MODE=external: make sure `python -m backend.worker` is running, or scans stay queued"))
    elif mode == "inline":
        out.append(Result("OK", "workers", "inline (the API runs scans itself)"))
    else:
        out.append(Result("FAIL", "workers", f"SCAN_WORKER_MODE={mode!r} (use inline or external)"))
    return out


def check_secrets_hygiene(env) -> list[Result]:
    if not any(_has(env, n) for n in ("GITHUB_TOKEN", "GITHUB_PAT", "VIBESECURE_GITHUB_TOKEN")):
        return [Result("OK", "server github token", "none set")]
    if env.get("ALLOW_SERVER_GITHUB_TOKEN") != "1":
        return [Result("WARN", "server github token", "set but IGNORED. Set ALLOW_SERVER_GITHUB_TOKEN=1 to use it (and SERVER_GITHUB_TOKEN_OWNERS to limit it)")]
    owners = [o for o in env.get("SERVER_GITHUB_TOKEN_OWNERS", "").split(",") if o.strip()]
    if not owners:
        return [Result("WARN", "server github token", "enabled for EVERY repository: anyone who can submit a URL can scan whatever it can read. Set SERVER_GITHUB_TOKEN_OWNERS")]
    return [Result("OK", "server github token", "limited to owner(s): " + ", ".join(o.strip() for o in owners))]


def check_tools(env) -> list[Result]:
    out = []
    git = shutil.which("git")
    if not git:
        out.append(Result("FAIL", "git", "not installed: repository scans cannot run"))
    else:
        text = subprocess.run([git, "--version"], capture_output=True, text=True).stdout
        m = re.search(r"(\d+)\.(\d+)", text)
        if m and (int(m.group(1)), int(m.group(2))) < (2, 37):
            out.append(Result("WARN", "git", f"{text.strip()} is older than 2.37: DNS pinning for clones is unavailable"))
        else:
            out.append(Result("OK", "git", text.strip()))
    out.append(
        Result("OK", "semgrep", "installed") if shutil.which("semgrep")
        else Result("WARN", "semgrep", "not installed: static analysis is skipped and every scan reports it as incomplete")
    )
    out.append(
        Result("OK", "gemini", "key set") if _has(env, "GEMINI_API_KEY")
        else Result("WARN", "gemini", "GEMINI_API_KEY unset: explanations and fix prompts use plain templates, not AI")
    )
    dsn = env.get("SENTRY_DSN", "")
    if not dsn:
        out.append(Result("SKIP", "sentry", "SENTRY_DSN unset: errors are not reported"))
    elif not urlparse(dsn).netloc or "@" not in urlparse(dsn).netloc:
        out.append(Result("FAIL", "sentry", "SENTRY_DSN does not look like a DSN (https://<key>@<host>/<project>)"))
    else:
        out.append(Result("OK", "sentry", "DSN set"))
    return out


STATIC_CHECKS = (
    check_database, check_cors_and_frontend, check_clerk, check_github_oauth, check_whop,
    check_admin_and_limits, check_secrets_hygiene, check_tools,
)


# ------------------------------------------------------------------- live


def live_clerk(env) -> list[Result]:
    url = env.get("CLERK_JWKS_URL", "")
    if not url:
        return []
    try:
        resp = requests.get(url, timeout=10)
        keys = resp.json().get("keys", []) if resp.ok else []
    except (requests.RequestException, ValueError):
        return [Result("FAIL", "clerk jwks (live)", "could not fetch or parse the key set")]
    if not keys:
        return [Result("FAIL", "clerk jwks (live)", f"HTTP {resp.status_code}, no signing keys found. Wrong URL?")]
    return [Result("OK", "clerk jwks (live)", f"{len(keys)} signing key(s)")]


def live_whop(env) -> list[Result]:
    key = env.get("WHOP_API_KEY", "")
    if not key:
        return []
    base = env.get("WHOP_API_BASE", "https://api.whop.com/api/v1").rstrip("/")
    try:  # a read-only list call: proves the key is accepted without creating anything
        resp = requests.get(f"{base}/checkout_configurations", headers={"Authorization": f"Bearer {key}"}, timeout=10)
    except requests.RequestException:
        return [Result("FAIL", "whop api key (live)", "could not reach the Whop API")]
    if resp.status_code == 401:
        return [Result("FAIL", "whop api key (live)", "Whop rejected the API key (401)")]
    if resp.status_code == 403:
        return [Result("WARN", "whop api key (live)", "key is valid but lacks read permission (403); confirm it may CREATE checkouts")]
    if resp.ok:
        return [Result("OK", "whop api key (live)", "accepted")]
    return [Result("WARN", "whop api key (live)", f"unexpected HTTP {resp.status_code}")]


def live_api(base: str) -> list[Result]:
    out = []
    for path in ("/healthz", "/readyz"):
        try:
            resp = requests.get(base.rstrip("/") + path, timeout=10)
        except requests.RequestException:
            out.append(Result("FAIL", f"api {path}", "unreachable"))
            continue
        if resp.ok:
            out.append(Result("OK", f"api {path}", "200"))
        else:
            try:
                problems = "; ".join(resp.json().get("problems", []))
            except ValueError:
                problems = ""
            out.append(Result("FAIL", f"api {path}", f"HTTP {resp.status_code} {problems}".strip()))
    return out


def sentry_test(env) -> list[Result]:
    dsn = env.get("SENTRY_DSN", "")
    if not dsn:
        return [Result("SKIP", "sentry test", "SENTRY_DSN unset")]
    try:
        import sentry_sdk

        sentry_sdk.init(dsn=dsn, send_default_pii=False)
        sentry_sdk.capture_message("Secure-VibeCode setup check: Sentry is wired up")
        delivered = sentry_sdk.flush(timeout=10) is not False
    except Exception as exc:
        return [Result("FAIL", "sentry test", exc.__class__.__name__)]
    return [Result("OK", "sentry test", "event sent: look for 'setup check' in your Sentry project")] if delivered else [
        Result("WARN", "sentry test", "sent, but delivery was not confirmed")
    ]


# ------------------------------------------------------------------- main


def run_checks(env: Mapping[str, str], live: bool = False, api: str | None = None, sentry: bool = False) -> list[Result]:
    results: list[Result] = []
    for check in STATIC_CHECKS:
        results.extend(check(env))
    if live:
        results.extend(live_clerk(env))
        results.extend(live_whop(env))
    if api:
        results.extend(live_api(api))
    if sentry:
        results.extend(sentry_test(env))
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check the Secure-VibeCode deployment configuration.")
    parser.add_argument("--live", action="store_true", help="also run read-only network checks")
    parser.add_argument("--api", metavar="URL", help="also check /healthz and /readyz of a running API")
    parser.add_argument("--sentry-test", action="store_true", help="send one test event to Sentry")
    args = parser.parse_args(argv)

    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    results = run_checks(os.environ, live=args.live, api=args.api, sentry=args.sentry_test)
    icons = {"OK": " ok ", "WARN": "warn", "FAIL": "FAIL", "SKIP": "skip"}
    for r in results:
        print(f"[{icons[r.status]}] {r.name:<28} {r.detail}")
    counts = {s: sum(1 for r in results if r.status == s) for s in icons}
    print(f"\n{counts['OK']} ok, {counts['WARN']} warnings, {counts['FAIL']} failures, {counts['SKIP']} skipped")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())

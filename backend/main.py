"""FastAPI service for Secure-VibeCode's backend/persistence layer.

Wraps Maheen's orchestrator.run_full_scan and matches re-scan findings via
Ali's verify_agent.fingerprint, persisting results to Postgres (or SQLite for
local dev), and exposes scan + badge endpoints.

Ownership: there are no user accounts. Instead, POST /scans issues an
opaque X-Owner-Token (generated server-side, or echoed back if the client
already supplied one) that must be presented on every later request for
that scan. This is deliberately lightweight -- session ownership, not a
permissions system -- see README_ANEEL.md for the rationale.
"""
import hashlib
import hmac
import json
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import update
from sqlalchemy.orm import Session

from agents.verify_agent import fingerprint
from backend import badge, db, limits, schemas
from orchestrator import run_full_scan

ACTIVE_STATUSES = ("queued", "running")


def _init_sentry() -> None:
    """Error monitoring is opt-in: without SENTRY_DSN this does nothing."""
    dsn = os.getenv("SENTRY_DSN")
    if not dsn:
        return
    import sentry_sdk

    sentry_sdk.init(
        dsn=dsn,
        environment=os.getenv("SENTRY_ENVIRONMENT", "production"),
        traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0")),
        send_default_pii=False,
    )


def _report_job_failure(exc: Exception) -> None:
    # Background job errors are caught and stored on the scan, so they never
    # reach Sentry's request hooks; report them explicitly (no-op if uninitialised).
    import sentry_sdk

    sentry_sdk.capture_exception(exc)


def _fail_orphaned_jobs() -> None:
    """Scans still queued/running at startup lost their worker when the
    process restarted; without this they would stay stuck forever."""
    with db.SessionLocal() as session:
        for scan in session.query(db.Scan).filter(db.Scan.status.in_(ACTIVE_STATUSES)).all():
            scan.status = "failed"
            scan.error = "Scan was interrupted by a server restart. Please scan again."
        session.commit()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    _fail_orphaned_jobs()
    yield


_init_sentry()

app = FastAPI(title="Secure-VibeCode API", version="0.1.0", lifespan=lifespan)

# The Next.js frontend (local dev on :3000, or the deployed Vercel domain)
# lives on a different origin than this API, so the browser needs an
# explicit CORS allowlist -- ALLOWED_ORIGINS is a comma-separated env var,
# e.g. "https://secure-vibecode.vercel.app,http://localhost:3000".
_default_origins = "http://localhost:3000,http://127.0.0.1:3000"
_allowed_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", _default_origins).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Owner-Token"],
)


def _save_findings(session: Session, scan: db.Scan, raw_findings: list[dict]) -> None:
    for f in raw_findings:
        session.add(
            db.Finding(
                scan_id=scan.id,
                category=f["category"],
                label=f["label"],
                file=f["file"],
                severity=f["severity"],
                what_it_means=f["what_it_means"],
                why_it_matters=f["why_it_matters"],
                fix_prompt=f["fix_prompt"],
                status=f.get("status", "open"),
                fingerprint=fingerprint(f),
            )
        )


def _claim_scan_for_rescan(session: Session, scan_id: str) -> bool:
    """Atomically moves a scan to "running". The status check and the update
    are one SQL statement, so of any number of concurrent callers exactly one
    gets True; a read-then-write check would let several through."""
    claimed = session.execute(
        update(db.Scan)
        .where(db.Scan.id == scan_id, db.Scan.status.notin_(ACTIVE_STATUSES))
        .values(status="running", error=None)
    ).rowcount
    return claimed == 1


def _get_owned_scan_or_404(session: Session, scan_id: str, x_owner_token: str | None) -> db.Scan:
    """Fetches a scan and enforces ownership in one step.

    A missing scan and a wrong/missing token both return the same 404 --
    deliberately not a 403 -- so a caller who doesn't hold the token can't
    even confirm the scan id exists.
    """
    scan = session.get(db.Scan, scan_id)
    if scan is None or x_owner_token is None or x_owner_token != scan.owner_token:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return scan


def _finding_to_dict(f: db.Finding) -> dict:
    return {
        "category": f.category,
        "label": f.label,
        "file": f.file,
        "severity": f.severity,
        "what_it_means": f.what_it_means,
        "why_it_matters": f.why_it_matters,
        "fix_prompt": f.fix_prompt,
        "status": f.status,
    }


def _run_scan_job(scan_id: str) -> None:
    """Background job for POST /scans. Uses its own session because the
    request's session is closed by the time this runs."""
    with db.SessionLocal() as session:
        try:
            scan = session.get(db.Scan, scan_id)
            scan.status = "running"
            session.commit()

            result = run_full_scan(scan.target)

            scan.platform = result["platform"]
            scan.commit_sha = result.get("commit_sha")
            _save_findings(session, scan, result["findings"])
            scan.status = "completed"
            session.commit()
        except Exception as exc:
            session.rollback()
            _report_job_failure(exc)
            scan = session.get(db.Scan, scan_id)
            scan.status = "failed"
            scan.error = f"Scan failed: {exc}"
            session.commit()


def _run_rescan_job(scan_id: str) -> None:
    """Background job for POST /scans/{id}/rescan. A failed rescan leaves the
    scan's existing results intact (status goes back to "completed") and
    records the failure in `error` instead."""
    with db.SessionLocal() as session:
        try:
            scan = session.get(db.Scan, scan_id)

            # Skip all scanner/LLM work when the repo is still at the commit
            # this scan saw -- unless a scanner failed last time, in which case
            # the rescan is the user's retry and must really run.
            scan_was_incomplete = any(
                f.category == "scan_incomplete" and f.status == "open" for f in scan.findings
            )
            kwargs = {"unchanged_since": scan.commit_sha} if scan.commit_sha and not scan_was_incomplete else {}
            result = run_full_scan(scan.target, **kwargs)
            if result.get("unchanged"):
                scan.status = "completed"
                session.commit()
                return

            scan.commit_sha = result.get("commit_sha")
            new_findings = result["findings"]

            # Findings are matched across scans by fingerprint (category, label
            # minus volatile detail, file, table), not by row id or raw label.
            # Rows saved before fingerprints existed fall back to computing it.
            new_fps = {fingerprint(f) for f in new_findings}
            for existing in scan.findings:
                fp = existing.fingerprint or fingerprint(_finding_to_dict(existing))
                existing.fingerprint = fp
                if existing.status == "open" and fp not in new_fps:
                    existing.status = "resolved"
                elif existing.status == "resolved" and fp in new_fps:
                    # A previously-fixed issue reappeared in the fresh scan --
                    # reopen it instead of leaving it silently marked resolved.
                    existing.status = "open"

            # Anything in the fresh scan that wasn't already tracked is new.
            known_fps = {f.fingerprint for f in scan.findings}
            truly_new = [f for f in new_findings if fingerprint(f) not in known_fps]
            _save_findings(session, scan, truly_new)

            scan.status = "completed"
            session.commit()
        except Exception as exc:
            session.rollback()
            _report_job_failure(exc)
            scan = session.get(db.Scan, scan_id)
            scan.status = "completed"
            scan.error = f"Rescan failed: {exc}"
            session.commit()


@app.post("/scans", response_model=schemas.ScanResponse, status_code=202)
def create_scan(
    payload: schemas.ScanCreateRequest,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    session: Session = Depends(db.get_db),
    x_owner_token: str | None = Header(default=None, alias="X-Owner-Token"),
):
    limits.enforce_scan_limits(request, session)

    # Reuse the caller's token if they already have one (e.g. a follow-up
    # scan from the same browser session); otherwise mint a fresh one.
    owner_token = x_owner_token or str(uuid.uuid4())

    scan = db.Scan(
        target=payload.target,
        platform="generic",
        status="queued",
        owner_token=owner_token,
    )
    session.add(scan)
    session.flush()
    session.add(db.ScanRun(scan_id=scan.id, kind="scan"))
    session.commit()
    session.refresh(scan)

    background_tasks.add_task(_run_scan_job, scan.id)

    # Never returned in the JSON body (ScanResponse has no owner_token
    # field) -- only via this header, so it's never mixed into stored/shared
    # scan data. The client polls GET /scans/{id} until status is
    # "completed" or "failed".
    response.headers["X-Owner-Token"] = owner_token
    return scan


@app.get("/scans", response_model=list[schemas.ScanResponse])
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(db.get_db),
    x_owner_token: str | None = Header(default=None, alias="X-Owner-Token"),
):
    # No token means no scans -- an empty list rather than a 404, since
    # "you haven't scanned anything yet" is a normal state, not an error.
    if x_owner_token is None:
        return []
    return (
        session.query(db.Scan)
        .filter(db.Scan.owner_token == x_owner_token)
        .order_by(db.Scan.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@app.get("/scans/{scan_id}", response_model=schemas.ScanResponse)
def get_scan(
    scan_id: str,
    session: Session = Depends(db.get_db),
    x_owner_token: str | None = Header(default=None, alias="X-Owner-Token"),
):
    return _get_owned_scan_or_404(session, scan_id, x_owner_token)


@app.post("/scans/{scan_id}/rescan", response_model=schemas.ScanResponse, status_code=202)
def rescan_scan(
    scan_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    session: Session = Depends(db.get_db),
    x_owner_token: str | None = Header(default=None, alias="X-Owner-Token"),
):
    scan = _get_owned_scan_or_404(session, scan_id, x_owner_token)

    if scan.status in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail="A scan is already in progress for this target.")

    limits.enforce_scan_limits(request, session)

    if not _claim_scan_for_rescan(session, scan.id):
        session.rollback()
        raise HTTPException(status_code=409, detail="A scan is already in progress for this target.")
    session.add(db.ScanRun(scan_id=scan.id, kind="rescan"))
    session.commit()
    session.refresh(scan)

    background_tasks.add_task(_run_rescan_job, scan.id)
    return scan


@app.get("/scans/{scan_id}/badge", response_model=schemas.BadgeResponse)
def get_badge(
    scan_id: str,
    session: Session = Depends(db.get_db),
    x_owner_token: str | None = Header(default=None, alias="X-Owner-Token"),
):
    scan = _get_owned_scan_or_404(session, scan_id, x_owner_token)

    open_critical = sum(1 for f in scan.findings if f.status == "open" and f.severity == "critical")
    open_high = sum(1 for f in scan.findings if f.status == "open" and f.severity == "high")
    passed = open_critical == 0 and open_high == 0

    reason = (
        "No open critical or high severity findings."
        if passed
        else f"{open_critical} open critical, {open_high} open high severity finding(s) remain."
    )

    return schemas.BadgeResponse(
        scan_id=scan.id,
        passed=passed,
        open_critical=open_critical,
        open_high=open_high,
        reason=reason,
    )


@app.get("/badge/{scan_id}.svg")
def public_badge(scan_id: str, session: Session = Depends(db.get_db)):
    """Unauthenticated, embeddable badge. Anyone holding the (unguessable)
    scan id can render it, so it exposes only verified / not verified."""
    scan = session.get(db.Scan, scan_id)
    if scan is None:
        svg, status_code = badge.render_badge("unknown", verified=False), 404
    else:
        verified = scan.status == "completed" and not any(
            f.status == "open" and f.severity in ("critical", "high") for f in scan.findings
        )
        svg = badge.render_badge("verified" if verified else "not verified", verified)
        status_code = 200
    return Response(
        content=svg,
        media_type="image/svg+xml",
        status_code=status_code,
        headers={"Cache-Control": "public, max-age=300"},
    )


def _normalize_repo_url(url: str) -> str:
    url = url.strip().lower().rstrip("/")
    for prefix in ("https://", "http://", "git://"):
        if url.startswith(prefix):
            url = url[len(prefix):]
    return url.removesuffix(".git")


MAX_SCANS_PER_PUSH = 20


@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    session: Session = Depends(db.get_db),
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
):
    """Re-scans repos on push. Add a repository webhook (content type
    application/json, "push" events) pointing here with the secret set in
    GITHUB_WEBHOOK_SECRET. Only repos someone has already scanned are
    re-scanned, and only for pushes to the default branch."""
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=503, detail="Webhooks are not configured.")

    body = await request.body()
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not x_hub_signature_256 or not hmac.compare_digest(expected, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid signature.")

    if x_github_event == "ping":
        return {"ok": True}
    if x_github_event != "push":
        return {"triggered": 0, "reason": f"ignored event '{x_github_event}'"}

    try:
        payload = json.loads(body)
        repo = payload["repository"]
        repo_key = _normalize_repo_url(repo["html_url"])
        default_ref = "refs/heads/" + repo["default_branch"]
        ref = payload["ref"]
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=400, detail="Malformed push payload.")

    if ref != default_ref:
        return {"triggered": 0, "reason": "push was not to the default branch"}

    candidates = (
        session.query(db.Scan)
        .filter(db.Scan.target.ilike(f"%{repo['full_name']}%"))
        .order_by(db.Scan.created_at.desc())
        .all()
    )
    seen_owners: set[str] = set()
    triggered = 0
    for scan in candidates:
        if _normalize_repo_url(scan.target) != repo_key or scan.owner_token in seen_owners:
            continue
        seen_owners.add(scan.owner_token)  # newest scan per owner only
        if scan.status in ACTIVE_STATUSES or (scan.status == "failed" and not scan.findings):
            continue
        if triggered >= MAX_SCANS_PER_PUSH or limits.daily_cap_reached(session):
            break

        if not _claim_scan_for_rescan(session, scan.id):
            session.rollback()
            continue
        session.add(db.ScanRun(scan_id=scan.id, kind="webhook"))
        session.commit()
        background_tasks.add_task(_run_rescan_job, scan.id)
        triggered += 1

    return {"triggered": triggered}

"""FastAPI service for Secure-VibeCode's backend/persistence layer.

Wraps Maheen's orchestrator.run_full_scan and diffs re-scans via Ali's
verify_agent.diff_findings, persisting results to Postgres (or SQLite for
local dev), and exposes scan + badge endpoints.

Ownership: there are no user accounts. Instead, POST /scans issues an
opaque X-Owner-Token (generated server-side, or echoed back if the client
already supplied one) that must be presented on every later request for
that scan. This is deliberately lightweight -- session ownership, not a
permissions system -- see README_ANEEL.md for the rationale.
"""
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from agents.verify_agent import diff_findings
from backend import db, schemas
from orchestrator import run_full_scan


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    yield


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
            )
        )


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


@app.post("/scans", response_model=schemas.ScanResponse, status_code=201)
def create_scan(
    payload: schemas.ScanCreateRequest,
    response: Response,
    session: Session = Depends(db.get_db),
    x_owner_token: str | None = Header(default=None, alias="X-Owner-Token"),
):
    try:
        result = run_full_scan(payload.target)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    # Reuse the caller's token if they already have one (e.g. a follow-up
    # scan from the same browser session); otherwise mint a fresh one.
    owner_token = x_owner_token or str(uuid.uuid4())

    scan = db.Scan(
        target=payload.target,
        platform=result["platform"],
        status="completed",
        owner_token=owner_token,
    )
    session.add(scan)
    session.flush()  # assigns scan.id before findings reference it

    _save_findings(session, scan, result["findings"])
    session.commit()
    session.refresh(scan)

    # Never returned in the JSON body (ScanResponse has no owner_token
    # field) -- only via this header, so it's never mixed into stored/shared
    # scan data.
    response.headers["X-Owner-Token"] = owner_token
    return scan


@app.get("/scans/{scan_id}", response_model=schemas.ScanResponse)
def get_scan(
    scan_id: str,
    session: Session = Depends(db.get_db),
    x_owner_token: str | None = Header(default=None, alias="X-Owner-Token"),
):
    return _get_owned_scan_or_404(session, scan_id, x_owner_token)


@app.post("/scans/{scan_id}/rescan", response_model=schemas.ScanResponse)
def rescan_scan(
    scan_id: str,
    session: Session = Depends(db.get_db),
    x_owner_token: str | None = Header(default=None, alias="X-Owner-Token"),
):
    scan = _get_owned_scan_or_404(session, scan_id, x_owner_token)

    previous = [_finding_to_dict(f) for f in scan.findings if f.status == "open"]

    try:
        result = run_full_scan(scan.target)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Rescan failed: {exc}") from exc

    new_findings = result["findings"]

    # diff_findings (Ali's Verify Agent) tells us which previously-open
    # findings are still present vs. resolved, matched by (category, label, file)
    # since findings have no stable external id across scans.
    diffed_by_key = {
        (d["category"], d["label"], d.get("file")): d["status"]
        for d in diff_findings(previous, new_findings)
    }
    new_keys = {(f["category"], f["label"], f.get("file")) for f in new_findings}
    for existing in scan.findings:
        key = (existing.category, existing.label, existing.file)
        if existing.status == "open" and diffed_by_key.get(key) == "resolved":
            existing.status = "resolved"
        elif existing.status == "resolved" and key in new_keys:
            # A previously-fixed issue reappeared in the fresh scan -- reopen it
            # instead of leaving it silently marked resolved.
            existing.status = "open"

    # Anything in the fresh scan that wasn't already tracked is a new finding.
    existing_keys = {(f.category, f.label, f.file) for f in scan.findings}
    truly_new = [f for f in new_findings if (f["category"], f["label"], f["file"]) not in existing_keys]
    _save_findings(session, scan, truly_new)

    session.commit()
    session.refresh(scan)
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

"""Operator endpoints, protected by a shared secret.

  GET    /admin/stats                        counts: users, scans, usage vs the daily cap, plans, jobs
  GET    /admin/users?email=&limit=          find accounts (effective plan, scan count, org count)
  POST   /admin/users/{id}/plan              grant a complimentary Pro plan for N days
  POST   /admin/orgs/{id}/plan               grant a complimentary Team plan for N days
  DELETE /admin/subscriptions/{id}           end a complimentary plan
  GET    /admin/audit?limit=                 what has been done through this API

Design rules:
  * Off unless ADMIN_API_KEY is set to a strong value (24+ characters); send it
    as `X-Admin-Key`. Wrong keys are compared in constant time and an IP that
    keeps sending them is locked out (ADMIN_FAIL_LIMIT_PER_HOUR, default 10).
  * Read-mostly and deliberately blind: it never returns scan targets, findings,
    fix prompts, tokens, or anything from a user's code. Counts and account
    metadata only.
  * It can only create and end its own "manual" subscriptions. Real provider
    subscriptions (Whop, ...) are never touched from here.
  * Every call is written to the admin_actions audit table.
"""
import hmac
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend import db, limits, plans

MIN_KEY_LENGTH = 24
FAIL_BUCKET = "admin_fail"
FAIL_ENV = "ADMIN_FAIL_LIMIT_PER_HOUR"


def require_admin(request: Request, x_admin_key: str | None = Header(default=None)) -> None:
    key = os.getenv("ADMIN_API_KEY", "")
    if len(key) < MIN_KEY_LENGTH:
        raise HTTPException(status_code=503, detail="The admin API is not configured.")

    limits.failure_gate(request, FAIL_BUCKET, FAIL_ENV, 10, "invalid admin key attempts")
    if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), key.encode()):
        limits.record_failure(request, FAIL_BUCKET, FAIL_ENV, 10)
        raise HTTPException(status_code=401, detail="Invalid admin key.")


router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(require_admin), Depends(limits.limit_by_ip("admin", "ADMIN_RATE_LIMIT_PER_HOUR", 600))],
)


def _audit(session: Session, request: Request, action: str, target: str | None = None, detail: str | None = None):
    session.add(db.AdminAction(action=action, target=target, detail=detail, ip=limits.client_ip(request)))


# ---------------------------------------------------------------- stats


@router.get("/stats")
def stats(request: Request, session: Session = Depends(db.get_db)):
    now = datetime.now(timezone.utc)
    day_ago, week_ago = now - timedelta(days=1), now - timedelta(days=7)
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    count = lambda q: q.scalar() or 0  # noqa: E731

    active = [s for s in session.query(db.Subscription) if plans._entitled(s, now)]
    by_plan: dict[str, int] = {}
    for sub in active:
        by_plan[sub.plan] = by_plan.get(sub.plan, 0) + 1

    jobs_by_status = dict(
        session.query(db.ScanJob.status, func.count(db.ScanJob.id)).group_by(db.ScanJob.status).all()
    )
    cap = limits._int_env("DAILY_SCAN_CAP", 500)
    used_today = count(session.query(func.count(db.ScanRun.id)).filter(db.ScanRun.started_at >= start_of_day))

    _audit(session, request, "stats")
    session.commit()
    return {
        "users": {
            "total": count(session.query(func.count(db.User.id))),
            "new_7d": count(session.query(func.count(db.User.id)).filter(db.User.created_at >= week_ago)),
        },
        "organizations": count(session.query(func.count(db.Organization.id))),
        "github_connections": count(session.query(func.count(db.GithubConnection.id))),
        "scans": {
            "total": count(session.query(func.count(db.Scan.id))),
            "last_24h": count(session.query(func.count(db.Scan.id)).filter(db.Scan.created_at >= day_ago)),
            "failed_24h": count(
                session.query(func.count(db.Scan.id)).filter(db.Scan.created_at >= day_ago, db.Scan.status == "failed")
            ),
        },
        "usage_today": {"runs": used_today, "daily_cap": cap or None, "remaining": max(cap - used_today, 0) if cap else None},
        "active_subscriptions": by_plan,
        "jobs": jobs_by_status,
    }


# ---------------------------------------------------------------- users


@router.get("/users")
def find_users(
    request: Request,
    email: str = Query(default="", max_length=254),
    limit: int = Query(default=20, ge=1, le=50),
    session: Session = Depends(db.get_db),
):
    query = session.query(db.User)
    if email.strip():
        like = "%" + email.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.filter(db.User.email.ilike(like, escape="\\"))
    users = query.order_by(db.User.created_at.desc()).limit(limit).all()

    out = []
    for u in users:
        out.append(
            {
                "id": u.id,
                "email": u.email,
                "clerk_user_id": u.clerk_user_id,
                "created_at": u.created_at,
                "plan": plans.plan_for_user(session, u).name,
                "scans": session.query(func.count(db.Scan.id)).filter_by(owner_user_id=u.id).scalar(),
                "orgs": session.query(func.count(db.Membership.id)).filter_by(user_id=u.id).scalar(),
                "github_connected": session.query(db.GithubConnection).filter_by(user_id=u.id).first() is not None,
                "subscriptions": [
                    {"id": s.id, "provider": s.provider, "plan": s.plan, "status": s.status,
                     "current_period_end": s.current_period_end}
                    for s in session.query(db.Subscription).filter_by(user_id=u.id)
                ],
            }
        )
    _audit(session, request, "find_users", detail=f"email~{email.strip()[:60]!r} -> {len(out)} result(s)")
    session.commit()
    return out


# ---------------------------------------------------------------- comp plans


class Grant(BaseModel):
    days: int = Field(..., ge=1, le=365)
    note: str = Field(default="", max_length=200)


def _grant(session: Session, request: Request, plan: Literal["pro", "team"], days: int, note: str, **owner) -> dict:
    sub = db.Subscription(
        provider="manual",
        provider_subscription_id=f"manual-{uuid.uuid4()}",
        plan=plan,
        status="active",
        current_period_end=datetime.now(timezone.utc) + timedelta(days=days),
        **owner,
    )
    session.add(sub)
    session.flush()
    _audit(session, request, f"grant_{plan}", target=next(iter(owner.values())), detail=f"{days} days; {note}".strip("; "))
    session.commit()
    return {"subscription_id": sub.id, "plan": plan, "expires": sub.current_period_end}


@router.post("/users/{user_id}/plan", status_code=201)
def grant_pro(user_id: str, payload: Grant, request: Request, session: Session = Depends(db.get_db)):
    if session.get(db.User, user_id) is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _grant(session, request, "pro", payload.days, payload.note, user_id=user_id)


@router.post("/orgs/{org_id}/plan", status_code=201)
def grant_team(org_id: str, payload: Grant, request: Request, session: Session = Depends(db.get_db)):
    if session.get(db.Organization, org_id) is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return _grant(session, request, "team", payload.days, payload.note, org_id=org_id)


@router.delete("/subscriptions/{subscription_id}")
def end_manual_subscription(subscription_id: str, request: Request, session: Session = Depends(db.get_db)):
    sub = session.get(db.Subscription, subscription_id)
    if sub is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if sub.provider != "manual":
        raise HTTPException(
            status_code=409,
            detail="Only complimentary (manual) plans can be ended here; cancel provider subscriptions with the provider.",
        )
    sub.status = "expired"
    _audit(session, request, "end_manual_subscription", target=sub.user_id or sub.org_id, detail=sub.id)
    session.commit()
    return {"subscription_id": sub.id, "status": "expired"}


# ---------------------------------------------------------------- audit


@router.get("/audit")
def audit_log(limit: int = Query(default=50, ge=1, le=200), session: Session = Depends(db.get_db)):
    rows = session.query(db.AdminAction).order_by(db.AdminAction.at.desc()).limit(limit).all()
    return [{"at": r.at, "action": r.action, "target": r.target, "detail": r.detail, "ip": r.ip} for r in rows]

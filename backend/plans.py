"""Plans, entitlements, and usage metering.

Plan limits (including private-repo access) are only ENFORCED when ENFORCE_PLAN_LIMITS=1, so a demo or a
pre-launch deployment is never paywalled by accident. Usage is always
computed (see /me) so the numbers are ready the day enforcement is turned on.

Usage is counted from scan_runs (one row per scan or rescan started) rather
than a separate counter, so it can never drift from what actually ran.
Webhook-triggered runs are a paid feature and are not metered.
"""
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import and_, false, func, or_
from sqlalchemy.orm import Session

from backend import db
from backend.access import Actor


@dataclass(frozen=True)
class Plan:
    name: str
    monthly_scans: int | None  # None = unlimited
    auto_rescan: bool  # re-scan on push (webhook)
    max_org_members: int
    private_repos: bool = False  # scan private GitHub repos through the user's connected account


PLANS = {
    "free": Plan("free", monthly_scans=5, auto_rescan=False, max_org_members=1),
    "pro": Plan("pro", monthly_scans=None, auto_rescan=True, max_org_members=1, private_repos=True),
    "team": Plan("team", monthly_scans=None, auto_rescan=True, max_org_members=5, private_repos=True),
}
_RANK = {"free": 0, "pro": 1, "team": 2}

METERED_KINDS = ("scan", "rescan")


def enforcement_enabled() -> bool:
    return os.getenv("ENFORCE_PLAN_LIMITS") == "1"


def _entitled(sub: db.Subscription, now: datetime) -> bool:
    """Active/trialing subscriptions count; a canceled one stays valid until
    the period the customer already paid for ends."""
    if sub.status in ("active", "trialing"):
        return True
    if sub.status == "canceled" and sub.current_period_end is not None:
        end = sub.current_period_end
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return end > now
    return False


def _best(plan_names) -> Plan:
    best = max(plan_names, key=lambda n: _RANK.get(n, 0), default="free")
    return PLANS.get(best, PLANS["free"])


def plan_for_user(session: Session, user: db.User | None) -> Plan:
    if user is None:
        return PLANS["free"]
    now = datetime.now(timezone.utc)
    org_ids = [m.org_id for m in session.query(db.Membership).filter_by(user_id=user.id)]
    conditions = [db.Subscription.user_id == user.id]
    if org_ids:
        conditions.append(db.Subscription.org_id.in_(org_ids))
    subs = session.query(db.Subscription).filter(or_(*conditions))
    return _best(["free"] + [s.plan for s in subs if _entitled(s, now)])


def pending_invite_count(session: Session, org_id: str) -> int:
    """Invites that could still be accepted; they hold a seat until they expire or are revoked."""
    now = datetime.now(timezone.utc)
    return (
        session.query(func.count(db.OrgInvite.id))
        .filter(
            db.OrgInvite.org_id == org_id,
            db.OrgInvite.accepted_at.is_(None),
            db.OrgInvite.revoked_at.is_(None),
            db.OrgInvite.expires_at > now,
        )
        .scalar()
    )


def plan_for_org(session: Session, org_id: str) -> Plan:
    now = datetime.now(timezone.utc)
    subs = session.query(db.Subscription).filter_by(org_id=org_id)
    return _best(["free"] + [s.plan for s in subs if _entitled(s, now)])


def plan_for_scan_owner(session: Session, scan: db.Scan) -> Plan:
    user = session.get(db.User, scan.owner_user_id) if scan.owner_user_id else None
    return plan_for_user(session, user)


def month_start() -> datetime:
    return datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _run_owner_clause(actor: Actor):
    """Usage records belonging to this actor (account, and any still-unclaimed anonymous token)."""
    clauses = []
    if actor.user is not None:
        clauses.append(db.ScanRun.owner_user_id == actor.user.id)
    if actor.owner_token:
        clauses.append(and_(db.ScanRun.owner_token == actor.owner_token, db.ScanRun.owner_user_id.is_(None)))
    return or_(*clauses) if clauses else false()


def monthly_usage(session: Session, actor: Actor) -> int:
    return (
        session.query(func.count(db.ScanRun.id))
        .filter(_run_owner_clause(actor), db.ScanRun.kind.in_(METERED_KINDS), db.ScanRun.started_at >= month_start())
        .scalar()
    )


def enforce_monthly_limit(session: Session, actor: Actor) -> None:
    """Raises 402 when the actor's plan has a monthly scan limit and it is used up."""
    if not enforcement_enabled():
        return
    plan = plan_for_user(session, actor.user)
    if plan.monthly_scans is None:
        return
    if monthly_usage(session, actor) >= plan.monthly_scans:
        raise HTTPException(
            status_code=402,
            detail=(
                f"You've used all {plan.monthly_scans} scans included in the free plan this month. "
                "Upgrade to Pro for unlimited scans and re-scan on every push."
            ),
        )

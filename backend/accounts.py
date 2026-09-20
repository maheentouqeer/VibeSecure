"""Account, organization, and billing endpoints.

  GET    /me                          who am I, my plan, this month's usage
  POST   /me/claim                    move anonymous scans (X-Owner-Token) into my account
  POST   /orgs                        create an organization (I become owner)
  GET    /orgs                        organizations I belong to
  POST   /orgs/{id}/members           add an existing user by email (owner/admin)
  DELETE /orgs/{id}/members/{user}    remove a member, or leave (owner/admin, or self)
  GET    /orgs/{id}/dashboard         pass/fail across every member's projects (owner/admin)
  POST   /webhooks/billing            subscription events from the payment provider

The billing webhook speaks a small provider-neutral contract (see
BillingEvent). A payment provider is connected by mapping its own events to
that shape; nothing here depends on one vendor's payload format.
"""
import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from backend import db, deletion, github_oauth, limits, plans
from backend.access import ADMIN_ROLES, Actor, org_role, scan_owner_clause
from backend.auth import get_actor, require_user

router = APIRouter()

# Org changes and deletions are throttled per user so a script (or a stolen token) can't churn them.
_mutation_limit = Depends(limits.limit_by_user("mutation", "MUTATION_RATE_LIMIT_PER_HOUR", 120, "changes"))


# --- /me -------------------------------------------------------------------


class MeResponse(BaseModel):
    user: dict | None
    plan: str
    limits: dict
    usage: dict
    enforced: bool
    orgs: list[dict]


@router.get("/me", response_model=MeResponse)
def me(actor: Actor = Depends(get_actor), session: Session = Depends(db.get_db)):
    plan = plans.plan_for_user(session, actor.user)
    orgs = []
    if actor.user:
        for m in session.query(db.Membership).filter_by(user_id=actor.user.id):
            orgs.append({"id": m.org_id, "name": m.organization.name, "role": m.role})
    return MeResponse(
        user={"id": actor.user.id, "email": actor.user.email} if actor.user else None,
        plan=plan.name,
        limits={"monthly_scans": plan.monthly_scans, "auto_rescan": plan.auto_rescan},
        usage={"scans_this_month": plans.monthly_usage(session, actor)},
        enforced=plans.enforcement_enabled(),
        orgs=orgs,
    )


@router.post("/me/claim")
def claim_anonymous_scans(
    user: db.User = Depends(require_user),
    actor: Actor = Depends(get_actor),
    session: Session = Depends(db.get_db),
):
    """Attach every scan made with this browser's anonymous owner token to the
    signed-in account. Idempotent; scans already claimed are left alone."""
    if not actor.owner_token:
        return {"claimed": 0}
    claimed = session.execute(
        update(db.Scan)
        .where(db.Scan.owner_token == actor.owner_token, db.Scan.owner_user_id.is_(None))
        .values(owner_user_id=user.id)
    ).rowcount
    session.execute(
        update(db.ScanRun)
        .where(db.ScanRun.owner_token == actor.owner_token, db.ScanRun.owner_user_id.is_(None))
        .values(owner_user_id=user.id)
    )
    session.commit()
    return {"claimed": claimed}


@router.delete("/me", status_code=204, dependencies=[_mutation_limit])
def delete_my_account(user: db.User = Depends(require_user), session: Session = Depends(db.get_db)):
    """Permanently deletes the account and all its scans. Refused (409) while
    there is an active subscription, a running scan, or an organization with
    other members. Usage counts are kept anonymously (see backend/deletion.py)."""
    conn = session.query(db.GithubConnection).filter_by(user_id=user.id).one_or_none()
    github_token = github_oauth.decrypt_token(conn.encrypted_token) if conn else None
    try:
        deletion.delete_account(session, user)
        session.commit()
    except HTTPException:
        session.rollback()
        raise
    if github_token and github_oauth.configured():
        github_oauth._revoke(github_token)  # best effort, after the data is gone
    return Response(status_code=204)


# --- organizations ---------------------------------------------------------


class OrgCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


class MemberAdd(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    role: Literal["member", "admin"] = "member"


def _require_org_admin(session: Session, user: db.User, org_id: str) -> str:
    role = org_role(session, user, org_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Only organization owners and admins can do that.")
    return role


@router.post("/orgs", status_code=201, dependencies=[_mutation_limit])
def create_org(payload: OrgCreate, user: db.User = Depends(require_user), session: Session = Depends(db.get_db)):
    org = db.Organization(name=payload.name.strip(), owner_user_id=user.id)
    session.add(org)
    session.flush()
    session.add(db.Membership(user_id=user.id, org_id=org.id, role="owner"))
    session.commit()
    return {"id": org.id, "name": org.name, "role": "owner", "created_at": org.created_at}


@router.get("/orgs")
def list_orgs(user: db.User = Depends(require_user), session: Session = Depends(db.get_db)):
    out = []
    for m in session.query(db.Membership).filter_by(user_id=user.id):
        out.append(
            {
                "id": m.org_id,
                "name": m.organization.name,
                "role": m.role,
                "member_count": session.query(db.Membership).filter_by(org_id=m.org_id).count(),
            }
        )
    return out


@router.post("/orgs/{org_id}/members", status_code=201, dependencies=[_mutation_limit])
def add_member(
    org_id: str,
    payload: MemberAdd,
    user: db.User = Depends(require_user),
    session: Session = Depends(db.get_db),
):
    caller_role = _require_org_admin(session, user, org_id)
    if payload.role == "admin" and caller_role != "owner":
        raise HTTPException(status_code=403, detail="Only the organization owner can add admins.")

    email = payload.email.strip().lower()
    target = session.query(db.User).filter(db.User.email.ilike(email)).first()
    if target is None:
        raise HTTPException(
            status_code=404,
            detail="No account with that email yet. Ask them to sign in to Secure-VibeCode once, then add them.",
        )
    if org_role(session, target, org_id) is not None:
        raise HTTPException(status_code=409, detail="That user is already a member.")

    if plans.enforcement_enabled():
        seats = plans.plan_for_org(session, org_id).max_org_members
        if session.query(db.Membership).filter_by(org_id=org_id).count() >= seats:
            raise HTTPException(
                status_code=402,
                detail=f"This organization's plan includes {seats} seat(s). Upgrade to the Team plan to add more.",
            )

    session.add(db.Membership(user_id=target.id, org_id=org_id, role=payload.role))
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="That user is already a member.")
    return {"user_id": target.id, "email": target.email, "role": payload.role}


@router.delete("/orgs/{org_id}/members/{member_user_id}", status_code=204, dependencies=[_mutation_limit])
def remove_member(
    org_id: str,
    member_user_id: str,
    user: db.User = Depends(require_user),
    session: Session = Depends(db.get_db),
):
    caller_role = org_role(session, user, org_id)
    if caller_role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if member_user_id != user.id and caller_role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Only organization owners and admins can remove other members.")

    membership = session.query(db.Membership).filter_by(user_id=member_user_id, org_id=org_id).one_or_none()
    if membership is None:
        raise HTTPException(status_code=404, detail="Member not found")
    if membership.role == "owner":
        raise HTTPException(status_code=400, detail="The organization owner cannot be removed.")
    if membership.role == "admin" and member_user_id != user.id and caller_role != "owner":
        raise HTTPException(status_code=403, detail="Only the organization owner can remove admins.")
    session.delete(membership)
    session.commit()
    return Response(status_code=204)


class RoleChange(BaseModel):
    role: Literal["member", "admin"]


class OwnershipTransfer(BaseModel):
    user_id: str = Field(..., min_length=1)


@router.patch("/orgs/{org_id}/members/{member_user_id}", dependencies=[_mutation_limit])
def change_member_role(
    org_id: str,
    member_user_id: str,
    payload: RoleChange,
    user: db.User = Depends(require_user),
    session: Session = Depends(db.get_db),
):
    """Owner only: promote a member to admin or demote an admin to member.
    Ownership itself only moves through /transfer."""
    role = org_role(session, user, org_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if role != "owner":
        raise HTTPException(status_code=403, detail="Only the organization owner can change roles.")

    membership = session.query(db.Membership).filter_by(user_id=member_user_id, org_id=org_id).one_or_none()
    if membership is None:
        raise HTTPException(status_code=404, detail="Member not found")
    if membership.role == "owner":
        raise HTTPException(status_code=400, detail="The owner's role can only change by transferring ownership.")
    membership.role = payload.role
    session.commit()
    return {"user_id": member_user_id, "role": payload.role}


@router.post("/orgs/{org_id}/transfer", dependencies=[_mutation_limit])
def transfer_ownership(
    org_id: str,
    payload: OwnershipTransfer,
    user: db.User = Depends(require_user),
    session: Session = Depends(db.get_db),
):
    """Owner only: hand the organization to another member. The previous
    owner becomes an admin. Each step is a conditional UPDATE, so of two
    simultaneous transfers only the one from the current owner can succeed."""
    role = org_role(session, user, org_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if role != "owner":
        raise HTTPException(status_code=403, detail="Only the organization owner can transfer ownership.")
    if payload.user_id == user.id:
        raise HTTPException(status_code=400, detail="You already own this organization.")

    demoted = session.execute(
        update(db.Membership)
        .where(db.Membership.org_id == org_id, db.Membership.user_id == user.id, db.Membership.role == "owner")
        .values(role="admin")
    ).rowcount
    if demoted != 1:  # ownership moved under us
        session.rollback()
        raise HTTPException(status_code=403, detail="Only the organization owner can transfer ownership.")

    promoted = session.execute(
        update(db.Membership)
        .where(
            db.Membership.org_id == org_id,
            db.Membership.user_id == payload.user_id,
            db.Membership.role.in_(("member", "admin")),
        )
        .values(role="owner")
    ).rowcount
    if promoted != 1:
        session.rollback()  # also undoes the demotion above
        raise HTTPException(status_code=404, detail="That user is not a member of this organization.")

    session.execute(update(db.Organization).where(db.Organization.id == org_id).values(owner_user_id=payload.user_id))
    session.commit()
    return {"org_id": org_id, "owner_user_id": payload.user_id, "previous_owner_role": "admin"}


@router.delete("/orgs/{org_id}", status_code=204, dependencies=[_mutation_limit])
def delete_org(org_id: str, user: db.User = Depends(require_user), session: Session = Depends(db.get_db)):
    """Owner only. Members keep their scans; they are just no longer filed
    under the organization."""
    role = org_role(session, user, org_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if role != "owner":
        raise HTTPException(status_code=403, detail="Only the organization owner can delete it.")
    try:
        deletion.delete_org(session, session.get(db.Organization, org_id))
        session.commit()
    except HTTPException:
        session.rollback()
        raise
    return Response(status_code=204)


def _project_summary(scan: db.Scan) -> dict:
    open_critical = sum(1 for f in scan.findings if f.status == "open" and f.severity == "critical")
    open_high = sum(1 for f in scan.findings if f.status == "open" and f.severity == "high")
    finished = scan.status in ("completed", "failed")
    return {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "passed": (open_critical == 0 and open_high == 0) if scan.status == "completed" else None,
        "open_critical": open_critical,
        "open_high": open_high,
        "scanned_at": scan.created_at,
        "finished": finished,
    }


@router.get("/orgs/{org_id}/dashboard")
def org_dashboard(org_id: str, user: db.User = Depends(require_user), session: Session = Depends(db.get_db)):
    """The organizer view: every member's projects with pass/fail, using each
    project's most recent scan."""
    _require_org_admin(session, user, org_id)
    org = session.get(db.Organization, org_id)

    scans = (
        session.query(db.Scan)
        .options(selectinload(db.Scan.findings))
        .filter(db.Scan.org_id == org_id)
        .order_by(db.Scan.created_at.desc())
        .all()
    )
    latest: dict[tuple[str | None, str], db.Scan] = {}
    for scan in scans:  # newest first, so the first one seen per (member, target) is the latest
        latest.setdefault((scan.owner_user_id, scan.target), scan)

    members = []
    summary = {"projects": 0, "passing": 0, "failing": 0, "in_progress": 0}
    for m in session.query(db.Membership).filter_by(org_id=org_id):
        projects = [_project_summary(s) for (owner, _), s in latest.items() if owner == m.user_id]
        for p in projects:
            summary["projects"] += 1
            if p["status"] in ("queued", "running"):
                summary["in_progress"] += 1
            elif p["passed"] is True:
                summary["passing"] += 1
            else:
                summary["failing"] += 1
        members.append({"user_id": m.user_id, "email": m.user.email, "role": m.role, "projects": projects})

    return {"org": {"id": org.id, "name": org.name}, "summary": summary, "members": members}


# --- billing webhook -------------------------------------------------------


class BillingUser(BaseModel):
    clerk_user_id: str | None = None
    email: str | None = None


class BillingEvent(BaseModel):
    """Provider-neutral subscription event.

    plan "pro" belongs to a user (`user`); plan "team" belongs to an
    organization (`org_id`). `status` defaults from the event name."""

    event: Literal["subscription.activated", "subscription.updated", "subscription.canceled", "subscription.expired"]
    provider: str = "generic"
    plan: Literal["pro", "team"]
    provider_subscription_id: str = Field(..., min_length=1)
    provider_customer_id: str | None = None
    status: Literal["active", "trialing", "past_due", "canceled", "expired"] | None = None
    current_period_end: datetime | None = None
    user: BillingUser | None = None
    org_id: str | None = None


_EVENT_STATUS = {
    "subscription.activated": "active",
    "subscription.updated": "active",
    "subscription.canceled": "canceled",
    "subscription.expired": "expired",
}


@router.post("/webhooks/billing")
async def billing_webhook(
    request: Request,
    session: Session = Depends(db.get_db),
    x_billing_signature: str | None = Header(default=None),
):
    """Requires BILLING_WEBHOOK_SECRET. The body must be signed with
    HMAC-SHA256 and sent as `X-Billing-Signature: sha256=<hex>`. Safe to
    retry: events are applied idempotently by (provider, subscription id)."""
    secret = os.getenv("BILLING_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=503, detail="Billing webhooks are not configured.")

    limits.webhook_gate(request)
    body = await request.body()
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not x_billing_signature or not hmac.compare_digest(expected, x_billing_signature):
        limits.webhook_failed(request)
        raise HTTPException(status_code=401, detail="Invalid signature.")

    try:
        event = BillingEvent.model_validate_json(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Malformed billing event: {exc.__class__.__name__}")

    return apply_billing_event(session, event)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def apply_billing_event(
    session: Session,
    event: BillingEvent,
    event_at: datetime | None = None,
    create_missing_user: bool = False,
) -> dict:
    """Applies one provider-neutral subscription event. Idempotent, and safe
    against out-of-order delivery when `event_at` (when the provider says it
    happened) is known: an event older than the last applied one is ignored.

    A pro subscription for an unknown user is a 404 (so a provider retries)
    unless `create_missing_user` is set and the event names a clerk_user_id, in
    which case the user row is created now and completed when they sign in --
    for providers that give up after days of failed deliveries."""
    user_id: str | None = None
    org_id: str | None = None
    if event.plan == "team":
        if not event.org_id:
            raise HTTPException(status_code=400, detail="A team subscription needs an org_id.")
        if session.get(db.Organization, event.org_id) is None:
            raise HTTPException(status_code=404, detail="Organization not found.")
        org_id = event.org_id
    else:
        if event.user is None or not (event.user.clerk_user_id or event.user.email):
            raise HTTPException(status_code=400, detail="A pro subscription needs a user (clerk_user_id or email).")
        query = session.query(db.User)
        user = (
            query.filter_by(clerk_user_id=event.user.clerk_user_id).one_or_none()
            if event.user.clerk_user_id
            else query.filter(db.User.email.ilike(event.user.email)).first()
        )
        if user is None and create_missing_user and event.user.clerk_user_id:
            user = db.User(clerk_user_id=event.user.clerk_user_id, email=event.user.email)
            session.add(user)
            session.flush()
        if user is None:
            # 404 makes the provider retry, by which time the customer has usually signed in.
            raise HTTPException(status_code=404, detail="No matching user yet.")
        user_id = user.id

    status = event.status or _EVENT_STATUS[event.event]
    sub = (
        session.query(db.Subscription)
        .filter_by(provider=event.provider, provider_subscription_id=event.provider_subscription_id)
        .one_or_none()
    )
    if sub is not None and event_at is not None and sub.last_event_at is not None:
        if _aware(event_at) < _aware(sub.last_event_at):
            session.rollback()
            return {"ok": True, "status": sub.status, "note": "stale event ignored"}
    if sub is None:
        sub = db.Subscription(provider=event.provider, provider_subscription_id=event.provider_subscription_id)
        session.add(sub)
    sub.user_id, sub.org_id = user_id, org_id
    sub.plan = event.plan
    sub.status = status
    sub.provider_customer_id = event.provider_customer_id or sub.provider_customer_id
    if event.current_period_end is not None:
        sub.current_period_end = _aware(event.current_period_end)
    if event_at is not None:
        sub.last_event_at = _aware(event_at)
    try:
        session.commit()
    except IntegrityError:  # two deliveries of the same new subscription raced
        session.rollback()
        raise HTTPException(status_code=409, detail="Concurrent update for this subscription; retry.")
    return {"ok": True, "status": status}

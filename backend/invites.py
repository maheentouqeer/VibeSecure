"""Organization invite links.

  POST   /orgs/{id}/invites          create a single-use invite link (owner/admin)
  GET    /orgs/{id}/invites          list pending invites (never their tokens)
  DELETE /orgs/{id}/invites/{invite}  revoke one
  GET    /invites/preview?token=     what am I being invited to? (no sign-in needed)
  POST   /invites/accept             join the organization (signed in)

Why links: adding a member by email only works for people who have already
signed in once. An invite works for anyone -- the owner shares the link (chat,
email, whatever), the person signs up, then accepts it. Sending the email
itself can be bolted on later; nothing here depends on it.

Safety properties:
  * The secret token is 256 random bits, shown ONCE at creation. Only its
    SHA-256 hash is stored, so a database leak yields no usable invites.
  * An invite works once. Acceptance is a single conditional UPDATE, so two
    people (or two clicks) racing for the same link cannot both get in.
  * Invites expire (INVITE_TTL_DAYS, default 7), can be revoked, and while
    pending they hold a seat against the plan's member limit.
  * An invite created for an email address only works for that address. The
    address comes from the sign-in token, so include the email claim in your
    Supabase Auth session token; otherwise create link-only invites (no email).
  * Unknown, expired, revoked and used tokens all get the same answer, so the
    endpoint can't be used to learn which tokens exist.
  * Only owners can create admin invites; admins can create member invites.
"""
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend import db, limits, plans
from backend.accounts import _require_org_admin
from backend.access import org_role
from backend.auth import require_user

router = APIRouter()

MAX_PENDING_PER_ORG = 50
_NOT_VALID = "This invite is invalid or has expired."
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_mutation_limit = Depends(limits.limit_by_user("mutation", "MUTATION_RATE_LIMIT_PER_HOUR", 120, "changes"))
_invite_limit = Depends(limits.limit_by_ip("invite", "INVITE_RATE_LIMIT_PER_HOUR", 30, "invite attempts"))


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _ttl_days() -> int:
    try:
        return min(max(int(os.getenv("INVITE_TTL_DAYS", "7")), 1), 60)
    except ValueError:
        return 7


def _is_pending(invite: db.OrgInvite, now: datetime) -> bool:
    return invite.accepted_at is None and invite.revoked_at is None and _aware(invite.expires_at) > now


class InviteCreate(BaseModel):
    email: str | None = Field(default=None, max_length=254, description="Optional: restrict the invite to this address")
    role: Literal["member", "admin"] = "member"


class InviteAccept(BaseModel):
    token: str = Field(..., min_length=10, max_length=200)


# ------------------------------------------------------------------ manage


@router.post("/orgs/{org_id}/invites", status_code=201, dependencies=[_mutation_limit])
def create_invite(
    org_id: str,
    payload: InviteCreate,
    user: db.User = Depends(require_user),
    session: Session = Depends(db.get_db),
):
    caller_role = _require_org_admin(session, user, org_id)
    if payload.role == "admin" and caller_role != "owner":
        raise HTTPException(status_code=403, detail="Only the organization owner can invite admins.")

    email = (payload.email or "").strip().lower() or None
    if email and not _EMAIL.match(email):
        raise HTTPException(status_code=422, detail="That does not look like an email address.")
    if email:
        existing = session.query(db.User).filter(db.User.email.ilike(email)).first()
        if existing is not None and org_role(session, existing, org_id) is not None:
            raise HTTPException(status_code=409, detail="That person is already a member.")

    now = _now()
    if email:  # re-inviting the same address replaces the older link instead of stacking them up
        session.execute(
            update(db.OrgInvite)
            .where(
                db.OrgInvite.org_id == org_id, db.OrgInvite.email == email,
                db.OrgInvite.accepted_at.is_(None), db.OrgInvite.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )

    pending = plans.pending_invite_count(session, org_id)
    if pending >= MAX_PENDING_PER_ORG:
        session.rollback()
        raise HTTPException(status_code=429, detail=f"This organization already has {MAX_PENDING_PER_ORG} pending invites.")
    if plans.enforcement_enabled():
        seats = plans.plan_for_org(session, org_id).max_org_members
        if session.query(db.Membership).filter_by(org_id=org_id).count() + pending >= seats:
            session.rollback()
            raise HTTPException(
                status_code=402,
                detail=f"This organization's plan includes {seats} seat(s), including pending invites. Upgrade to the Team plan to add more.",
            )

    token = secrets.token_urlsafe(32)
    invite = db.OrgInvite(
        org_id=org_id, email=email, role=payload.role, token_hash=_hash(token),
        invited_by=user.id, expires_at=now + timedelta(days=_ttl_days()),
    )
    session.add(invite)
    session.commit()

    front = os.getenv("FRONTEND_URL", "").rstrip("/")
    return {
        "id": invite.id,
        "email": email,
        "role": invite.role,
        "expires_at": invite.expires_at,
        "token": token,  # shown once; only its hash is kept
        "url": f"{front}?invite={token}" if front.startswith(("http://", "https://")) else None,
    }


@router.get("/orgs/{org_id}/invites")
def list_invites(org_id: str, user: db.User = Depends(require_user), session: Session = Depends(db.get_db)):
    _require_org_admin(session, user, org_id)
    now = _now()
    rows = (
        session.query(db.OrgInvite)
        .filter(db.OrgInvite.org_id == org_id, db.OrgInvite.accepted_at.is_(None), db.OrgInvite.revoked_at.is_(None))
        .order_by(db.OrgInvite.created_at.desc())
        .all()
    )
    return [
        {"id": i.id, "email": i.email, "role": i.role, "created_at": i.created_at, "expires_at": i.expires_at}
        for i in rows
        if _is_pending(i, now)
    ]


@router.delete("/orgs/{org_id}/invites/{invite_id}", status_code=204, dependencies=[_mutation_limit])
def revoke_invite(
    org_id: str, invite_id: str, user: db.User = Depends(require_user), session: Session = Depends(db.get_db)
):
    caller_role = _require_org_admin(session, user, org_id)
    invite = session.get(db.OrgInvite, invite_id)
    if invite is None or invite.org_id != org_id or not _is_pending(invite, _now()):
        raise HTTPException(status_code=404, detail="Invite not found")
    if invite.role == "admin" and caller_role != "owner":
        raise HTTPException(status_code=403, detail="Only the organization owner can revoke admin invites.")
    invite.revoked_at = _now()
    session.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------ redeem


def _find_pending(session: Session, token: str) -> db.OrgInvite:
    invite = session.query(db.OrgInvite).filter_by(token_hash=_hash(token.strip())).one_or_none()
    if invite is None or not _is_pending(invite, _now()):
        raise HTTPException(status_code=404, detail=_NOT_VALID)
    return invite


@router.get("/invites/preview", dependencies=[_invite_limit])
def preview_invite(token: str = Query(..., min_length=10, max_length=200), session: Session = Depends(db.get_db)):
    """Lets the frontend show "Join <organization> as <role>?" before asking anyone to sign in."""
    invite = _find_pending(session, token)
    org = session.get(db.Organization, invite.org_id)
    return {
        "organization": org.name,
        "role": invite.role,
        "expires_at": invite.expires_at,
        "restricted_to_email": invite.email is not None,  # whether, not which: the address stays private
    }


@router.post("/invites/accept", dependencies=[_invite_limit])
def accept_invite(payload: InviteAccept, user: db.User = Depends(require_user), session: Session = Depends(db.get_db)):
    invite = _find_pending(session, payload.token)

    if invite.email is not None:
        if not user.email:
            raise HTTPException(
                status_code=403,
                detail="This invite is restricted to one email address, and your account has none we can verify.",
            )
        if user.email.strip().lower() != invite.email:
            raise HTTPException(status_code=403, detail="This invite was sent to a different email address.")

    if org_role(session, user, invite.org_id) is not None:
        raise HTTPException(status_code=409, detail="You are already a member of this organization.")

    if plans.enforcement_enabled():
        seats = plans.plan_for_org(session, invite.org_id).max_org_members
        # This invite's own seat is already counted among the pending ones.
        if session.query(db.Membership).filter_by(org_id=invite.org_id).count() + plans.pending_invite_count(session, invite.org_id) - 1 >= seats:
            raise HTTPException(status_code=402, detail="This organization has no free seats left.")

    now = _now()
    claimed = session.execute(
        update(db.OrgInvite)
        .where(
            db.OrgInvite.id == invite.id, db.OrgInvite.accepted_at.is_(None),
            db.OrgInvite.revoked_at.is_(None), db.OrgInvite.expires_at > now,
        )
        .values(accepted_at=now, accepted_by=user.id)
        .execution_options(synchronize_session=False)
    ).rowcount
    if claimed != 1:  # someone else used it first, or it was revoked a moment ago
        session.rollback()
        raise HTTPException(status_code=404, detail=_NOT_VALID)

    session.add(db.Membership(user_id=user.id, org_id=invite.org_id, role=invite.role))
    try:
        session.commit()  # the membership and "used" flag land together, or neither does
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="You are already a member of this organization.")

    org = session.get(db.Organization, invite.org_id)
    return {"organization_id": org.id, "organization": org.name, "role": invite.role}

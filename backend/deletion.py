"""Deleting data: scans, accounts, organizations, and the retention sweep.

What is kept, and why (this is what a privacy policy should say):
  * Usage records (scan_runs) outlive the scans they describe, so deleting
    scans can't reset a plan's monthly limit or the daily spend cap. They hold
    no code or findings, and are anonymized (scan and owner references
    removed) when an account is deleted.
  * Nothing else about a deleted scan is kept: findings, fix prompts, the
    target URL and queued jobs are all removed.

Deletion is refused (409) rather than guessed at when it would strand something:
an entitled paid subscription (cancel it with the payment provider first), an
organization that still has other members, or a scan that is mid-run.
"""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from backend import db
from backend.plans import _entitled

ACTIVE_STATUSES = ("queued", "running")


def delete_scan(session: Session, scan: db.Scan) -> None:
    """Removes a scan and everything hanging off it. Does not commit."""
    session.execute(update(db.ScanRun).where(db.ScanRun.scan_id == scan.id).values(scan_id=None))
    session.execute(delete(db.ScanJob).where(db.ScanJob.scan_id == scan.id))
    session.delete(scan)  # findings go with it (ORM cascade)


def _entitled_subscriptions(session: Session, **owner) -> list[db.Subscription]:
    now = datetime.now(timezone.utc)
    return [s for s in session.query(db.Subscription).filter_by(**owner) if _entitled(s, now)]


def delete_org(session: Session, org: db.Organization) -> None:
    """Removes an organization. Its scans stay with the members who made
    them, just no longer filed under the organization. Does not commit."""
    if _entitled_subscriptions(session, org_id=org.id):
        raise HTTPException(
            status_code=409,
            detail="This organization has an active Team subscription. Cancel it with the payment provider first.",
        )
    session.execute(update(db.Scan).where(db.Scan.org_id == org.id).values(org_id=None))
    session.execute(delete(db.OrgInvite).where(db.OrgInvite.org_id == org.id))
    session.execute(delete(db.Subscription).where(db.Subscription.org_id == org.id))
    session.delete(org)  # memberships go with it (ORM cascade)


def delete_account(session: Session, user: db.User) -> None:
    """Removes a user and all their scans. Does not commit; raises 409 (leaving
    the session for the caller to roll back) if it can't proceed safely."""
    if _entitled_subscriptions(session, user_id=user.id):
        raise HTTPException(
            status_code=409,
            detail="You have an active subscription. Cancel it with the payment provider first, then delete your account.",
        )

    scans = session.query(db.Scan).filter_by(owner_user_id=user.id).all()
    if any(s.status in ACTIVE_STATUSES for s in scans):
        raise HTTPException(status_code=409, detail="A scan is still running. Wait for it to finish, then try again.")

    owned_orgs = session.query(db.Organization).filter_by(owner_user_id=user.id).all()
    for org in owned_orgs:
        others = session.query(db.Membership).filter(
            db.Membership.org_id == org.id, db.Membership.user_id != user.id
        ).count()
        if others:
            raise HTTPException(
                status_code=409,
                detail=f"You own the organization '{org.name}', which still has other members. Remove them or delete it first.",
            )
    # The ORM does not know that scans/organizations reference users, so it
    # would delete the user row first and violate the foreign keys on any
    # database that enforces them (Postgres). Flush the dependents out first.
    for org in owned_orgs:
        delete_org(session, org)
    for scan in scans:
        delete_scan(session, scan)
    session.flush()

    session.execute(
        update(db.ScanRun).where(db.ScanRun.owner_user_id == user.id).values(owner_user_id=None, owner_token=None)
    )
    session.execute(delete(db.Membership).where(db.Membership.user_id == user.id))
    # Invites this user sent (they lose meaning without their sender) and their trace on invites they accepted.
    session.execute(delete(db.OrgInvite).where(db.OrgInvite.invited_by == user.id))
    session.execute(update(db.OrgInvite).where(db.OrgInvite.accepted_by == user.id).values(accepted_by=None))
    session.execute(delete(db.Subscription).where(db.Subscription.user_id == user.id))
    session.execute(delete(db.GithubConnection).where(db.GithubConnection.user_id == user.id))
    session.flush()
    session.delete(user)


def purge_expired_anonymous_scans(session: Session, days: int) -> int:
    """Retention sweep: deletes finished scans that no account owns once they
    are older than `days`. Scans owned by accounts are never touched here."""
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    expired = (
        session.query(db.Scan)
        .filter(
            db.Scan.owner_user_id.is_(None),
            db.Scan.created_at < cutoff,
            db.Scan.status.notin_(ACTIVE_STATUSES),
        )
        .all()
    )
    for scan in expired:
        delete_scan(session, scan)
    session.commit()
    return len(expired)

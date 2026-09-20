"""Who may see or change what.

Rules for a scan:
  * The signed-in owner (scan.owner_user_id) always has access.
  * An anonymous owner_token grants access only while the scan is unclaimed
    (owner_user_id is null). Once an account claims a scan, the old token
    stops working, so a leaked or shared token can't outlive the migration.
  * Owners/admins of the scan's organization get read-only access.
A missing scan and a scan you may not see are indistinguishable (both 404).
"""
from fastapi import HTTPException
from sqlalchemy import and_, false, or_
from sqlalchemy.orm import Session

from backend import db
from backend.auth import Actor

__all__ = ["Actor", "scan_owner_clause", "org_role", "get_scan_or_404"]

ADMIN_ROLES = ("owner", "admin")


def scan_owner_clause(actor: Actor):
    """SQL condition matching exactly the scans this actor owns."""
    clauses = []
    if actor.user is not None:
        clauses.append(db.Scan.owner_user_id == actor.user.id)
    if actor.owner_token:
        clauses.append(and_(db.Scan.owner_token == actor.owner_token, db.Scan.owner_user_id.is_(None)))
    return or_(*clauses) if clauses else false()


def org_role(session: Session, user: db.User | None, org_id: str | None) -> str | None:
    if user is None or org_id is None:
        return None
    membership = session.query(db.Membership).filter_by(user_id=user.id, org_id=org_id).one_or_none()
    return membership.role if membership else None


def _owns(actor: Actor, scan: db.Scan) -> bool:
    if actor.user is not None and scan.owner_user_id == actor.user.id:
        return True
    return bool(
        actor.owner_token and scan.owner_user_id is None and actor.owner_token == scan.owner_token
    )


def get_scan_or_404(session: Session, scan_id: str, actor: Actor, *, allow_org_admin: bool = False) -> db.Scan:
    scan = session.get(db.Scan, scan_id)
    allowed = scan is not None and (
        _owns(actor, scan)
        or (allow_org_admin and org_role(session, actor.user, scan.org_id) in ADMIN_ROLES)
    )
    if not allowed:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return scan

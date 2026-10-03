"""Secure API-key creation and authentication for VibeSecure."""
from __future__ import annotations

import hashlib
import secrets
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Header, HTTPException
from sqlalchemy.orm import Session

from backend import db

KEY_PREFIX = "vsk_"
_context: ContextVar["ApiKeyContext | None"] = ContextVar("vibesecure_api_key_context", default=None)

@dataclass(frozen=True)
class ApiKeyContext:
    key_id: str
    user_id: str

def _now() -> datetime:
    return datetime.now(timezone.utc)

def generate_raw_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)

def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

def create_api_key(session: Session, user: db.User, label: str) -> tuple[db.ApiKey, str]:
    active = (
        session.query(db.ApiKey)
        .filter(db.ApiKey.user_id == user.id, db.ApiKey.revoked_at.is_(None))
        .count()
    )
    if active >= 10:
        raise HTTPException(status_code=400, detail="You can have at most 10 active API keys.")

    raw = generate_raw_key()
    row = db.ApiKey(
        user_id=user.id,
        label=(label.strip() or "VibeSecure API key")[:80],
        key_hash=hash_api_key(raw),
        key_prefix=raw[:12],
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row, raw

def authenticate_api_key(session: Session, raw_key: str) -> ApiKeyContext:
    if not raw_key.startswith(KEY_PREFIX) or len(raw_key) < 20:
        raise HTTPException(status_code=401, detail="Invalid VibeSecure API key.")
    row = (
        session.query(db.ApiKey)
        .filter(db.ApiKey.key_hash == hash_api_key(raw_key), db.ApiKey.revoked_at.is_(None))
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked VibeSecure API key.")
    row.last_used_at = _now()
    session.commit()
    return ApiKeyContext(key_id=row.id, user_id=row.user_id)

def authenticate_header(raw_key: str | None) -> ApiKeyContext:
    if not raw_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header.")
    with db.SessionLocal() as session:
        return authenticate_api_key(session, raw_key)

def get_current_api_key_context() -> ApiKeyContext:
    value = _context.get()
    if value is None:
        raise HTTPException(status_code=401, detail="MCP API key authentication is required.")
    return value

def set_api_key_context(value: ApiKeyContext):
    return _context.set(value)

def reset_api_key_context(token) -> None:
    _context.reset(token)

def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> ApiKeyContext:
    return authenticate_header(x_api_key)

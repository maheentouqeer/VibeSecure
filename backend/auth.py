"""Optional sign-in via Clerk session tokens (RS256 JWTs).

Anonymous use keeps working: with no Authorization header a request is
handled exactly as before, using the X-Owner-Token session token. A request
that DOES carry an Authorization header must carry a valid token -- it is
rejected with 401 rather than silently downgraded to anonymous, so a client
never believes it is signed in when it is not.

Configuration (environment):
  CLERK_JWKS_URL            e.g. https://<your-clerk-domain>/.well-known/jwks.json
                            (sign-in is disabled, and Bearer tokens get 503, when unset)
  CLERK_ISSUER              optional; if set, the token's `iss` must match
  CLERK_AUTHORIZED_PARTIES  optional comma-separated list; if set, the token's
                            `azp` (the frontend origin) must be one of them
"""
import os
from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend import db

_client: PyJWKClient | None = None
_client_url: str | None = None


def _get_jwks_client() -> PyJWKClient | None:
    global _client, _client_url
    url = os.getenv("CLERK_JWKS_URL")
    if not url:
        return None
    if _client is None or _client_url != url:
        _client = PyJWKClient(url, cache_keys=True, lifespan=3600)
        _client_url = url
    return _client


def verify_token(token: str) -> dict:
    client = _get_jwks_client()
    if client is None:
        raise HTTPException(status_code=503, detail="Sign-in is not configured on this server.")

    try:
        signing_key = client.get_signing_key_from_jwt(token).key
        issuer = os.getenv("CLERK_ISSUER") or None
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"require": ["exp", "sub"], "verify_aud": False, "verify_iss": issuer is not None},
        )
    except PyJWKClientConnectionError as exc:
        raise HTTPException(status_code=503, detail="Could not reach the sign-in provider.") from exc
    except (jwt.PyJWTError, PyJWKClientError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired sign-in token.") from exc

    allowed = [p.strip() for p in os.getenv("CLERK_AUTHORIZED_PARTIES", "").split(",") if p.strip()]
    if allowed and claims.get("azp") not in allowed:
        raise HTTPException(status_code=401, detail="Invalid or expired sign-in token.")
    return claims


def _upsert_user(session: Session, claims: dict) -> db.User:
    clerk_id = claims["sub"]
    email = claims.get("email") or None

    user = session.query(db.User).filter_by(clerk_user_id=clerk_id).one_or_none()
    if user is None:
        user = db.User(clerk_user_id=clerk_id, email=email)
        session.add(user)
        try:
            session.commit()
        except IntegrityError:  # a concurrent first request created it
            session.rollback()
            user = session.query(db.User).filter_by(clerk_user_id=clerk_id).one()
    elif email and user.email != email:
        user.email = email
        session.commit()
    return user


@dataclass
class Actor:
    """Who is making the request: a signed-in user, an anonymous owner
    token, or both (a signed-in user who still holds an old anonymous token)."""

    user: db.User | None
    owner_token: str | None


def get_actor(
    session: Session = Depends(db.get_db),
    authorization: str | None = Header(default=None),
    x_owner_token: str | None = Header(default=None, alias="X-Owner-Token"),
) -> Actor:
    user = None
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise HTTPException(status_code=401, detail="Invalid Authorization header.")
        user = _upsert_user(session, verify_token(token.strip()))
    return Actor(user=user, owner_token=x_owner_token)


def require_user(actor: Actor = Depends(get_actor)) -> db.User:
    if actor.user is None:
        raise HTTPException(status_code=401, detail="Sign in required.")
    return actor.user

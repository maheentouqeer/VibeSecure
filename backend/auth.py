"""Optional sign-in via Supabase Auth session tokens (JWTs).

Anonymous use keeps working: with no Authorization header a request is
handled exactly as before, using the X-Owner-Token session token. A request
that DOES carry an Authorization header must carry a valid token -- it is
rejected with 401 rather than silently downgraded to anonymous, so a client
never believes it is signed in when it is not.

Configuration (environment) -- set one of the two verification modes:

  Shared secret (the default for a new Supabase project):
    SUPABASE_JWT_SECRET    Project Settings > API > JWT Settings > "JWT Secret".
                            Supabase signs auth tokens HS256 with this by default.
                            (sign-in is disabled, and Bearer tokens get 503, when
                            neither this nor SUPABASE_JWKS_URL is set)

  JWKS (only if the project has "JWT Signing Keys" / asymmetric keys enabled --
  Project Settings > API > JWT Settings shows this instead of a shared secret
  when it's on):
    SUPABASE_JWKS_URL      https://<project-ref>.supabase.co/auth/v1/.well-known/jwks.json

  Optional, either mode:
    SUPABASE_URL                 if set, the token's `iss` must be "<SUPABASE_URL>/auth/v1"
    SUPABASE_AUTHORIZED_PARTIES  optional comma-separated list; if set, the token's
                                  `azp` (present on tokens from a custom OIDC client,
                                  not on Supabase's own email/password or OAuth
                                  tokens) must be one of them
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
    url = os.getenv("SUPABASE_JWKS_URL")
    if not url:
        return None
    if _client is None or _client_url != url:
        _client = PyJWKClient(url, cache_keys=True, lifespan=3600)
        _client_url = url
    return _client


def _issuer() -> str | None:
    base = os.getenv("SUPABASE_URL")
    return f"{base.rstrip('/')}/auth/v1" if base else None


def verify_token(token: str) -> dict:
    secret = os.getenv("SUPABASE_JWT_SECRET")
    jwks_client = _get_jwks_client()
    if not secret and jwks_client is None:
        raise HTTPException(status_code=503, detail="Sign-in is not configured on this server.")

    issuer = _issuer()
    # Supabase's own tokens always carry aud="authenticated", but a token
    # from a custom OIDC client in front of Supabase might not -- so, like
    # the issuer/azp checks below, this only rejects a mismatch, not absence.
    decode_kwargs = dict(
        issuer=issuer,
        options={
            "require": ["exp", "sub"],
            "verify_aud": False,
            "verify_iss": issuer is not None,
        },
    )

    try:
        if jwks_client is not None:
            signing_key = jwks_client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, signing_key, algorithms=["RS256", "ES256"], **decode_kwargs)
        else:
            claims = jwt.decode(token, secret, algorithms=["HS256"], **decode_kwargs)
    except PyJWKClientConnectionError as exc:
        raise HTTPException(status_code=503, detail="Could not reach the sign-in provider.") from exc
    except (jwt.PyJWTError, PyJWKClientError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired sign-in token.") from exc

    if claims.get("aud") not in (None, "authenticated"):
        raise HTTPException(status_code=401, detail="Invalid or expired sign-in token.")

    allowed = [p.strip() for p in os.getenv("SUPABASE_AUTHORIZED_PARTIES", "").split(",") if p.strip()]
    if allowed and claims.get("azp") not in allowed:
        raise HTTPException(status_code=401, detail="Invalid or expired sign-in token.")
    return claims


def _upsert_user(session: Session, claims: dict) -> db.User:
    # `clerk_user_id` predates the Supabase migration; it now holds the auth
    # provider's subject id (`sub`) regardless of provider. Left unrenamed --
    # it's also the field name in API request/response bodies (accounts.py,
    # admin.py, billing.py, whop.py) and in the Whop checkout metadata
    # contract, so renaming it is a separate, cross-cutting change.
    auth_user_id = claims["sub"]
    email = claims.get("email") or None

    user = session.query(db.User).filter_by(clerk_user_id=auth_user_id).one_or_none()
    if user is None:
        user = db.User(clerk_user_id=auth_user_id, email=email)
        session.add(user)
        try:
            session.commit()
        except IntegrityError:  # a concurrent first request created it
            session.rollback()
            user = session.query(db.User).filter_by(clerk_user_id=auth_user_id).one()
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

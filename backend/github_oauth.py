"""Connect a GitHub account so Pro users can scan their private repositories.

  GET    /integrations/github            configured? connected? as whom?
  GET    /integrations/github/authorize  the GitHub URL to send the browser to
  GET    /integrations/github/callback   where GitHub returns the browser
  DELETE /integrations/github            disconnect (deletes our copy, revokes the grant)

Configuration (environment; the feature is off until all four are set):
  GITHUB_OAUTH_CLIENT_ID / GITHUB_OAUTH_CLIENT_SECRET   from a GitHub OAuth App
  GITHUB_OAUTH_REDIRECT_URI   this API's callback URL, registered on that app,
                              e.g. https://api.example.com/integrations/github/callback
  TOKEN_ENCRYPTION_KEY        Fernet key that encrypts stored tokens. Generate:
                              python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  FRONTEND_URL                optional; the browser is sent here (with ?github=connected)
                              after the callback instead of seeing JSON

Notes on trust:
  * GitHub OAuth Apps can only read private repositories with the broad `repo`
    scope, so that is what is requested. Users can revoke it at any time in
    their GitHub settings, and disconnecting here revokes it too.
  * The callback is a plain browser redirect and carries no Authorization
    header, so the user is identified by `state`: a short-lived signed token
    naming the user who started the flow. A tampered, expired, or foreign
    state is rejected, which is what stops login-CSRF (linking someone else's
    GitHub account to a victim).
  * Tokens are encrypted at rest and only ever handed to git for github.com.
"""
import base64
import hashlib
import logging
import os
import time
from urllib.parse import urlencode

import jwt
import requests
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from backend import db, plans
from backend.auth import Actor, get_actor, require_user
from scanner.repo_utils import is_github_url

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/integrations/github")

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API_USER_URL = "https://api.github.com/user"
SCOPE = "repo"
STATE_TTL_SECONDS = 600


# ------------------------------------------------------------------ config


def _client_id() -> str | None:
    return os.getenv("GITHUB_OAUTH_CLIENT_ID") or None


def _client_secret() -> str | None:
    return os.getenv("GITHUB_OAUTH_CLIENT_SECRET") or None


def _redirect_uri() -> str | None:
    return os.getenv("GITHUB_OAUTH_REDIRECT_URI") or None


def _key() -> bytes | None:
    key = os.getenv("TOKEN_ENCRYPTION_KEY")
    return key.encode() if key else None


def configured() -> bool:
    if not (_client_id() and _client_secret() and _redirect_uri() and _key()):
        return False
    try:
        Fernet(_key())
    except ValueError:
        return False
    return True


def _require_configured() -> None:
    if not configured():
        raise HTTPException(status_code=503, detail="GitHub connection is not configured on this server.")


# --------------------------------------------------------- encryption/state


def encrypt_token(token: str) -> str:
    _require_configured()
    return Fernet(_key()).encrypt(token.encode()).decode()


def decrypt_token(blob: str) -> str | None:
    """None if the key is missing/changed or the data is corrupt; callers then
    simply scan as if the user had not connected GitHub."""
    if not _key():
        return None
    try:
        return Fernet(_key()).decrypt(blob.encode()).decode()
    except (InvalidToken, ValueError):
        logger.warning("could not decrypt a stored GitHub token (was TOKEN_ENCRYPTION_KEY changed?)")
        return None


def _state_secret() -> bytes:
    # A different key from the one that encrypts tokens, derived from it.
    return hashlib.sha256(b"github-oauth-state:" + (_key() or b"")).digest()


def make_state(user_id: str) -> str:
    return jwt.encode(
        {"sub": user_id, "exp": int(time.time()) + STATE_TTL_SECONDS, "n": base64.urlsafe_b64encode(os.urandom(9)).decode()},
        _state_secret(),
        algorithm="HS256",
    )


def read_state(state: str) -> str:
    try:
        return jwt.decode(state, _state_secret(), algorithms=["HS256"], options={"require": ["exp", "sub"]})["sub"]
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=400, detail="Invalid or expired state. Start the connection again.") from exc


# ------------------------------------------------------------ GitHub calls
# Isolated so tests can replace them without touching the network.


def _exchange_code(code: str) -> tuple[str, str | None]:
    resp = requests.post(
        TOKEN_URL,
        headers={"Accept": "application/json"},
        data={
            "client_id": _client_id(),
            "client_secret": _client_secret(),
            "code": code,
            "redirect_uri": _redirect_uri(),
        },
        timeout=10,
    )
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise ValueError(data.get("error_description") or "GitHub did not return an access token")
    return token, data.get("scope")


def _fetch_login(token: str) -> str:
    resp = requests.get(
        API_USER_URL,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["login"]


def _revoke(token: str) -> None:
    """Best effort: an unreachable GitHub must not block disconnecting."""
    try:
        requests.delete(
            f"https://api.github.com/applications/{_client_id()}/grant",
            auth=(_client_id(), _client_secret()),
            headers={"Accept": "application/vnd.github+json"},
            json={"access_token": token},
            timeout=10,
        )
    except requests.RequestException:
        logger.warning("could not revoke a GitHub grant", exc_info=True)


# -------------------------------------------------------------- endpoints


@router.get("")
def status(actor: Actor = Depends(get_actor), session: Session = Depends(db.get_db)):
    conn = (
        session.query(db.GithubConnection).filter_by(user_id=actor.user.id).one_or_none() if actor.user else None
    )
    return {"configured": configured(), "connected": conn is not None, "login": conn.github_login if conn else None}


@router.get("/authorize")
def authorize(user: db.User = Depends(require_user)):
    _require_configured()
    query = urlencode(
        {
            "client_id": _client_id(),
            "redirect_uri": _redirect_uri(),
            "scope": SCOPE,
            "state": make_state(user.id),
            "allow_signup": "false",
        }
    )
    return {"url": f"{AUTHORIZE_URL}?{query}"}


def _finish(result: str):
    frontend = os.getenv("FRONTEND_URL", "").rstrip("/")
    if frontend.startswith(("http://", "https://")):
        return RedirectResponse(f"{frontend}?github={result}", status_code=302)
    return {"github": result}


@router.get("/callback")
def callback(
    state: str = Query(...),
    code: str | None = Query(default=None),
    error: str | None = Query(default=None),
    session: Session = Depends(db.get_db),
):
    _require_configured()
    user_id = read_state(state)  # invalid state is an error, never a friendly redirect
    if error or not code:
        return _finish("denied")

    user = session.get(db.User, user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired state. Start the connection again.")

    try:
        token, scope = _exchange_code(code)
        login = _fetch_login(token)
        blob = encrypt_token(token)
    except HTTPException:
        raise
    except Exception:
        logger.warning("GitHub OAuth callback failed", exc_info=True)
        return _finish("error")

    conn = session.query(db.GithubConnection).filter_by(user_id=user.id).one_or_none()
    if conn is None:
        conn = db.GithubConnection(user_id=user.id)
        session.add(conn)
    conn.github_login, conn.encrypted_token, conn.scope = login, blob, scope
    session.commit()
    return _finish("connected")


@router.delete("", status_code=204)
def disconnect(user: db.User = Depends(require_user), session: Session = Depends(db.get_db)):
    conn = session.query(db.GithubConnection).filter_by(user_id=user.id).one_or_none()
    if conn is not None:
        token = decrypt_token(conn.encrypted_token)
        session.delete(conn)
        session.commit()
        if token and configured():
            _revoke(token)
    return Response(status_code=204)


# -------------------------------------------------------- used by scan jobs


def token_for_scan(session: Session, scan: db.Scan) -> str | None:
    """The scan owner's own GitHub token, if this scan should use it: the scan
    belongs to an account with a connection, targets github.com, and (when
    plans are enforced) the owner's plan includes private repositories."""
    if not scan.owner_user_id or not is_github_url(scan.target):
        return None
    conn = session.query(db.GithubConnection).filter_by(user_id=scan.owner_user_id).one_or_none()
    if conn is None:
        return None
    if plans.enforcement_enabled() and not plans.plan_for_scan_owner(session, scan).private_repos:
        return None
    return decrypt_token(conn.encrypted_token)

"""Whop billing adapter: POST /webhooks/whop.

Verified against Whop's documentation and its official Python SDK
(whop_sdk.lib.verify_webhook), not assumed:
  * Deliveries follow the Standard Webhooks spec: headers `webhook-id`,
    `webhook-timestamp`, `webhook-signature` (`v1,<base64>`, possibly several
    space-separated). The signed string is `{id}.{timestamp}.{raw body}`,
    HMAC-SHA256 with the *literal UTF-8 bytes of the whole `ws_...` secret*
    (prefix included -- unlike plain Standard Webhooks, which base64-decodes).
  * Timestamps more than 5 minutes off are rejected. Reply 2xx within 5 s.
  * Events are at-least-once and retried for ~71 h, and a webhook that keeps
    failing for 72 h is DISABLED by Whop -- so anything a retry cannot fix is
    answered 200 (and logged) rather than with an error.

Configuration:
  WHOP_WEBHOOK_SECRET  the endpoint's signing secret, exactly as Whop shows it (`ws_...`)
  WHOP_PLAN_MAP        JSON mapping Whop plan ids (or product ids) to our plans, e.g.
                       {"plan_abc123": "pro", "prod_xyz789": "team"}

Who a purchase belongs to: create the Whop checkout with metadata
  {"clerk_user_id": "<the signed-in user's Clerk id>"}            for a Pro plan
  {"clerk_user_id": "...", "org_id": "<our organization id>"}     for a Team plan
so the event carries it back to us. (The payload has no email unless it uses
Whop's legacy shape, which is honoured as a fallback for Pro.)
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Mapping

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend import db
from backend.accounts import BillingEvent, BillingUser, apply_billing_event

logger = logging.getLogger(__name__)
router = APIRouter()

TOLERANCE_SECONDS = 300

# Whop membership status -> our subscription status (None: not a subscription state).
_STATUS = {
    "trialing": "trialing",
    "active": "active",
    "canceling": "active",  # cancels at period end: still paid until then
    "past_due": "past_due",
    "unresolved": "past_due",
    "canceled": "canceled",
    "completed": "expired",
    "expired": "expired",
    "drafted": None,
}
_INVALID = ("canceled", "expired")


def verify_signature(body: bytes, headers: Mapping[str, str], secret: str, now: float | None = None) -> bool:
    """Standard Webhooks verification as Whop implements it."""
    lower = {k.lower(): v for k, v in headers.items()}
    msg_id, ts, sigs = lower.get("webhook-id"), lower.get("webhook-timestamp"), lower.get("webhook-signature")
    if not (msg_id and ts and sigs):
        return False
    try:
        sent_at = int(ts)
    except ValueError:
        return False
    if abs((now if now is not None else time.time()) - sent_at) > TOLERANCE_SECONDS:
        return False

    signed = msg_id.encode() + b"." + ts.encode() + b"." + body
    expected = base64.b64encode(hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).digest()).decode()
    for part in sigs.split():
        version, _, sig = part.partition(",")
        if version == "v1" and hmac.compare_digest(sig, expected):
            return True
    return False


def _plan_map() -> dict[str, str]:
    try:
        mapping = json.loads(os.getenv("WHOP_PLAN_MAP", "{}"))
    except ValueError:
        return {}
    return {k: v for k, v in mapping.items() if v in ("pro", "team")} if isinstance(mapping, dict) else {}


def _get(data: dict, flat: str, nested: str) -> str | None:
    """Whop sends either flat ids (plan_id) or nested objects (plan: {id})."""
    value = data.get(flat)
    if value:
        return value
    inner = data.get(nested)
    return inner.get("id") if isinstance(inner, dict) else None


def _parse_time(value) -> datetime | None:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def to_billing_event(envelope: dict) -> tuple[BillingEvent | None, datetime | None, str]:
    """Maps a Whop event to our neutral event. Returns (event, when it
    happened, reason); the event is None when it should be acknowledged and
    ignored, with the reason saying why."""
    kind = envelope.get("type")
    data = envelope.get("data")
    if kind not in (
        "membership.activated", "membership.deactivated", "membership.cancel_at_period_end_changed",
    ):
        return None, None, f"ignored event type '{kind}'"
    if not isinstance(data, dict) or not data.get("id"):
        return None, None, "no membership in the event"

    plan_map = _plan_map()
    plan_id, product_id = _get(data, "plan_id", "plan"), _get(data, "product_id", "product")
    plan = plan_map.get(plan_id or "") or plan_map.get(product_id or "")
    if plan is None:
        return None, None, "plan is not in WHOP_PLAN_MAP"

    whop_status = data.get("status")
    status = _STATUS.get(whop_status, "active" if kind == "membership.activated" else None)
    if whop_status == "drafted" or (status is None and kind != "membership.deactivated"):
        return None, None, f"membership status '{whop_status}' is not a subscription state"
    if kind == "membership.deactivated" and status not in _INVALID:
        status = "expired"  # the membership just stopped being valid, whatever status says

    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    user_obj = data.get("user") if isinstance(data.get("user"), dict) else {}
    clerk_id = metadata.get("clerk_user_id")
    email = user_obj.get("email")
    org_id = metadata.get("org_id") if plan == "team" else None
    if plan == "team" and not org_id:
        return None, None, "team membership without metadata.org_id"
    if plan == "pro" and not (clerk_id or email):
        return None, None, "membership without metadata.clerk_user_id (or an email)"

    event = BillingEvent(
        event="subscription.activated" if kind == "membership.activated" else "subscription.updated",
        provider="whop",
        plan=plan,
        provider_subscription_id=data["id"],
        provider_customer_id=_get(data, "user_id", "user"),
        status=status,
        current_period_end=_parse_time(data.get("current_period_end") or data.get("renewal_period_end")),
        user=BillingUser(clerk_user_id=clerk_id, email=email) if plan == "pro" else None,
        org_id=org_id,
    )
    return event, _parse_time(envelope.get("timestamp")), "ok"


@router.post("/webhooks/whop")
async def whop_webhook(request: Request, session: Session = Depends(db.get_db)):
    secret = os.getenv("WHOP_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=503, detail="Whop webhooks are not configured.")

    body = await request.body()
    if not verify_signature(body, request.headers, secret):
        raise HTTPException(status_code=401, detail="Invalid signature.")

    try:
        envelope = json.loads(body)
    except ValueError:
        raise HTTPException(status_code=400, detail="Body is not valid JSON.")
    if not isinstance(envelope, dict):
        raise HTTPException(status_code=400, detail="Body must be a JSON object.")

    event, event_at, reason = to_billing_event(envelope)
    if event is None:
        # Acknowledge: a retry would not change the outcome, and repeated
        # failures get the whole webhook disabled by Whop.
        logger.info("whop webhook ignored: %s", reason)
        return {"ok": True, "ignored": reason}

    try:
        return apply_billing_event(session, event, event_at=event_at, create_missing_user=True)
    except HTTPException as exc:
        if exc.status_code in (400, 404):  # permanent for this event: acknowledge, don't retry
            logger.warning("whop webhook could not be applied: %s", exc.detail)
            return {"ok": True, "ignored": exc.detail}
        raise

"""Start a paid subscription: POST /billing/checkout.

Creates a Whop checkout for the signed-in user and returns its URL for the
frontend to send the browser to. The other half of the flow is the webhook in
backend/whop.py, which grants the plan when the purchase completes.

How the two halves connect (per Whop's API documentation): metadata set on a
checkout configuration is "copied to payments and memberships", so the
`clerk_user_id` (and `org_id` for Team) we attach here comes back on the
membership event and tells the webhook whose plan to activate. The metadata is
built here, on the server, from the verified session -- the client cannot
choose it, so nobody can attribute a purchase to someone else.

Configuration:
  WHOP_API_KEY    a Whop API key allowed to create checkout configurations
  WHOP_PLAN_MAP   {"plan_...": "pro", "plan_...": "team"} (shared with the webhook;
                  only `plan_` ids can be used for checkout)
  WHOP_API_BASE   optional override of https://api.whop.com/api/v1
  FRONTEND_URL    optional; customers return to it (?checkout=success) after paying
"""
import logging
import os
from datetime import datetime, timezone
from typing import Literal

import requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend import db, limits
from backend.access import org_role
from backend.auth import require_user
from backend.deletion import _entitled_subscriptions
from backend.whop import _plan_map

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/billing")

DEFAULT_API_BASE = "https://api.whop.com/api/v1"


class CheckoutRequest(BaseModel):
    plan: Literal["pro", "team"]
    org_id: str | None = Field(default=None, description="Required for the team plan: the organization to upgrade")
    whop_plan_id: str | None = Field(
        default=None, description="Which configured Whop plan to buy (e.g. monthly vs yearly); defaults to the first"
    )


def _checkout_plans() -> dict[str, list[str]]:
    """our plan name -> the Whop plan ids (checkout needs `plan_` ids) that buy it."""
    out: dict[str, list[str]] = {}
    for whop_id, ours in _plan_map().items():
        if whop_id.startswith("plan_"):
            out.setdefault(ours, []).append(whop_id)
    return out


def _create_checkout(payload: dict) -> dict:
    """The one network call. Isolated so tests can replace it."""
    api_key = os.getenv("WHOP_API_KEY")
    base = os.getenv("WHOP_API_BASE", DEFAULT_API_BASE).rstrip("/")
    try:
        resp = requests.post(
            f"{base}/checkout_configurations",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.warning("Whop checkout request failed: %s", exc.__class__.__name__)
        raise HTTPException(status_code=502, detail="Could not reach the payment provider. Please try again.") from exc

    if not 200 <= resp.status_code < 300:
        # Log Whop's reason for us; the customer only needs to know it failed.
        logger.warning("Whop refused the checkout (HTTP %s): %s", resp.status_code, resp.text[:300])
        raise HTTPException(status_code=502, detail="The payment provider could not start a checkout. Please try again.")
    try:
        return resp.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="The payment provider returned an unexpected response.") from exc


@router.post(
    "/checkout",
    dependencies=[Depends(limits.limit_by_user("checkout", "CHECKOUT_RATE_LIMIT_PER_HOUR", 20, "checkout attempts"))],
)
def start_checkout(
    payload: CheckoutRequest,
    user: db.User = Depends(require_user),
    session: Session = Depends(db.get_db),
):
    if not os.getenv("WHOP_API_KEY"):
        raise HTTPException(status_code=503, detail="Checkout is not configured on this server.")
    options = _checkout_plans().get(payload.plan, [])
    if not options:
        raise HTTPException(status_code=503, detail=f"The {payload.plan} plan is not available for purchase yet.")

    whop_plan_id = payload.whop_plan_id or options[0]
    if whop_plan_id not in options:  # never let a client pick an arbitrary Whop plan
        raise HTTPException(status_code=400, detail="Unknown plan option.")

    metadata = {"clerk_user_id": user.clerk_user_id, "source": "secure-vibecode"}
    if payload.plan == "team":
        if not payload.org_id:
            raise HTTPException(status_code=400, detail="The team plan needs an org_id.")
        role = org_role(session, user, payload.org_id)
        if role is None:
            raise HTTPException(status_code=404, detail="Organization not found")
        if role != "owner":
            raise HTTPException(status_code=403, detail="Only the organization owner can buy the team plan.")
        if _entitled_subscriptions(session, org_id=payload.org_id):
            raise HTTPException(status_code=409, detail="This organization already has an active subscription.")
        metadata["org_id"] = payload.org_id
    else:
        if payload.org_id:
            raise HTTPException(status_code=400, detail="org_id is only for the team plan.")
        if _entitled_subscriptions(session, user_id=user.id):
            raise HTTPException(status_code=409, detail="You already have an active subscription.")

    body = {"plan_id": whop_plan_id, "metadata": metadata}
    frontend = os.getenv("FRONTEND_URL", "").rstrip("/")
    if frontend.startswith(("http://", "https://")):
        body["redirect_url"] = f"{frontend}?checkout=success"

    created = _create_checkout(body)
    url = created.get("purchase_url")
    if not isinstance(url, str) or not url.startswith("https://"):
        logger.warning("Whop checkout response had no usable purchase_url")
        raise HTTPException(status_code=502, detail="The payment provider returned an unexpected response.")
    return {"url": url, "checkout_id": created.get("id"), "plan": payload.plan}

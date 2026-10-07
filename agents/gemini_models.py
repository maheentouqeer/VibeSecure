"""Single source of truth for which Gemini models the agents try, in order.

Why this exists: the triage, explainer and fix-prompt agents each kept their own
copy of the list, and the copies had gone stale (``gemini-1.5-flash`` was shut
down in Nov 2025 and ``gemini-2.0-flash`` on 1 Jun 2026). Every dead entry cost
one failed network call per finding, per agent.

* Default order is newest first, with one older stable model as a safety net.
* Set ``GEMINI_MODELS`` (comma-separated) to change the list without a deploy,
  e.g. ``GEMINI_MODELS=gemini-3.8-flash,gemini-3.6-flash``.
* A model that fails is skipped by later calls: "not found / not supported"
  errors for the rest of the process, transient errors (rate limit, 5xx,
  timeout) for ``COOLDOWN_SECONDS``. This keeps a dead model from adding a
  failed call to every finding in a scan.

Model names and their shutdown dates change often. Check
https://ai.google.dev/gemini-api/docs/deprecations before editing the default.
"""

from __future__ import annotations

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

DEFAULT_MODELS: tuple[str, ...] = (
    "gemini-3.8-flash",
    "gemini-3.6-flash",
    "gemini-2.5-flash",
)

COOLDOWN_SECONDS = 60.0

_PERMANENT_MARKERS = (
    "404",
    "not_found",
    "not found",
    "no longer available",
    "is not supported",
    "has been shut down",
    "permission_denied",
    "403",
)

_lock = threading.Lock()
_dead: set[str] = set()
_cooling: dict[str, float] = {}


def configured_models() -> tuple[str, ...]:
    """The full ordered list: ``GEMINI_MODELS`` if set, else the defaults."""
    raw = os.environ.get("GEMINI_MODELS", "")
    models = tuple(m.strip() for m in raw.split(",") if m.strip())
    return models or DEFAULT_MODELS


def usable_models() -> list[str]:
    """Configured models minus any that are dead or cooling down.

    If nothing is healthy, fall back to models that are only cooling down (a
    rate limit usually clears), and if every model looks dead, to the whole
    configured list, so a wrong guess about health can never turn Gemini off
    completely. A model that was reported unavailable is only tried again when
    there is nothing else to try.
    """
    now = time.monotonic()
    with _lock:
        configured = list(configured_models())
        healthy = [m for m in configured if m not in _dead and _cooling.get(m, 0.0) <= now]
        not_dead = [m for m in configured if m not in _dead]

    # If every non-dead model is cooling down, do not immediately retry a
    # rate-limited/failed model. Let callers use their deterministic fallback
    # for this scan instead of turning one quota event into repeated network
    # calls across every finding.
    if not healthy and any(m in _cooling for m in not_dead):
        return []

    # If all configured models are marked permanently unavailable, there is
    # nothing useful to retry. Returning [] makes the agents fall back cleanly.
    if not healthy and not not_dead:
        return []

    return healthy or not_dead


def report_failure(model: str, error: BaseException | str) -> None:
    """Record that a call to ``model`` raised, so later calls can skip it."""
    message = str(error).lower()
    permanent = any(marker in message for marker in _PERMANENT_MARKERS)
    with _lock:
        if permanent:
            if model not in _dead:
                logger.warning("Gemini model %s looks unavailable; skipping it from now on", model)
            _dead.add(model)
        else:
            _cooling[model] = time.monotonic() + COOLDOWN_SECONDS


def report_success(model: str) -> None:
    with _lock:
        _cooling.pop(model, None)


def reset() -> None:
    """Forget all failures (used by tests)."""
    with _lock:
        _dead.clear()
        _cooling.clear()

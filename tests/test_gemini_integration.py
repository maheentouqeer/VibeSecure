"""Opt-in smoke test for the real Gemini path.

Run with GEMINI_API_KEY and RUN_GEMINI_INTEGRATION=1 to verify credentials,
model availability, and response parsing against the live API.
"""

import os

import pytest

from agents.explainer_agent import explain
from agents.fixprompt_agent import generate_fix_prompt
from agents.triage_agent import triage


pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    not os.environ.get("GEMINI_API_KEY") or os.environ.get("RUN_GEMINI_INTEGRATION") != "1",
    reason="Set GEMINI_API_KEY and RUN_GEMINI_INTEGRATION=1 for a live Gemini smoke test",
)
def test_real_gemini_agent_path(caplog):
    finding = {
        "id": "integration-secret",
        "category": "hardcoded_secret",
        "label": "API key",
        "file": "src/config.ts",
    }

    triaged = triage([finding])
    explanation = explain(finding, platform="generic")
    fix_prompt = generate_fix_prompt(finding, platform="generic")

    assert triaged
    assert set(explanation) == {"what_it_means", "why_it_matters"}
    assert fix_prompt
    success_logs = " ".join(record.getMessage() for record in caplog.records)
    assert "Gemini triage succeeded" in success_logs
    assert "Gemini explanation succeeded" in success_logs
    assert "Gemini fix prompt succeeded" in success_logs
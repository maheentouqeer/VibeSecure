"""Tests for the agent layer contract compliance, deterministic fallbacks, and Gemini calls."""

import json
import os
from unittest import mock

import pytest

import agents.explainer_agent as explainer_mod
from agents.explainer_agent import explain
import agents.fixprompt_agent as fixprompt_mod
from agents.fixprompt_agent import generate_fix_prompt
import agents.triage_agent as triage_mod
from agents.triage_agent import triage
from agents.verify_agent import diff_findings

VALID_SEVERITIES = {"critical", "high", "medium", "low"}


@pytest.fixture(autouse=True)
def unconfigured_gemini():
    with mock.patch.dict(os.environ, {}, clear=True):
        yield


def test_models_configured_with_gemini_38_and_36():
    for mod in (explainer_mod, triage_mod, fixprompt_mod):
        assert "gemini-3.8-flash" in mod.MODELS
        assert "gemini-3.6-flash" in mod.MODELS


def test_triage_contract_and_deduplication():
    raw_findings = [
        {
            "category": "hardcoded_secret",
            "label": "Stripe Secret Key",
            "file": "server.py",
            "raw_severity": "critical",
        },
        {
            "category": "hardcoded_secret",
            "label": "Stripe Secret Key",
            "file": "server.py",
            "raw_severity": "critical",
        },
        {
            "category": "missing_header",
            "label": "Missing X-Frame-Options header",
            "file": "https://example.com",
            "raw_severity": "medium",
        },
    ]

    triaged = triage(raw_findings)

    assert len(triaged) == 2

    for finding in triaged:
        assert set(finding.keys()) == {"id", "category", "label", "file", "severity"}
        assert finding["severity"] in VALID_SEVERITIES

    assert triaged[0]["category"] == "hardcoded_secret"
    assert triaged[0]["severity"] == "critical"
    assert triaged[1]["category"] == "missing_header"
    assert triaged[1]["severity"] == "medium"


def test_triage_gemini_success():
    raw_findings = [
        {
            "category": "hardcoded_secret",
            "label": "Stripe Secret Key",
            "file": "server.py",
            "raw_severity": "critical",
        }
    ]
    mock_response = mock.MagicMock()
    mock_response.text = json.dumps([
        {
            "id": "finding_100",
            "category": "hardcoded_secret",
            "label": "Stripe Secret Key",
            "file": "server.py",
            "severity": "critical",
        }
    ])

    mock_client = mock.MagicMock()
    mock_client.models.generate_content.return_value = mock_response

    mock_genai = mock.MagicMock()
    mock_genai.Client.return_value = mock_client

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch.dict("sys.modules", {"google": mock.MagicMock(genai=mock_genai), "google.genai": mock_genai}):
            triaged = triage(raw_findings)

    assert len(triaged) == 1
    assert triaged[0]["id"] == "finding_100"
    assert triaged[0]["category"] == "hardcoded_secret"
    assert triaged[0]["severity"] == "critical"


def test_triage_gemini_failure_falls_back():
    raw_findings = [
        {
            "category": "hardcoded_secret",
            "label": "Stripe Secret Key",
            "file": "server.py",
            "raw_severity": "critical",
        }
    ]

    mock_client = mock.MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError("API unavailable")

    mock_genai = mock.MagicMock()
    mock_genai.Client.return_value = mock_client

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch.dict("sys.modules", {"google": mock.MagicMock(genai=mock_genai), "google.genai": mock_genai}):
            triaged = triage(raw_findings)

    assert len(triaged) == 1
    assert triaged[0]["category"] == "hardcoded_secret"
    assert triaged[0]["severity"] == "critical"


def test_verify_diff_findings():
    previous = [
        {"category": "hardcoded_secret", "label": "Key A", "file": "a.py"},
        {"category": "missing_header", "label": "Header B", "file": "https://example.com"},
    ]
    current = [
        {"category": "hardcoded_secret", "label": "Key A", "file": "a.py"}
    ]

    diffed = diff_findings(previous, current)
    assert len(diffed) == 2
    assert diffed[0]["status"] == "still_present"
    assert diffed[1]["status"] == "resolved"


def test_fingerprint_ignores_volatile_entropy_value_in_label():
    from agents.verify_agent import fingerprint

    a = {"category": "hardcoded_secret", "label": "High Entropy Secret (entropy: 4.71)", "file": "src/a.ts"}
    b = {"category": "hardcoded_secret", "label": "High Entropy Secret (entropy: 5.02)", "file": "src/a.ts"}
    other_file = {**a, "file": "src/b.ts"}
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint(other_file)


def test_fingerprint_distinguishes_tables_and_path_separators():
    from agents.verify_agent import fingerprint

    base = {"category": "missing_access_control", "label": "Row-Level Security not enabled", "file": "supabase migrations"}
    assert fingerprint({**base, "table": "users"}) != fingerprint({**base, "table": "orders"})
    windows_style = {"category": "c", "label": "l", "file": "src" + chr(92) + "a.ts"}
    assert fingerprint(windows_style) == fingerprint({"category": "c", "label": "l", "file": "src/a.ts"})


def test_diff_findings_treats_changed_entropy_as_still_present():
    prev = [{"category": "hardcoded_secret", "label": "High Entropy Secret (entropy: 4.71)", "file": "a.ts"}]
    curr = [{"category": "hardcoded_secret", "label": "High Entropy Secret (entropy: 4.90)", "file": "a.ts"}]
    assert diff_findings(prev, curr)[0]["status"] == "still_present"


def test_fallback_triage_keeps_findings_for_different_tables():
    from agents.triage_agent import _fallback_triage

    raw = [
        {"category": "missing_access_control", "label": "Row-Level Security not enabled",
         "file": "supabase migrations", "table": t, "raw_severity": "critical"}
        for t in ("users", "orders")
    ]
    out = _fallback_triage(raw + raw)  # exact duplicates still collapse
    assert sorted(f["table"] for f in out) == ["orders", "users"]

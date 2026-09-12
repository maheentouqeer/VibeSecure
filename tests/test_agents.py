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


def test_models_configured_with_gemini_36():
    assert "gemini-3.6-flash" in explainer_mod.MODELS
    assert "gemini-3.6-flash" in triage_mod.MODELS
    assert "gemini-3.6-flash" in fixprompt_mod.MODELS


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

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch("google.genai.Client", return_value=mock_client):
            result = triage(raw_findings)

    assert len(result) == 1
    assert result[0]["id"] == "finding_100"
    assert result[0]["severity"] == "critical"


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

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch("google.genai.Client", return_value=mock_client):
            result = triage(raw_findings)

    assert len(result) == 1
    assert result[0]["category"] == "hardcoded_secret"
    assert result[0]["severity"] == "critical"


def test_explainer_contract():
    finding = {
        "id": "finding_0",
        "category": "missing_access_control",
        "label": "Row-Level Security not enabled",
        "file": "supabase migrations",
        "severity": "critical",
    }

    result = explain(finding)

    assert set(result.keys()) == {"what_it_means", "why_it_matters"}
    assert isinstance(result["what_it_means"], str) and len(result["what_it_means"]) > 0
    assert isinstance(result["why_it_matters"], str) and len(result["why_it_matters"]) > 0


def test_explainer_gemini_success():
    finding = {
        "id": "finding_0",
        "category": "hardcoded_secret",
        "label": "API Key Exposed",
        "file": "config.js",
        "severity": "high",
    }
    mock_response = mock.MagicMock()
    mock_response.text = json.dumps({
        "what_it_means": "An API key is exposed in the frontend bundle.",
        "why_it_matters": "Callers can exhaust your quota or access privileged resources.",
    })

    mock_client = mock.MagicMock()
    mock_client.models.generate_content.return_value = mock_response

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch("google.genai.Client", return_value=mock_client):
            result = explain(finding)

    assert result["what_it_means"] == "An API key is exposed in the frontend bundle."
    assert "exhaust your quota" in result["why_it_matters"]


def test_explainer_gemini_failure_falls_back():
    finding = {
        "id": "finding_0",
        "category": "hardcoded_secret",
        "label": "API Key Exposed",
        "file": "config.js",
        "severity": "high",
    }
    mock_client = mock.MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError("API unavailable")

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch("google.genai.Client", return_value=mock_client):
            result = explain(finding)

    assert set(result.keys()) == {"what_it_means", "why_it_matters"}
    assert "hardcoded directly in your code" in result["what_it_means"]


def test_fixprompt_platform_specific_fallbacks():
    rls_finding = {
        "category": "missing_access_control",
        "label": "Row-Level Security not enabled",
        "table": "profiles",
        "file": "supabase/migrations/001.sql",
    }
    supabase_fix = generate_fix_prompt(rls_finding, "lovable_supabase")
    assert "ENABLE ROW LEVEL SECURITY" in supabase_fix
    assert "auth.uid()" in supabase_fix

    secret_finding = {
        "category": "hardcoded_secret",
        "label": "Stripe Secret Key",
        "file": "index.js",
    }
    replit_fix = generate_fix_prompt(secret_finding, "replit")
    assert "Secrets pane" in replit_fix

    bolt_fix = generate_fix_prompt(secret_finding, "bolt_v0")
    assert ".env.local" in bolt_fix or "NEXT_PUBLIC_" in bolt_fix

    generic_fix = generate_fix_prompt(secret_finding, "generic")
    assert "environment variable" in generic_fix


def test_fixprompt_gemini_success():
    finding = {
        "category": "hardcoded_secret",
        "label": "Stripe Secret Key",
        "file": "index.js",
    }
    mock_response = mock.MagicMock()
    mock_response.text = "In Replit, move the Stripe key to Secrets and read it via process.env.STRIPE_SECRET_KEY."

    mock_client = mock.MagicMock()
    mock_client.models.generate_content.return_value = mock_response

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch("google.genai.Client", return_value=mock_client):
            prompt = generate_fix_prompt(finding, "replit")

    assert "In Replit, move the Stripe key to Secrets" in prompt


def test_fixprompt_gemini_failure_falls_back():
    finding = {
        "category": "hardcoded_secret",
        "label": "Stripe Secret Key",
        "file": "index.js",
    }
    mock_client = mock.MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError("API unavailable")

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch("google.genai.Client", return_value=mock_client):
            prompt = generate_fix_prompt(finding, "replit")

    assert "Secrets pane" in prompt


def test_verify_diff_findings():
    previous = [
        {"category": "hardcoded_secret", "label": "Stripe Secret Key", "file": "index.js"},
        {"category": "missing_header", "label": "Missing CSP", "file": "https://test.com"},
    ]
    current = [
        {"category": "missing_header", "label": "Missing CSP", "file": "https://test.com"},
    ]

    diff = diff_findings(previous, current)
    assert len(diff) == 2

    by_cat = {d["category"]: d["status"] for d in diff}
    assert by_cat["hardcoded_secret"] == "resolved"
    assert by_cat["missing_header"] == "still_present"

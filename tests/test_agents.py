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
    assert diffed[1]["status"] == "resolved"            "file": "server.py",
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
        with mock.patch.dict("sys.modules", {"google": mock.MagicMock(), "google.genai": mock_genai}):
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
        with mock.patch.dict("sys.modules", {"google": mock.MagicMock(), "google.genai": mock_genai}):
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

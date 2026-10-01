"""Tests for the agent layer contract compliance, deterministic fallbacks,
platform-awareness, evidence-strict anti-hallucination grounding, and Gemini calls.
"""

import json
import os
from unittest import mock

import pytest

from agents.curated_retrieval import get_available_topics, get_curated_doc
from agents.evidence_guard import (
    extract_mentioned_files,
    extract_mentioned_lines,
    validate_evidence_grounding,
)
import agents.explainer_agent as explainer_mod
from agents.explainer_agent import explain
import agents.fixprompt_agent as fixprompt_mod
from agents.fixprompt_agent import generate_fix_prompt
import agents.triage_agent as triage_mod
from agents.triage_agent import triage
from agents.verify_agent import diff_findings
from agents.vulnerability_lookup import (
    format_vulnerability_evidence,
    mcp_lookup_vulnerability_tool,
)

VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def test_all_deterministic_templates_are_grounded():
    findings = {
        "hardcoded_secret": {"category": "hardcoded_secret", "label": "Secret", "file": "src/app.ts"},
        "static_analysis": {"category": "static_analysis", "label": "Unsafe pattern", "file": "src/app.ts"},
        "missing_access_control": {
            "category": "missing_access_control", "label": "RLS missing", "file": "schema.sql", "table": "profiles",
        },
        "exposed_file": {"category": "exposed_file", "label": "Exposed file", "file": ".env"},
        "missing_header": {"category": "missing_header", "label": "CSP", "file": "https://example.com"},
        "cors_misconfig": {"category": "cors_misconfig", "label": "Wildcard CORS", "file": "server.py"},
        "scan_incomplete": {"category": "scan_incomplete", "label": "Incomplete scan", "file": ""},
    }
    for category, finding in findings.items():
        for platform in ("generic", "lovable_supabase", "bolt_v0", "replit"):
            explanation = explainer_mod._fallback_explain(finding, platform)
            for text in explanation.values():
                assert validate_evidence_grounding(text, finding, platform)[0], (category, platform, text)
            prompt = fixprompt_mod._fallback_fix_prompt(finding, platform)
            assert validate_evidence_grounding(prompt, finding, platform)[0], (category, platform, prompt)


@pytest.fixture(autouse=True)
def unconfigured_gemini():
    """Ensures test environment starts with unconfigured Gemini API key."""
    with mock.patch.dict(os.environ, {}, clear=True):
        yield


def test_models_configured_with_gemini_38_and_36():
    """Confirms backward-compatible model tuple configuration across all LLM agents."""
    for mod in (explainer_mod, triage_mod, fixprompt_mod):
        assert "gemini-3.8-flash" in mod.MODELS
        assert "gemini-3.6-flash" in mod.MODELS
        # Also confirm live production models are included in the cascade
        assert "gemini-2.5-flash" in mod.MODELS or "gemini-2.0-flash" in mod.MODELS


# ---------------------------------------------------------------------------
# Triage Agent Tests
# ---------------------------------------------------------------------------

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
    mock_client.models.generate_content.assert_called_once()
    call = mock_client.models.generate_content.call_args.kwargs
    assert call["model"] == triage_mod.MODELS[0]
    assert "raw scanner security findings" in call["contents"]


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


# ---------------------------------------------------------------------------
# Explainer Agent Platform-Aware Fallbacks & Grounding Tests
# ---------------------------------------------------------------------------

def test_explainer_contract_and_keys():
    finding = {
        "category": "hardcoded_secret",
        "label": "AWS Access Key",
        "file": "src/config.ts",
    }
    result = explain(finding)
    assert set(result.keys()) == {"what_it_means", "why_it_matters"}
    assert isinstance(result["what_it_means"], str)
    assert isinstance(result["why_it_matters"], str)
    assert len(result["what_it_means"]) > 0
    assert len(result["why_it_matters"]) > 0


def test_explainer_platform_aware_lovable_supabase():
    finding = {
        "category": "missing_access_control",
        "label": "Row-Level Security not enabled",
        "file": "supabase/migrations/init.sql",
        "table": "profiles",
    }
    result = explain(finding, platform="lovable_supabase")
    assert "RLS" in result["what_it_means"] or "Row-Level Security" in result["what_it_means"]
    assert "profiles" in result["what_it_means"]
    # Why it matters references anon key / Supabase PostgREST
    assert "anon" in result["why_it_matters"].lower() or "supabase" in result["why_it_matters"].lower()


def test_explainer_platform_aware_bolt_v0():
    finding = {
        "category": "hardcoded_secret",
        "label": "Stripe Secret Key",
        "file": "src/lib/stripe.ts",
    }
    result = explain(finding, platform="bolt_v0")
    assert "Bolt" in result["what_it_means"] or "src/lib/stripe.ts" in result["what_it_means"]
    # Explains client bundle exposure in Vite / Next.js
    assert "vite" in result["why_it_matters"].lower() or "next.js" in result["why_it_matters"].lower() or "client" in result["why_it_matters"].lower()


def test_explainer_platform_aware_replit():
    finding = {
        "category": "hardcoded_secret",
        "label": "OpenAI API Key",
        "file": "server.py",
    }
    result = explain(finding, platform="replit")
    assert "Replit Secrets" in result["why_it_matters"] or "Replit" in result["why_it_matters"]


def test_explainer_gemini_success_grounded():
    finding = {
        "category": "hardcoded_secret",
        "label": "Stripe Secret Key",
        "file": "server.py",
        "line": 15,
    }
    mock_response = mock.MagicMock()
    mock_response.text = json.dumps({
        "what_it_means": "A Stripe secret key is hardcoded directly in server.py.",
        "why_it_matters": "Anyone with access to the code can charge transactions using this key.",
    })

    mock_client = mock.MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    mock_genai = mock.MagicMock()
    mock_genai.Client.return_value = mock_client

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch.dict("sys.modules", {"google": mock.MagicMock(genai=mock_genai), "google.genai": mock_genai}):
            res = explain(finding, platform="generic")

    assert res["what_it_means"] == "A Stripe secret key is hardcoded directly in server.py."
    assert "server.py" in res["what_it_means"]
    mock_client.models.generate_content.assert_called_once()
    call = mock_client.models.generate_content.call_args.kwargs
    assert call["model"] == explainer_mod.MODELS[0]
    assert "STRICT EVIDENCE GROUNDING RULES" in call["contents"]
    assert "OWASP" in call["contents"]


def test_explainer_rejects_hallucinated_file_and_falls_back():
    """Anti-hallucination initiative test:
    When Gemini invents a filename not in the evidence, output is rejected and fallback used."""
    finding = {
        "category": "hardcoded_secret",
        "label": "Stripe Secret Key",
        "file": "src/config.ts",
    }
    # LLM hallucinates an unrelated file 'src/auth/jwt_controller.py'
    mock_response = mock.MagicMock()
    mock_response.text = json.dumps({
        "what_it_means": "An exposed secret was discovered inside src/auth/jwt_controller.py.",
        "why_it_matters": "Attackers can compromise the authentication module.",
    })

    mock_client = mock.MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    mock_genai = mock.MagicMock()
    mock_genai.Client.return_value = mock_client

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch.dict("sys.modules", {"google": mock.MagicMock(genai=mock_genai), "google.genai": mock_genai}):
            res = explain(finding, platform="generic")

    # Hallucinated response must be rejected, and clean fallback returned referencing src/config.ts
    assert "jwt_controller.py" not in res["what_it_means"]
    assert "src/config.ts" in res["what_it_means"]


# ---------------------------------------------------------------------------
# Fix-Prompt Agent Platform-Aware Fallbacks & Grounding Tests
# ---------------------------------------------------------------------------

def test_fixprompt_platform_aware_lovable_supabase():
    finding = {
        "category": "missing_access_control",
        "label": "Row-Level Security not enabled",
        "file": "supabase/migrations/2024.sql",
        "table": "documents",
    }
    prompt = generate_fix_prompt(finding, platform="lovable_supabase")
    assert "ALTER TABLE documents ENABLE ROW LEVEL SECURITY;" in prompt
    assert "auth.uid()" in prompt


def test_fixprompt_platform_aware_replit():
    finding = {
        "category": "hardcoded_secret",
        "label": "Stripe Secret Key",
        "file": "app.py",
    }
    prompt = generate_fix_prompt(finding, platform="replit")
    assert "Replit" in prompt
    assert "Tools > Secrets" in prompt or "Secrets" in prompt


def test_fixprompt_platform_aware_bolt_v0():
    finding = {
        "category": "hardcoded_secret",
        "label": "Private Key",
        "file": "src/lib/keys.ts",
    }
    prompt = generate_fix_prompt(finding, platform="bolt_v0")
    assert ".env.local" in prompt
    assert "NEXT_PUBLIC_" in prompt or "VITE_" in prompt


def test_fixprompt_rejects_hallucinated_file_and_falls_back():
    """Anti-hallucination test:
    When model generates a fix targeting an invented file, reject and use platform fallback."""
    finding = {
        "category": "hardcoded_secret",
        "label": "AWS Key",
        "file": "src/aws_client.ts",
    }
    # LLM hallucinates an invented file
    mock_response = mock.MagicMock()
    mock_response.text = "Open src/backend/secrets_loader.py and delete the AWS secret key."

    mock_client = mock.MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    mock_genai = mock.MagicMock()
    mock_genai.Client.return_value = mock_client

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch.dict("sys.modules", {"google": mock.MagicMock(genai=mock_genai), "google.genai": mock_genai}):
            prompt = generate_fix_prompt(finding, platform="generic")

    assert "secrets_loader.py" not in prompt
    assert "src/aws_client.ts" in prompt


def test_fixprompt_gemini_success_is_used_and_grounded():
    finding = {
        "category": "hardcoded_secret",
        "label": "AWS Key",
        "file": "src/aws_client.ts",
    }
    mock_response = mock.MagicMock()
    mock_response.text = "Remove the secret from src/aws_client.ts and load it from an environment variable."
    mock_client = mock.MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    mock_genai = mock.MagicMock()
    mock_genai.Client.return_value = mock_client

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch.dict("sys.modules", {"google": mock.MagicMock(genai=mock_genai), "google.genai": mock_genai}):
            prompt = generate_fix_prompt(finding, platform="generic")

    assert prompt == mock_response.text
    call = mock_client.models.generate_content.call_args.kwargs
    assert call["model"] == fixprompt_mod.MODELS[0]
    assert "STRICT EVIDENCE GROUNDING RULES" in call["contents"]


@pytest.mark.parametrize("finding, response", [
    (
        {"category": "hardcoded_secret", "label": "AWS Key", "file": "src/config/aws.ts"},
        "Add `AWS_ACCESS_KEY_ID=your-key` to your `.env` file and remove the key from src/config/aws.ts.",
    ),
    (
        {"category": "hardcoded_secret", "label": "AWS Key", "file": "src/config/aws.ts"},
        "Edit `src/config/aws.ts` and load the value from the server environment.",
    ),
    (
        {
            "category": "missing_access_control", "label": "RLS missing",
            "file": "supabase/migrations/init.sql", "table": "documents",
        },
        "Run ALTER TABLE documents ENABLE ROW LEVEL SECURITY; then add a policy using auth.uid().",
    ),
])
def test_fixprompt_accepts_realistic_grounded_remediation(finding, response):
    mock_response = mock.MagicMock(text=response)
    mock_client = mock.MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    mock_genai = mock.MagicMock()
    mock_genai.Client.return_value = mock_client

    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}):
        with mock.patch.dict("sys.modules", {"google": mock.MagicMock(genai=mock_genai), "google.genai": mock_genai}):
            assert generate_fix_prompt(finding, platform="generic") == response


# ---------------------------------------------------------------------------
# Evidence Guard Unit Tests
# ---------------------------------------------------------------------------

def test_extract_mentioned_files():
    text = "Check src/lib/auth.ts and also .env.local for secrets. Do not touch config.py."
    files = extract_mentioned_files(text)
    assert "src/lib/auth.ts" in files
    assert ".env.local" in files
    assert "config.py" in files


def test_extract_mentioned_lines():
    text = "Issue found on line 42 and another alert at line 89."
    lines = extract_mentioned_lines(text)
    assert lines == [42, 89]


def test_validate_evidence_grounding_valid():
    finding = {
        "file": "src/services/api.ts",
        "line": 20,
        "table": "users",
        "category": "missing_access_control",
    }
    # Valid output referencing only evidence file, allowed platform file, and evidence table
    valid_text = "In src/services/api.ts, enable RLS for table 'users' and update .env."
    is_valid, reason = validate_evidence_grounding(valid_text, finding)
    assert is_valid is True
    assert reason is None


def test_validate_evidence_grounding_hallucinated_file():
    finding = {
        "file": "src/services/api.ts",
        "line": 20,
    }
    hallucinated_text = "The issue is located in src/handlers/auth_helper.js."
    is_valid, reason = validate_evidence_grounding(hallucinated_text, finding)
    assert is_valid is False
    assert "hallucinated file" in reason.lower()
    assert "auth_helper.js" in reason


def test_validate_evidence_grounding_hallucinated_line():
    finding = {
        "file": "src/services/api.ts",
        # No line specified in finding
    }
    hallucinated_text = "Inspect src/services/api.ts on line 95 to fix the flaw."
    is_valid, reason = validate_evidence_grounding(hallucinated_text, finding)
    assert is_valid is False
    assert "line number 95" in reason


def test_validate_evidence_grounding_requires_exact_line():
    finding = {"file": "src/services/api.ts", "line": 20}
    is_valid, reason = validate_evidence_grounding("Review src/services/api.ts on line 21.", finding)
    assert is_valid is False
    assert "line 21" in reason


def test_validate_evidence_grounding_does_not_parse_freeform_code_quotes():
    finding = {
        "file": "src/services/api.ts",
        "snippet": "fetch('/api/profile')",
    }
    is_valid, reason = validate_evidence_grounding(
        "Replace `axios.get('/api/admin')` in src/services/api.ts.", finding
    )
    assert is_valid is True
    assert reason is None


@pytest.mark.parametrize("text", [
    "Add `AWS_ACCESS_KEY_ID=your-key` to your .env file.",
    "Set it as a variable named `AWS_ACCESS_KEY_ID`.",
    "Remove the `NEXT_PUBLIC_` prefix.",
    "Edit `src/config/aws.ts`.",
    "Replace the made-up `db.update(users).set({admin: true})` call.",
])
def test_validate_evidence_grounding_allows_remediation_wording(text):
    finding = {"file": "src/config/aws.ts", "snippet": "const key = '[secret redacted]';"}
    is_valid, reason = validate_evidence_grounding(text, finding)
    assert is_valid is True
    assert reason is None


@pytest.mark.parametrize("filename", ["next.config.js", "vite.config.js", "vite.config.ts", "vercel.json", "netlify.toml", "middleware.ts"])
def test_validate_evidence_grounding_allows_deployment_config_files(filename):
    finding = {"file": "https://example.com", "category": "missing_header"}
    is_valid, reason = validate_evidence_grounding(f"Edit {filename} to add the header.", finding)
    assert is_valid is True
    assert reason is None


def test_validate_evidence_grounding_allows_parenthetical_prose():
    finding = {"file": "src/services/api.ts", "label": "Unsafe API request"}
    is_valid, reason = validate_evidence_grounding(
        "The issue was found in your code (src/services/api.ts).", finding
    )
    assert is_valid is True
    assert reason is None


def test_validate_evidence_grounding_hallucinated_table():
    finding = {
        "file": "supabase/migrations/init.sql",
        "table": "profiles",
        "category": "missing_access_control",
    }
    hallucinated_text = "Add RLS policies to table 'credit_cards'."
    is_valid, reason = validate_evidence_grounding(hallucinated_text, finding)
    assert is_valid is False
    assert "credit_cards" in reason


# ---------------------------------------------------------------------------
# Curated Retrieval Unit Tests
# ---------------------------------------------------------------------------

def test_curated_retrieval_returns_vetted_docs():
    topics = get_available_topics()
    assert "supabase_rls" in topics
    assert "owasp_top_10" in topics
    assert "replit_security" in topics
    assert "bolt_v0_security" in topics
    assert "security_headers" in topics

    supabase_doc = get_curated_doc("missing_access_control", platform="lovable_supabase")
    assert "Row Level Security" in supabase_doc
    assert "auth.uid()" in supabase_doc

    replit_doc = get_curated_doc("hardcoded_secret", platform="replit")
    assert "Replit Secrets" in replit_doc

    bolt_doc = get_curated_doc("hardcoded_secret", platform="bolt_v0")
    assert "NEXT_PUBLIC_" in bolt_doc


# ---------------------------------------------------------------------------
# Structured Vulnerability Lookup via MCP Unit Tests
# ---------------------------------------------------------------------------

def test_format_vulnerability_evidence():
    sample_osv = {
        "id": "GHSA-j8xg-fqg3-53r8",
        "aliases": ["CVE-2020-28500"],
        "summary": "Prototype Pollution in lodash",
        "details": "Lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution.",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
            }
        ],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    }
    evidence = format_vulnerability_evidence(sample_osv)
    assert evidence["vulnerability_id"] == "CVE-2020-28500"
    assert "4.17.21" in evidence["fixed_versions"]
    assert "Prototype Pollution" in evidence["summary"]
    assert "OSV.dev" in evidence["database_source"]


def test_mcp_lookup_vulnerability_tool_mocked():
    sample_osv = {
        "id": "CVE-2021-23337",
        "summary": "Command Injection in lodash",
        "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
    }
    with mock.patch("agents.vulnerability_lookup.query_osv_package", return_value=[sample_osv]):
        tool_output = mcp_lookup_vulnerability_tool({"package": "lodash", "version": "4.17.15"})
        parsed = json.loads(tool_output)
        assert parsed["status"] == "vulnerabilities_found"
        assert parsed["package"] == "lodash"
        assert len(parsed["evidence"]) == 1
        assert parsed["evidence"][0]["vulnerability_id"] == "CVE-2021-23337"


# ---------------------------------------------------------------------------
# Verify Agent Unit Tests
# ---------------------------------------------------------------------------

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

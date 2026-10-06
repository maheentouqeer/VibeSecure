from pathlib import Path

from agents.fraud_risk_agent import analyze_finding, summarize
from backend.risk import build_context, build_hardening
from scanner.hardening_scanner import scan_hardening


def test_missing_authorization_maps_to_impersonation_path():
    result = analyze_finding(
        {
            "id": "f1",
            "category": "missing_access_control",
            "label": "Authorization missing",
            "file": "api/orders.ts",
            "severity": "critical",
            "fix_prompt": "Enforce server-side ownership checks.",
        }
    )
    assert result["risk_band"] == "critical"
    assert result["fraud_category"] == "Account takeover / unauthorized access"
    assert "Impersonation" in result["business_impact"]


def test_secret_risk_is_very_high_and_actionable():
    result = analyze_finding(
        {
            "id": "f2",
            "category": "hardcoded_secret",
            "label": "Stripe Secret Key",
            "file": "src/config.ts",
            "severity": "critical",
            "fix_prompt": "Move the key to a server-side secret.",
        }
    )
    assert result["risk_score"] == 99
    assert result["fraud_category"] == "Credential theft / impersonation"
    assert result["recommended_fix"]


def test_context_exposes_verification_and_not_checked_controls():
    context = build_context(
        [
            {
                "id": "f1",
                "category": "cors_misconfig",
                "label": "CORS allows any origin (*)",
                "file": "server.ts",
                "severity": "high",
                "status": "open",
                "fix_prompt": "Restrict CORS.",
            }
        ]
    )
    assert context["open_high_critical"] == 1
    assert context["verification"]["passed"] is False
    assert any(item["status"] == "not_checked" for item in context["hardening"]["items"])


def test_hardening_marks_detected_control_attention():
    hardening = build_hardening(
        [
            {
                "id": "f1",
                "category": "hardcoded_secret",
                "label": "Stripe Secret Key",
                "file": "src/config.ts",
                "status": "open",
            }
        ]
    )
    secrets = next(item for item in hardening["items"] if item["id"] == "secrets")
    assert secrets["status"] == "attention"
    assert hardening["attention"] == 1


def test_hardening_scanner_finds_high_signal_client_secret(tmp_path: Path):
    source = tmp_path / "env.ts"
    source.write_text('const key = import.meta.env.VITE_STRIPE_SECRET_KEY = "x";\\n')
    findings = scan_hardening(tmp_path)
    assert any(item["category"] == "public_secret_env" for item in findings)
    secret = next(item for item in findings if item["category"] == "public_secret_env")
    assert secret["raw_severity"] == "critical"
    assert secret["line"] == 1


def test_empty_summary_is_safe():
    summary = summarize([])
    assert summary["overall_risk_score"] == 0
    assert summary["top_finding"] is None

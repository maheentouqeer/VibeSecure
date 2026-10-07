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


def test_context_exposes_verification_and_all_hardening_controls():
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
    assert context["hardening"]["total"] == 15
    assert context["hardening"]["checked"] == 15
    assert all(item["automated"] for item in context["hardening"]["items"])


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

def test_resolved_findings_do_not_keep_current_risk_open():
    context = build_context(
        [
            {
                "id": "old",
                "category": "missing_access_control",
                "label": "Authorization missing",
                "file": "api/orders.ts",
                "severity": "critical",
                "status": "resolved",
                "fix_prompt": "Enforce server-side ownership checks.",
            }
        ]
    )
    assert context["finding_count"] == 1
    assert context["open_high_critical"] == 0
    assert context["verification"]["passed"] is True
    assert context["fraud_findings"] == []
    assert context["hardening"]["checked"] == 15


def test_hardening_scanner_flags_client_side_authorization_and_unsafe_upload(tmp_path: Path):
    source = tmp_path / "admin.tsx"
    source.write_text(
        'const isAdmin = await supabase.from("user_roles").select("role");\n'
        'await supabase.storage.from("auction-media").upload(path, file);\n'
        'accept="image/*"\n'
    )
    findings = scan_hardening(tmp_path)
    categories = {item["category"] for item in findings}
    assert "client_side_authorization" in categories
    assert "unsafe_file_upload" in categories


def test_hardening_scanner_flags_missing_dependency_lockfile(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"dependencies":{"react":"19.0.0"}}')
    findings = scan_hardening(tmp_path)
    dependency = next(item for item in findings if item["category"] == "missing_dependency_lockfile")
    assert dependency["raw_severity"] == "medium"


def test_hardening_scanner_flags_explicitly_disabled_security_controls(tmp_path: Path):
    source = tmp_path / "security.py"
    source.write_text(
        "@csrf_exempt\ndef update(): pass\n"
        "response.set_cookie('session', token, secure=False, httponly=False)\n"
        "RATE_LIMIT_ENABLED = False\n"
        "logging.disable(logging.CRITICAL)\n"
    )
    categories = {item["category"] for item in scan_hardening(tmp_path)}
    assert "csrf_disabled" in categories
    assert "insecure_cookie_config" in categories
    assert "rate_limit_disabled" in categories
    assert "security_logging_disabled" in categories


def test_all_secret_labels_receive_fraud_impact():
    labels = [
        "AWS Access Key",
        "Stripe Secret Key",
        "GitHub Token",
        "Google API Key",
        "Generic Bearer Secret",
        "High Entropy Secret (entropy: 4.58)",
    ]
    for label in labels:
        result = analyze_finding(
            {
                "id": label,
                "category": "hardcoded_secret",
                "label": label,
                "file": "security-lab/secrets.ts",
                "severity": "critical" if "Entropy" not in label else "high",
                "fix_prompt": "Move the credential to a server-side secret and rotate it.",
            }
        )
        assert result["fraud_category"] == "Credential theft / impersonation"
        assert result["attack_path"]
        assert result["recommended_fix"]

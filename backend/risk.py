"""Security-context API helpers for VibeSecure 2.0.

Keeps the existing findings database contract unchanged. The fraud impact,
attack-path, and hardening views are derived from persisted scanner evidence
at read time, so no destructive migration is needed for ForgeHacks V1.
"""
from __future__ import annotations

from typing import Any

from agents.fraud_risk_agent import summarize


_HARDENING_CONTROLS: tuple[dict[str, Any], ...] = (
    {"id": "secrets", "title": "Secrets & API keys", "description": "Secrets should live outside source and public artifacts.", "keywords": ("hardcoded_secret", "secret", "api key", "token")},
    {"id": "env", "title": "Environment file protection", "description": "Sensitive .env files should never be publicly served or committed.", "keywords": ("exposed .env", "exposed_file")},
    {"id": "auth", "title": "Authentication", "description": "Sensitive routes should require a verified identity.", "keywords": ("authentication", "jwt", "login", "password")},
    {"id": "authorization", "title": "Authorization / RLS", "description": "Server-side ownership and Supabase RLS should protect user-scoped data.", "keywords": ("missing_access_control", "authorization", "row-level security", "access control")},
    {"id": "sql-injection", "title": "SQL injection", "description": "Attacker-controlled input must not alter database queries.", "keywords": ("sql", "injection", "query")},
    {"id": "xss", "title": "Cross-site scripting", "description": "Untrusted content should not execute in a user's browser.", "keywords": ("xss", "cross-site scripting", "innerhtml")},
    {"id": "cors", "title": "CORS boundary", "description": "Only trusted application origins should access browser-facing APIs.", "keywords": ("cors_misconfig", "cors allows any origin")},
    {"id": "headers", "title": "Security headers", "description": "Browser hardening headers reduce common web attack paths.", "keywords": ("missing_header", "content-security-policy", "x-frame-options", "strict-transport-security")},
    {"id": "csrf", "title": "CSRF protection", "description": "State-changing browser actions should resist cross-site request forgery.", "keywords": ("csrf_disabled", "csrf_exempt", "csrf protection disabled")},
    {"id": "cookies", "title": "Secure cookies", "description": "Authentication cookies should use secure, HttpOnly, and appropriate SameSite settings.", "keywords": ("insecure_cookie_config", "insecure cookie")},
    {"id": "rate-limit", "title": "Rate limiting", "description": "Login, recovery, and high-value actions should resist automation.", "keywords": ("rate_limit_disabled", "rate limiting disabled", "skip_rate_limit")},
    {"id": "uploads", "title": "File-upload controls", "description": "Uploads should validate type, size, storage, and execution risk.", "keywords": ("unsafe_file_upload",)},
    {"id": "dependencies", "title": "Dependency hygiene", "description": "Dependency manifests should be accompanied by a lockfile before release.", "keywords": ("missing_dependency_lockfile",)},
    {"id": "client-trust", "title": "Client-side trust", "description": "Security decisions should be enforced on the server, not only in the UI.", "keywords": ("client_side_authorization",)},
    {"id": "logging", "title": "Security audit logging", "description": "Important authentication and security events should be observable.", "keywords": ("security_logging_disabled", "audit logging disabled", "logging disabled")},
)


def _finding_text(finding: dict[str, Any]) -> str:
    return " ".join(str(finding.get(key) or "") for key in ("category", "label", "what_it_means", "why_it_matters")).lower()


def build_hardening(findings: list[dict[str, Any]]) -> dict[str, Any]:
    items = []
    for control in _HARDENING_CONTROLS:
        matches = []
        if control["keywords"]:
            for finding in findings:
                haystack = _finding_text(finding)
                if any(keyword.lower() in haystack for keyword in control["keywords"]):
                    matches.append(finding)

        automated = True
        open_matches = [f for f in matches if str(f.get("status") or "open") == "open"]
        status = "attention" if open_matches else "no_finding"

        items.append(
            {
                "id": control["id"],
                "title": control["title"],
                "description": control["description"],
                "status": status,
                "automated": automated,
                "evidence_count": len(matches),
                "finding_ids": [str(f.get("id") or "") for f in matches[:8]],
            }
        )

    automated_count = sum(1 for item in items if item["automated"])
    checked_count = len(items)
    attention_count = sum(1 for item in items if item["status"] == "attention")
    return {
        "total": len(items),
        "automated": automated_count,
        "checked": checked_count,
        "attention": attention_count,
        "items": items,
        "note": "No finding means the active detector found no matching risky configuration or code pattern; it is not proof of security.",
    }


def build_attack_paths(assessments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "finding_id": item["finding_id"],
            "title": item["fraud_category"],
            "risk_score": item["risk_score"],
            "risk_band": item["risk_band"],
            "steps": item["attack_path"],
            "confidence": item["confidence"],
            "label": item["label"],
        }
        for item in assessments[:6]
    ]


def build_context(findings: list[dict[str, Any]]) -> dict[str, Any]:
    # Keep historical resolved findings visible to the UI, but never let them
    # inflate the current fraud-risk score or verification state.
    open_findings = [
        finding
        for finding in findings
        if str(finding.get("status") or "open") == "open"
    ]
    summary = summarize(open_findings)
    assessments = summary["findings"]
    open_high_critical = summary["open_high_critical"]
    return {
        "overall_risk_score": summary["overall_risk_score"],
        "overall_risk_band": summary["overall_risk_band"],
        "finding_count": len(findings),
        "open_high_critical": open_high_critical,
        "verification": {
            "passed": open_high_critical == 0,
            "label": "Attack paths clear for critical/high findings" if open_high_critical == 0 else "High-impact paths remain open",
        },
        "fraud_findings": assessments,
        "attack_paths": build_attack_paths(assessments),
        "hardening": build_hardening(findings),
        "methodology": "Deterministic mapping from scanner evidence. Fraud impact is an inferred risk scenario, not a claim that exploitation was performed.",
    }

"""Deterministic fraud/scam impact reasoning for VibeSecure 2.0.

This layer deliberately sits after deterministic scanners and before the UI.
It does not claim to prove exploitability. It maps scanner evidence to a
conservative attack path, fraud/impersonation category, business impact,
and a risk score. LLMs can be added later as a second opinion without
becoming the source of truth.
"""
from __future__ import annotations

from typing import Any


_SEVERITY_BASE = {
    "critical": 95,
    "high": 82,
    "medium": 60,
    "low": 30,
}


def _profile(finding: dict[str, Any]) -> dict[str, Any]:
    category = str(finding.get("category") or "").lower()
    text = " ".join(
        str(finding.get(key) or "")
        for key in ("label", "what_it_means", "why_it_matters")
    ).lower()

    if category == "hardcoded_secret":
        return {
            "fraud_category": "Credential theft / impersonation",
            "attacker_action": "Obtain the exposed credential from source, artifacts, or a leaked build context.",
            "victim_impact": "An attacker may act with the compromised service or user identity and access protected data or actions.",
            "business_impact": "Account impersonation, unauthorized transactions, API abuse, privacy exposure, or direct financial loss.",
            "steps": [
                "Exposed credential is reachable",
                "Attacker obtains or reuses the credential",
                "Protected identity or service is impersonated",
                "Sensitive data or business action is abused",
                "Fraud / account abuse becomes possible",
            ],
            "confidence": 0.93,
            "boost": 4,
        }

    if category == "missing_access_control" or "authorization" in text or "access control" in text:
        return {
            "fraud_category": "Account takeover / unauthorized access",
            "attacker_action": "Reach a protected resource while changing or omitting the identity/ownership check.",
            "victim_impact": "Another user's private records or account-scoped actions may become accessible to the attacker.",
            "business_impact": "Impersonation, order manipulation, fraudulent account actions, privacy abuse, and trust loss.",
            "steps": [
                "Authorization boundary is missing or weak",
                "Attacker reaches a protected route or record",
                "Victim-scoped data or actions become accessible",
                "Attacker can act outside their account",
                "Impersonation / fraud risk increases",
            ],
            "confidence": 0.94,
            "boost": 7,
        }

    if category == "exposed_file":
        return {
            "fraud_category": "Credential / configuration theft",
            "attacker_action": "Request an exposed configuration or repository file that should never be public.",
            "victim_impact": "Secrets or deployment details may be recovered and reused against the application.",
            "business_impact": "Credential abuse, service takeover, data exposure, or downstream financial impact.",
            "steps": [
                "Sensitive file is publicly reachable",
                "Attacker downloads configuration or metadata",
                "Credential or internal detail is recovered",
                "Protected service is targeted",
                "Fraud / service abuse becomes possible",
            ],
            "confidence": 0.95,
            "boost": 6,
        }

    if category == "cors_misconfig" or "cors" in text:
        return {
            "fraud_category": "Cross-origin credential abuse",
            "attacker_action": "Use an untrusted origin to make browser-mediated requests where the server trusts the caller too broadly.",
            "victim_impact": "Authenticated users may be exposed to unintended cross-origin actions depending on cookie and auth configuration.",
            "business_impact": "Account actions, data exposure, or transaction abuse can become easier to trigger from a malicious origin.",
            "steps": [
                "Untrusted origins are accepted",
                "Malicious origin can reach browser-accessible API surface",
                "Victim session may be abused in the browser",
                "Sensitive action or data is reached",
                "Fraud / account abuse becomes possible",
            ],
            "confidence": 0.86,
            "boost": 3,
        }

    if category == "missing_header":
        return {
            "fraud_category": "Session / UI abuse",
            "attacker_action": "Exploit a missing browser security control to weaken the application's defensive boundary.",
            "victim_impact": "A user may be exposed to clickjacking or other browser-mediated abuse depending on the missing header.",
            "business_impact": "Sensitive workflows can be manipulated or social-engineering attacks can become easier.",
            "steps": [
                "Browser security control is missing",
                "A defensive browser boundary is weaker",
                "Attacker attempts UI or session abuse",
                "Sensitive workflow may be manipulated",
            ],
            "confidence": 0.74,
            "boost": 0,
        }

    if category == "static_analysis":
        if any(word in text for word in ("sql", "injection", "query")):
            return {
                "fraud_category": "Data / transaction manipulation",
                "attacker_action": "Inject attacker-controlled input into a database operation.",
                "victim_impact": "Records outside the intended scope may be read or modified.",
                "business_impact": "Order, payment, inventory, identity, or account data can be manipulated for fraud.",
                "steps": [
                    "Attacker controls an input",
                    "Input reaches a database operation unsafely",
                    "Database query behavior is altered",
                    "Sensitive or transactional data is changed",
                    "Fraudulent outcome may be possible",
                ],
                "confidence": 0.84,
                "boost": 5,
            }
        if any(word in text for word in ("xss", "cross-site scripting", "innerhtml", "script")):
            return {
                "fraud_category": "Session hijack / impersonation",
                "attacker_action": "Inject script content into a browser-executed application context.",
                "victim_impact": "A victim's browser session or trusted UI context may be manipulated.",
                "business_impact": "Credential capture, session abuse, fraudulent actions, and social-engineering enablement.",
                "steps": [
                    "Attacker-controlled content reaches the browser",
                    "Injected script executes in a trusted context",
                    "Victim session or page state is targeted",
                    "Attacker attempts credential or action theft",
                    "Impersonation / fraud risk increases",
                ],
                "confidence": 0.82,
                "boost": 4,
            }
        if any(word in text for word in ("ssrf", "server-side request")):
            return {
                "fraud_category": "Internal / credential access",
                "attacker_action": "Influence a server-side request toward an unintended destination.",
                "victim_impact": "Internal services or cloud metadata may become reachable from the application's network context.",
                "business_impact": "Credential theft, privileged API access, and downstream account or service abuse.",
                "steps": [
                    "Attacker controls a network destination",
                    "Server makes the request on the attacker's behalf",
                    "Internal service or metadata becomes reachable",
                    "Credential or privileged capability is recovered",
                    "Service / account abuse may follow",
                ],
                "confidence": 0.86,
                "boost": 5,
            }
        if any(word in text for word in ("command injection", "os command", "shell", "exec")):
            return {
                "fraud_category": "Remote code execution / service abuse",
                "attacker_action": "Inject attacker-controlled input into a command or execution primitive.",
                "victim_impact": "The application environment may be used to access secrets, data, or privileged capabilities.",
                "business_impact": "Service takeover, data theft, destructive actions, and fraud-enabling compromise.",
                "steps": [
                    "Attacker controls execution input",
                    "Unsafe command reaches the runtime",
                    "Application executes attacker influence",
                    "Secrets or privileged actions become reachable",
                    "Full service abuse may become possible",
                ],
                "confidence": 0.9,
                "boost": 7,
            }
        if any(word in text for word in ("jwt", "authentication", "auth", "password")):
            return {
                "fraud_category": "Authentication / impersonation risk",
                "attacker_action": "Exploit a weak authentication or token-handling path to obtain or forge user authority.",
                "victim_impact": "An attacker may operate as another user or bypass a security boundary.",
                "business_impact": "Account takeover, fraudulent actions, privacy exposure, and loss of customer trust.",
                "steps": [
                    "Authentication control is weakened",
                    "Attacker targets the identity boundary",
                    "User authority is obtained or forged",
                    "Protected account actions become reachable",
                    "Impersonation / fraud becomes possible",
                ],
                "confidence": 0.8,
                "boost": 5,
            }

    if category == "scan_incomplete":
        return {
            "fraud_category": "Unknown — scan incomplete",
            "attacker_action": "No conclusion should be drawn until the missing security check completes.",
            "victim_impact": "The current result cannot establish that the application is safe.",
            "business_impact": "An incomplete scan can hide security or fraud paths and should be treated as a verification gap.",
            "steps": [
                "Security check did not complete",
                "Evidence is incomplete",
                "Risk cannot be bounded reliably",
            ],
            "confidence": 0.98,
            "boost": 0,
        }

    return {
        "fraud_category": "Potential application abuse",
        "attacker_action": "Probe the affected code path for a way to cross an intended trust boundary.",
        "victim_impact": "A vulnerable path may expose data or permit an unintended application action.",
        "business_impact": "The exact fraud scenario depends on what the affected path protects or changes.",
        "steps": [
            "Vulnerable code path is identified",
            "Attacker probes the trust boundary",
            "Protected behavior may be reached",
            "Impact depends on the affected resource",
        ],
        "confidence": 0.62,
        "boost": 0,
    }


def analyze_finding(finding: dict[str, Any]) -> dict[str, Any]:
    severity = str(finding.get("severity") or finding.get("raw_severity") or "medium").lower()
    base = _SEVERITY_BASE.get(severity, 60)
    profile = _profile(finding)
    score = max(0, min(100, base + int(profile["boost"])))
    if str(finding.get("category") or "") == "scan_incomplete":
        score = 45

    if score >= 90:
        band = "critical"
    elif score >= 75:
        band = "high"
    elif score >= 50:
        band = "medium"
    else:
        band = "low"

    return {
        "finding_id": str(finding.get("id") or ""),
        "label": str(finding.get("label") or "Security finding"),
        "category": str(finding.get("category") or "unknown"),
        "file": str(finding.get("file") or ""),
        "severity": severity,
        "risk_score": score,
        "risk_band": band,
        "fraud_category": profile["fraud_category"],
        "attacker_action": profile["attacker_action"],
        "victim_impact": profile["victim_impact"],
        "business_impact": profile["business_impact"],
        "attack_path": profile["steps"],
        "confidence": profile["confidence"],
        "recommended_fix": str(finding.get("fix_prompt") or "Investigate and remediate the finding."),
        "evidence": {
            "file": str(finding.get("file") or ""),
            "severity": severity,
            "category": str(finding.get("category") or ""),
        },
    }


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    assessments = [analyze_finding(f) for f in findings]
    assessments.sort(key=lambda item: item["risk_score"], reverse=True)

    open_high = sum(
        1
        for f in assessments
        if f["severity"] in ("critical", "high")
    )
    if not assessments:
        overall = 0
    else:
        top = assessments[:5]
        overall = round(sum(f["risk_score"] for f in top) / len(top))

    if overall >= 90:
        band = "critical"
    elif overall >= 75:
        band = "high"
    elif overall >= 50:
        band = "medium"
    elif overall > 0:
        band = "low"
    else:
        band = "low"

    return {
        "overall_risk_score": overall,
        "overall_risk_band": band,
        "open_high_critical": open_high,
        "top_finding": assessments[0] if assessments else None,
        "findings": assessments,
    }

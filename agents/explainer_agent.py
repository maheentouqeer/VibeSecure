"""STUB — placeholder for Ali's real Explainer Agent (Gemini-based).

CONTRACT — do not change without telling the team:
  input:  one finding dict (post-triage)
  output: dict with exactly these keys: what_it_means, why_it_matters
"""

_TEMPLATES = {
    "hardcoded_secret": (
        "A secret or API key is hardcoded directly in your code.",
        "Anyone who sees this code, including in a public repo, can use that key to access your accounts or services.",
    ),
    "static_analysis": (
        "A known unsafe coding pattern was found by the scanner.",
        "This could let an attacker manipulate your app in ways you didn't intend.",
    ),
    "missing_access_control": (
        "This database table has no access rules protecting it.",
        "Anyone with your app's public key could read or change every row in this table.",
    ),
    "exposed_file": (
        "A sensitive configuration file is publicly reachable on your live site.",
        "Anyone can view it directly in a browser and see what's inside.",
    ),
    "missing_header": (
        "Your site is missing a standard security header.",
        "This makes certain browser-based attacks against your users easier.",
    ),
    "cors_misconfig": (
        "Your site allows requests from any website (CORS wide open).",
        "Other websites could make requests to your app on a visitor's behalf without permission.",
    ),
}

_DEFAULT = ("A potential security issue was found.", "This could expose your app or its users to risk.")


def explain(finding: dict) -> dict:
    """STUB: templated explanation by category. Replace with a real
    Gemini call for finding-specific, plain-language explanations —
    keep the two output keys the same."""
    what, why = _TEMPLATES.get(finding.get("category"), _DEFAULT)
    return {"what_it_means": what, "why_it_matters": why}

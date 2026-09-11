"""Explainer Agent (Gemini-based).

CONTRACT — do not change without telling the team:
  input:  one finding dict (post-triage)
  output: dict with exactly these keys: what_it_means, why_it_matters
"""

import json
import os
from typing import Any

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


def _fallback_explain(finding: dict[str, Any]) -> dict[str, str]:
    what, why = _TEMPLATES.get(finding.get("category", ""), _DEFAULT)
    return {"what_it_means": what, "why_it_matters": why}


def explain(finding: dict) -> dict:
    """Uses Gemini to generate plain-language explanations tailored to the specific finding.
    Keeps the two contract keys: what_it_means, why_it_matters.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return _fallback_explain(finding)

    prompt = f"""You are a helpful security educator explaining a vulnerability to an application developer.
Explain the following security finding in clear, plain, and non-jargon language:
{json.dumps(finding, indent=2)}

Output MUST be a JSON object with exactly two string keys:
- "what_it_means": Explain what this vulnerability is in simple terms (1-2 sentences).
- "why_it_matters": Explain the practical risk/consequences if left unfixed (1-2 sentences).

Do not include markdown code formatting or surrounding explanations, output only raw JSON.
"""

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        text = response.text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        data = json.loads(text)
        if isinstance(data, dict) and "what_it_means" in data and "why_it_matters" in data:
            return {
                "what_it_means": str(data["what_it_means"]),
                "why_it_matters": str(data["why_it_matters"]),
            }
    except Exception:
        pass

    return _fallback_explain(finding)

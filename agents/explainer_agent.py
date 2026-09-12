"""Explainer Agent (Gemini-based).

CONTRACT — do not change without telling the team:
  input:  one finding dict (post-triage)
  output: dict with exactly these keys: what_it_means, why_it_matters
"""

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

MODELS = ("gemini-3.8-flash", "gemini-3.6-flash")

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
    Cascades through models before falling back to pre-defined explanation templates.
    Keeps the two contract keys: what_it_means, why_it_matters.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logger.debug("GEMINI_API_KEY not set; using fallback explainer.")
        return _fallback_explain(finding)

    prompt = f"""You are a cybersecurity expert explaining vulnerabilities to a non-expert developer.
Analyze the following security finding and explain it clearly in plain English.

Finding details:
{json.dumps(finding, indent=2)}

Respond with a valid JSON object containing exactly these two keys:
- "what_it_means": A simple 1-2 sentence explanation of what this vulnerability is in plain terms.
- "why_it_matters": A simple 1-2 sentence explanation of the real-world risk or impact to the app/users.

Return ONLY the raw JSON object, without markdown formatting or code blocks.
"""

    try:
        from google import genai
<<<<<<< HEAD
=======
        from google.genai import types
>>>>>>> origin/main

        client = genai.Client(api_key=api_key)
        for model in MODELS:
            try:
<<<<<<< HEAD
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
=======
                config = types.GenerateContentConfig(
                    response_mime_type="application/json",
                )
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=config,
>>>>>>> origin/main
                )
                text = (response.text or "").strip()
                if text.startswith("```"):
                    lines = text.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    text = "\n".join(lines).strip()

<<<<<<< HEAD
                parsed = json.loads(text)
                if isinstance(parsed, dict) and "what_it_means" in parsed and "why_it_matters" in parsed:
                    return {
                        "what_it_means": str(parsed["what_it_means"]).strip(),
                        "why_it_matters": str(parsed["why_it_matters"]).strip(),
                    }
            except Exception as model_err:
                logger.warning("Error explaining finding with model %s: %s", model, model_err)
                continue
    except Exception as err:
        logger.warning("Failed to initialize or execute Gemini client for explainer: %s", err)
=======
                data = json.loads(text)
                if isinstance(data, dict) and "what_it_means" in data and "why_it_matters" in data:
                    return {
                        "what_it_means": str(data["what_it_means"]),
                        "why_it_matters": str(data["why_it_matters"]),
                    }
                logger.warning(
                    "Model %s returned JSON missing expected keys: %s",
                    model,
                    text,
                )
            except Exception as model_err:
                logger.warning("Error generating explanation with model %s: %s", model, model_err)
                continue
    except Exception as err:
        logger.warning("Failed to initialize or run Gemini client: %s", err)
>>>>>>> origin/main

    return _fallback_explain(finding)

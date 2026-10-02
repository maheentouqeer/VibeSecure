"""Explainer Agent (Gemini-based with Platform-Aware Fallbacks & Evidence-Strict Grounding).

CONTRACT — do not change without telling the team:
  input:  one finding dict (post-triage), optional platform string
  output: dict with exactly these keys: what_it_means, why_it_matters
"""

import json
import logging
import os
from typing import Any, Optional

from agents.curated_retrieval import get_curated_doc
from agents.evidence_guard import (
    EVIDENCE_STRICT_DIRECTIVE,
    validate_evidence_grounding,
)

from agents import gemini_models
from agents.privacy import PLACEHOLDER_NOTE, Masker

logger = logging.getLogger(__name__)

# Model order and health tracking live in agents/gemini_models.py (override with GEMINI_MODELS).
MODELS = gemini_models.DEFAULT_MODELS

# Generic fallback templates
_GENERIC_TEMPLATES = {
    "hardcoded_secret": (
        "A secret or API key is hardcoded directly in your code ({file}).",
        "Anyone who sees this code, including in a public repository, can use that key to access your accounts or services.",
    ),
    "static_analysis": (
        "A known unsafe coding pattern was found by the scanner in {file}: {label}.",
        "This could let an attacker manipulate your app in ways you didn't intend.",
    ),
    "missing_access_control": (
        "The database table '{table}' has no access control rules protecting it.",
        "Anyone with your app's public key could read or change every row in this table.",
    ),
    "exposed_file": (
        "A sensitive configuration file ({file}) is publicly reachable on your live site.",
        "Anyone can view it directly in a browser and see what's inside.",
    ),
    "missing_header": (
        "Your site is missing a standard security header ({label}).",
        "This makes certain browser-based attacks against your users easier.",
    ),
    "cors_misconfig": (
        "Your site allows requests from any website (CORS wide open: *).",
        "Other websites could make requests to your app on a visitor's behalf without permission.",
    ),
    "scan_incomplete": (
        "The static analysis scanner didn't finish, so some issues may not have been checked for.",
        "Findings from this category of scan may be missing or incomplete for this run -- consider re-scanning.",
    ),
}

# Platform-specific explanation templates
_PLATFORM_EXPLANATIONS = {
    "lovable_supabase": {
        "missing_access_control": (
            "Row-Level Security (RLS) is disabled on table '{table}' in your Supabase database.",
            "In Lovable and Supabase apps, the anon public key is bundled in the frontend. Without RLS enabled, anyone can query or mutate all data in '{table}' via PostgREST APIs.",
        ),
        "hardcoded_secret": (
            "A secret or API credential is embedded directly in {file} within your Lovable project.",
            "Lovable client bundles are visible in browser DevTools. Exposing private credentials lets unauthorized users access your backend or third-party APIs.",
        ),
        "cors_misconfig": (
            "Your Supabase edge functions or Lovable routes allow requests from any origin (*).",
            "Malicious websites can issue cross-origin requests to your Supabase backend using the session of your logged-in users.",
        ),
        "exposed_file": (
            "A sensitive configuration file ({file}) is deployed to the public web root.",
            "Vercel or Lovable static deployments will serve this file directly to anyone requesting its path.",
        ),
        "static_analysis": (
            "An unsafe code pattern ({label}) was flagged in {file}.",
            "This pattern can lead to client-side injection, DOM manipulation, or state corruption in your Lovable app.",
        ),
        "missing_header": (
            "Your Lovable deployment is missing the {label} security header.",
            "Users browsing your app lack defense-in-depth protection against clickjacking or MIME-type sniffing.",
        ),
    },
    "bolt_v0": {
        "hardcoded_secret": (
            "A private secret or API key was found in {file} in your Bolt/v0 application.",
            "Bolt/v0 apps bundle code using Vite or Next.js. Any secret placed in client components or prefixed with NEXT_PUBLIC_/VITE_ is visible to any site visitor.",
        ),
        "missing_access_control": (
            "Database queries or server actions touching table '{table}' lack authorization checks.",
            "Attackers can invoke Bolt/v0 server actions or API endpoints directly, bypassing frontend UI checks to read or modify '{table}'.",
        ),
        "cors_misconfig": (
            "Your Next.js or Vite server configuration allows wildcard CORS requests (*).",
            "Untrusted third-party websites can interact with your Bolt/v0 API routes on behalf of your users.",
        ),
        "exposed_file": (
            "A sensitive file ({file}) is present in your Bolt/v0 public static assets.",
            "The production web server serves this file directly to any incoming HTTP request.",
        ),
        "static_analysis": (
            "A potential security or code quality issue ({label}) was identified in {file}.",
            "This unsafe pattern could lead to unexpected behavior or security bypass in your application.",
        ),
        "missing_header": (
            "Your Next.js/Vite HTTP response headers omit {label}.",
            "Client browsers will not enforce strict isolation rules for your Bolt/v0 app.",
        ),
    },
    "replit": {
        "hardcoded_secret": (
            "A secret credential is hardcoded in {file} instead of being stored in Replit Secrets.",
            "Public Repls and forks expose source code to viewers. Storing keys in Replit Secrets (Tools > Secrets) keeps them encrypted and secure.",
        ),
        "exposed_file": (
            "A sensitive file ({file}) is located in a publicly served folder in your Replit workspace.",
            "Replit's web server exposes files in public directories directly over the webview.",
        ),
        "missing_access_control": (
            "Backend routes manipulating '{table}' in your Replit application lack user identity checks.",
            "Any visitor to your public Replit URL can execute backend actions or manipulate records in '{table}'.",
        ),
        "cors_misconfig": (
            "Your Replit web server allows all cross-origin requests (*).",
            "External websites can make unauthorized API calls to your Repl container using visitor credentials.",
        ),
        "static_analysis": (
            "An unsafe coding pattern ({label}) was found in {file}.",
            "This pattern may allow command injection or unauthorized execution inside the Repl environment.",
        ),
        "missing_header": (
            "Your Replit web server response does not set {label}.",
            "Browsers visiting your deployed Repl will lack standard defensive protections against framing and sniffing.",
        ),
    },
}

_DEFAULT = ("A potential security issue was found in {file}.", "This could expose your app or its users to risk.")


def _normalize_platform(platform: Optional[str]) -> str:
    if not platform:
        return "generic"
    p = platform.lower()
    if "supabase" in p or "lovable" in p:
        return "lovable_supabase"
    if "replit" in p:
        return "replit"
    if "bolt" in p or "v0" in p:
        return "bolt_v0"
    return "generic"


def _fallback_explain(finding: dict[str, Any], platform: Optional[str] = None) -> dict[str, str]:
    """Generates platform-aware deterministic explanations without LLM calls."""
    norm_platform = _normalize_platform(platform or finding.get("platform"))
    cat = finding.get("category", "")
    file_path = finding.get("file") or "the affected file"
    label = finding.get("label") or "this vulnerability"
    table = finding.get("table") or "the affected table"

    # Platform-specific lookup first
    platform_map = _PLATFORM_EXPLANATIONS.get(norm_platform, {})
    template = platform_map.get(cat) or _GENERIC_TEMPLATES.get(cat, _DEFAULT)

    what_tmpl, why_tmpl = template
    return {
        "what_it_means": what_tmpl.format(file=file_path, label=label, table=table),
        "why_it_matters": why_tmpl.format(file=file_path, label=label, table=table),
    }


def explain(finding: dict, platform: Optional[str] = None) -> dict:
    """Uses Gemini to generate plain-language explanations tailored to the specific finding.

    Grounding & Anti-Hallucination:
    - Injects curated, vetted official security documentation (OWASP, Supabase RLS, platform guides).
    - Constrains generation via strict evidence grounding directives.
    - Validates output and rejects any LLM response inventing files/lines/tables not in finding.
    - Cascades through models and falls back to platform-aware deterministic templates.
    """
    effective_platform = platform or finding.get("platform", "generic")
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logger.debug("GEMINI_API_KEY not set; using fallback explainer.")
        return _fallback_explain(finding, effective_platform)

    # Names, paths and secrets are masked before anything leaves this process (see agents/privacy.py).
    masker = Masker()
    safe_finding = masker.mask_finding(finding)
    # Retrieve curated reference documentation for grounding.
    curated_context = get_curated_doc(finding.get("category", ""), effective_platform)
    prompt = f"""You are a cybersecurity expert explaining vulnerabilities to a non-expert developer.
Analyze the following security finding and explain it clearly in plain English.
{PLACEHOLDER_NOTE}

Finding details:
{json.dumps(safe_finding, indent=2)}

OFFICIAL VETTED SECURITY KNOWLEDGE:
{curated_context}

{EVIDENCE_STRICT_DIRECTIVE}

Respond with a valid JSON object containing exactly these two keys:
- "what_it_means": A simple 1-2 sentence explanation of what this vulnerability is in plain terms, referencing ONLY the provided evidence.
- "why_it_matters": A simple 1-2 sentence explanation of the real-world risk or impact to the app/users on {effective_platform}.

Return ONLY the raw JSON object, without markdown formatting or code blocks.
"""
    unresolved_placeholder = False
    unresolved_attempts = 0

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        for model in gemini_models.usable_models():
            try:
                config = types.GenerateContentConfig(
                    response_mime_type="application/json",
                )
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=config,
                )
                text = (response.text or "").strip()
                if text.startswith("```"):
                    lines = text.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    text = "\n".join(lines).strip()

                parsed = json.loads(text)
                if isinstance(parsed, dict) and "what_it_means" in parsed and "why_it_matters" in parsed:
                    what = str(parsed["what_it_means"]).strip()
                    why = str(parsed["why_it_matters"]).strip()
                    if masker.unresolved(what) or masker.unresolved(why):
                        logger.warning("Model %s used a placeholder we cannot resolve; ignoring its answer", model)
                        unresolved_placeholder = True
                        unresolved_attempts += 1
                        if unresolved_attempts >= 2:
                            break
                        continue

                    # Validate the model response against the original, unmasked evidence.
                    validation_finding = {
                        **safe_finding,
                        "_original_file": finding.get("file", ""),
                        "_original_table": finding.get("table", ""),
                    }
                    valid_what, reason_what = validate_evidence_grounding(what, validation_finding, effective_platform)
                    valid_why, reason_why = validate_evidence_grounding(why, validation_finding, effective_platform)

                    if not valid_what or not valid_why:
                        logger.warning(
                            "Model %s produced ungrounded output (%s / %s); falling back to deterministic template.",
                            model,
                            reason_what,
                            reason_why,
                        )
                        continue

                    gemini_models.report_success(model)
                    logger.info("Gemini explanation succeeded with model %s", model)
                    return {
                        "what_it_means": masker.restore(what),
                        "why_it_matters": masker.restore(why),
                    }
                logger.warning("Model %s returned JSON missing expected keys: %s", model, text)
            except Exception as model_err:
                gemini_models.report_failure(model, model_err)
                logger.warning("Error explaining finding with model %s: %s", model, model_err)
                continue
    except Exception as err:
        logger.warning("Failed to initialize or execute Gemini client for explainer: %s", err)

    if unresolved_placeholder and finding.get("category") == "hardcoded_secret":
        fallback = _fallback_explain(finding, effective_platform)
        fallback["what_it_means"] = "A secret or API key is hardcoded directly in your code."
        return fallback
    return _fallback_explain(finding, effective_platform)

"""Fix-Prompt Agent (Gemini-based).

CONTRACT — do not change without telling the team:
  input:  one finding dict (post-explain), plus a platform string
  output: a single string — the fix prompt
"""

import json
import logging
import os
from typing import Any

from agents.privacy import PLACEHOLDER_NOTE, Masker

logger = logging.getLogger(__name__)

MODELS = ("gemini-3.8-flash", "gemini-3.6-flash")

_GENERIC_FIXES = {
    "hardcoded_secret": "Move the secret found in {file} out of the code and into an environment variable or your platform's secrets manager, then remove it from the source file.",
    "static_analysis": "Review and fix the issue flagged in {file}: {label}.",
    "missing_access_control": "Enable Row Level Security on the affected table and add an access control policy restricting access to authorized users.",
    "exposed_file": "Update your hosting/deploy configuration so {file} is not publicly served.",
    "missing_header": "Add the {label} response header to your app's server configuration.",
    "cors_misconfig": "Restrict CORS to your app's actual domain instead of allowing all origins (*).",
    "scan_incomplete": "Re-run the scan -- static analysis did not complete last time, so results may be incomplete.",
}

_PLATFORM_FIXES = {
    "lovable_supabase": {
        "missing_access_control": "In your Supabase migration for table '{table}', add: ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; and define policies restricting row operations using auth.uid().",
        "hardcoded_secret": "Remove the secret in {file}. In Supabase/Lovable, configure this secret in Supabase Project Settings > Vault/Config or your project environment variables, referencing it on the backend without exposing it to the client.",
        "exposed_file": "Ensure {file} is added to .gitignore and configure your deploy static hosting to prevent serving configuration files publicly.",
        "cors_misconfig": "Restrict Supabase client and edge function CORS configurations to your production domain rather than allowing '*'.",
        "static_analysis": "Review and resolve the code quality or security issue flagged in {file}: {label}.",
        "missing_header": "Configure custom headers in your Supabase edge functions or hosting configuration to include {label}.",
    },
    "replit": {
        "missing_access_control": "Add authentication checks and access control validation before processing operations for table '{table}'.",
        "hardcoded_secret": "Remove the hardcoded secret from {file}. In Replit, open the Secrets pane (Tools > Secrets) and add this key-value pair, then access it using standard environment variable lookups (e.g. process.env or os.environ).",
        "exposed_file": "Remove {file} from public serving. Ensure hidden/configuration files are not placed in public folders or exposed via the Replit webview.",
        "cors_misconfig": "Update your server configuration in Replit to restrict CORS origins to your Replit deployment domain.",
        "static_analysis": "Review and resolve the code quality or security issue flagged in {file}: {label}.",
        "missing_header": "Add the {label} response header in your Replit server configuration.",
    },
    "bolt_v0": {
        "hardcoded_secret": "Move the secret in {file} to your .env.local file. Note that secrets should not use NEXT_PUBLIC_ or VITE_ prefixes unless they are strictly public keys intended for client-side consumption.",
        "missing_access_control": "Protect server actions or API endpoints touching {table} with session verification and restrict database access control.",
        "exposed_file": "Ensure {file} is added to .gitignore and not bundled in public static assets.",
        "cors_misconfig": "Update your Next.js or Vite server/route middleware CORS configuration to allow only your production origin.",
        "static_analysis": "Review and resolve the code quality or security issue flagged in {file}: {label}.",
        "missing_header": "Add the {label} response header to your Next.js headers config or Vite server response headers.",
    },
}

_DEFAULT = "Investigate and fix: {label} in {file}."


def _normalize_platform(platform: str) -> str:
    p = platform.lower()
    if "supabase" in p or "lovable" in p:
        return "lovable_supabase"
    if "replit" in p:
        return "replit"
    if "bolt" in p or "v0" in p:
        return "bolt_v0"
    return "generic"


def _fallback_fix_prompt(finding: dict[str, Any], platform: str) -> str:
    norm_platform = _normalize_platform(platform)
    category = finding.get("category", "")
    table = finding.get("table", "the affected table")
    file_path = finding.get("file", "the affected file")
    label = finding.get("label", "this issue")

    platform_templates = _PLATFORM_FIXES.get(norm_platform, {})
    template = platform_templates.get(category) or _GENERIC_FIXES.get(category, _DEFAULT)

    return template.format(
        file=file_path,
        label=label,
        table=table,
    )


def generate_fix_prompt(finding: dict, platform: str) -> str:
    """Uses Gemini to generate a tailored fix prompt based on the finding and target platform.
    Cascades through models (gemini-3.8-flash -> gemini-3.6-flash) and falls back to
    platform-aware deterministic templates if LLM calls fail or API key is absent.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logger.debug("GEMINI_API_KEY not set; using fallback fix prompt.")
        return _fallback_fix_prompt(finding, platform)

    # Names, paths and secrets are masked before anything leaves this process (see agents/privacy.py).
    masker = Masker()
    prompt = f"""You are an AI coding assistant prompt engineer.
Create an actionable, ready-to-use prompt that a developer can feed to their vibe-coding AI assistant (like Lovable, Bolt, v0, Cursor, Replit, or Copilot) to automatically fix this security issue.

Target platform: {platform}
{PLACEHOLDER_NOTE}
Security finding:
{json.dumps(masker.mask_finding(finding), indent=2)}

Platform conventions to respect:
- If platform is 'lovable' or 'supabase': reference Supabase Row-Level Security (RLS) SQL policies, Supabase client auth context (auth.uid()), or Supabase secrets where applicable.
- If platform is 'replit': reference Replit Secrets manager instead of .env files.
- If platform is 'bolt' or 'v0': reference Vite/Next.js environment variables (e.g., NEXT_PUBLIC_ vs server-only secrets).
- Otherwise: provide a clean, direct instruction targeting the affected file and pattern.

Output requirement:
Return ONLY the prompt string to give to the vibe-coding tool. Do not wrap in markdown quotes or extra conversational text.
"""

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        for model in MODELS:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                )
                text = (response.text or "").strip()
                if text:
                    if masker.unresolved(text):
                        logger.warning("Model %s used a placeholder we cannot resolve; ignoring its answer", model)
                        continue
                    return masker.restore(text)
            except Exception as model_err:
                logger.warning("Error generating fix prompt with model %s: %s", model, model_err)
                continue
    except Exception as err:
        logger.warning("Failed to initialize or execute Gemini client for fix prompt: %s", err)

    return _fallback_fix_prompt(finding, platform)

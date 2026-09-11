"""Fix-Prompt Agent (Gemini-based).

CONTRACT — do not change without telling the team:
  input:  one finding dict (post-explain), plus a platform string
  output: a single string — the fix prompt
"""

import json
import os
from typing import Any

_GENERIC_FIXES = {
    "hardcoded_secret": "Move the secret found in {file} out of the code and into an environment variable or your platform's secrets manager, then remove it from the source file.",
    "static_analysis": "Review and fix the issue flagged in {file}: {label}.",
    "missing_access_control": "Enable Row Level Security on the affected table and add a policy restricting access to the record's owner.",
    "exposed_file": "Update your hosting/deploy configuration so {file} is not publicly served.",
    "missing_header": "Add the {label} response header to your app's server configuration.",
    "cors_misconfig": "Restrict CORS to your app's actual domain instead of allowing all origins (*).",
}

_DEFAULT = "Investigate and fix: {label} in {file}."


def _fallback_fix_prompt(finding: dict[str, Any], platform: str) -> str:
    template = _GENERIC_FIXES.get(finding.get("category", ""), _DEFAULT)
    return template.format(
        file=finding.get("file", "the affected file"),
        label=finding.get("label", "this issue"),
    )


def generate_fix_prompt(finding: dict, platform: str) -> str:
    """Uses Gemini to generate a tailored fix prompt based on the finding and target platform.
    Examples of platform-specific conventions:
    - Lovable/Supabase: RLS policies, supabase secrets/vault, client-side safety
    - Replit: Replit Secrets pane, replit configuration
    - Bolt/v0: Next.js/Vite environment variable conventions
    - generic: standard environment variables and remediation patterns
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return _fallback_fix_prompt(finding, platform)

    prompt = f"""You are an AI coding assistant prompt engineer.
Create an actionable, ready-to-use prompt that a developer can feed to their vibe-coding AI assistant (like Lovable, Bolt, v0, Cursor, Replit, or Copilot) to automatically fix this security issue.

Target platform: {platform}
Security finding:
{json.dumps(finding, indent=2)}

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
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        text = response.text.strip()
        if text:
            return text
    except Exception:
        pass

    return _fallback_fix_prompt(finding, platform)

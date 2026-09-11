"""STUB — placeholder for Ali's real Fix-Prompt Agent (Gemini-based).

CONTRACT — do not change without telling the team:
  input:  one finding dict (post-explain), plus a platform string
  output: a single string — the fix prompt

Ali's real version should tailor wording per platform (Lovable/
Supabase RLS syntax vs. Replit Secrets vs. generic). This stub does
not, on purpose — that platform-specific knowledge is his task.
"""

_GENERIC_FIXES = {
    "hardcoded_secret": "Move the secret found in {file} out of the code and into an environment variable or your platform's secrets manager, then remove it from the source file.",
    "static_analysis": "Review and fix the issue flagged in {file}: {label}.",
    "missing_access_control": "Enable Row Level Security on the affected table and add a policy restricting access to the record's owner.",
    "exposed_file": "Update your hosting/deploy configuration so {file} is not publicly served.",
    "missing_header": "Add the {label} response header to your app's server configuration.",
    "cors_misconfig": "Restrict CORS to your app's actual domain instead of allowing all origins (*).",
}

_DEFAULT = "Investigate and fix: {label} in {file}."


def generate_fix_prompt(finding: dict, platform: str) -> str:
    """STUB: templated, platform-agnostic fix instruction. Replace with
    a real Gemini call that tailors wording to `platform` — keep the
    return type (a single string)."""
    template = _GENERIC_FIXES.get(finding.get("category"), _DEFAULT)
    return template.format(
        file=finding.get("file", "the affected file"),
        label=finding.get("label", "this issue"),
    )

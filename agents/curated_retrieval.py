"""Curated Documentation Retrieval for Anti-Hallucination Grounding.

Grounds agent prompts in official, vetted security standards (OWASP, Supabase RLS,
platform security specifications) rather than open internet browsing.

Security Rationale:
Open internet browsing exposes LLM agents to prompt injection, outdated recommendations,
and malicious third-party content. A curated, version-controlled local documentation
set delivers strict factual grounding with zero network/injection risk.
"""

from pathlib import Path
from typing import Optional

_KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"


def _read_doc(filename: str) -> str:
    path = _KNOWLEDGE_DIR / filename
    if path.is_file():
        try:
            return path.read_text(encoding="utf-8")
        except Exception:
            return ""
    return ""


def get_curated_doc(category: str, platform: Optional[str] = None) -> str:
    """Retrieves relevant vetted reference documentation for a vulnerability category and platform.

    Args:
        category: Vulnerability category (e.g. 'missing_access_control', 'hardcoded_secret',
                  'cors_misconfig', 'exposed_file', 'missing_header').
        platform: Detected platform (e.g. 'lovable_supabase', 'bolt_v0', 'replit', 'generic').

    Returns:
        Curated markdown excerpt containing official remediation and security context.
    """
    cat = (category or "").lower()
    plat = (platform or "").lower()

    docs = []

    # Platform-specific guidance
    if "supabase" in plat or "lovable" in plat or cat == "missing_access_control":
        supabase_doc = _read_doc("supabase_rls.md")
        if supabase_doc:
            docs.append(supabase_doc)

    if "replit" in plat:
        replit_doc = _read_doc("replit_security.md")
        if replit_doc:
            docs.append(replit_doc)

    if "bolt" in plat or "v0" in plat:
        bolt_doc = _read_doc("bolt_v0_security.md")
        if bolt_doc:
            docs.append(bolt_doc)

    # Category-specific guidance
    if cat in ("missing_header", "exposed_file", "cors_misconfig"):
        headers_doc = _read_doc("security_headers.md")
        if headers_doc:
            docs.append(headers_doc)

    # General OWASP standards
    owasp_doc = _read_doc("owasp_top_10.md")
    if owasp_doc:
        docs.append(owasp_doc)

    if not docs:
        return "Refer to standard secure coding practices and official platform security documentation."

    # Return unified curated guidance
    return "\n\n---\n\n".join(docs)


def get_available_topics() -> list[str]:
    """Lists all available vetted documentation topics in the knowledge store."""
    if not _KNOWLEDGE_DIR.is_dir():
        return []
    return [f.stem for f in _KNOWLEDGE_DIR.glob("*.md")]

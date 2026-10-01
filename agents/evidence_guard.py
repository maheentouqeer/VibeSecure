"""Evidence-Strict Prompting and Output Validation for Anti-Hallucination Grounding.

Grounding Initiative:
Constrains Explainer and Fix-Prompt agents to reference ONLY the exact file,
line, and table present in the finding dictionary. Validates those structured
references and rejects/flags anything not grounded in the given evidence.
Direct fix for LLM-invented specifics without requiring internet access.
"""

import logging
import re
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# Standard platform config files that may legitimately be referenced in remediation instructions
_ALLOWED_PLATFORM_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    ".gitignore",
    "package.json",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "vite.config.js",
    "vite.config.ts",
    "replit.nix",
    ".replit",
    "schema.sql",
    "supabase/migrations",
    "vercel.json",
    "netlify.toml",
    "middleware.ts",
}

# Regex to detect file-like references (e.g., path/to/file.ts, server.js, config/aws.ts, .env.local)
_FILE_PATH_PATTERN = re.compile(
    r"(?:[\w.-]+/)*[\w.-]+\.(?:ts|tsx|js|jsx|py|sql|html|css|json|yaml|yml|env|local|sh|toml)\b|(?:\.env\b)",
    re.IGNORECASE,
)

# Regex to detect specific line number claims (e.g., "line 42", "on line 15", "at line 88")
_LINE_NUMBER_PATTERN = re.compile(r"\bline\s+(\d+)\b", re.IGNORECASE)


EVIDENCE_STRICT_DIRECTIVE = """
STRICT EVIDENCE GROUNDING RULES (ANTI-HALLUCINATION ENFORCEMENT):
1. You may ONLY reference the exact file, line, and table present in the finding evidence.
2. Under NO circumstances should you invent, assume, or fabricate filenames, directory structures, function names, database tables, or line numbers that do not appear in the finding details.
3. If a detail (such as a line number or table) is missing from the finding, speak generally about 'the affected file' or 'the identified code' rather than guessing or fabricating specifics.
4. Any response that mentions files or specifics not present in the evidence will fail automated grounding validation and be rejected.
"""


def extract_mentioned_files(text: str) -> set[str]:
    """Finds all file paths and filenames referenced in the text."""
    matches = set(_FILE_PATH_PATTERN.findall(text))
    # Filter out common non-file extensions/tokens if matched
    clean = set()
    for m in matches:
        m_lower = m.lower().strip("`'\"(),;: \t\n")
        if m_lower.endswith("."):
            m_lower = m_lower[:-1]
        if m_lower.endswith(".com") or m_lower.endswith(".org") or m_lower.endswith(".net") or m_lower.endswith(".io") or m_lower.endswith(".dev"):
            continue  # URL / domain
        if m_lower in ("next.js", "node.js", "react.js", "vue.js", "nuxt.js", "express.js"):
            continue  # Framework names
        if m_lower:
            clean.add(m_lower)
    return clean


def extract_mentioned_lines(text: str) -> list[int]:
    """Extracts line numbers referenced as 'line <number>'."""
    return [int(num) for num in _LINE_NUMBER_PATTERN.findall(text)]


def validate_evidence_grounding(
    output_text: str,
    finding: dict[str, Any],
    platform: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Validates that output references ONLY details present in finding evidence.

    Returns:
        (True, None) if grounded.
        (False, reason_string) if hallucinated details are detected.
    """
    if not output_text:
        return False, "Output is empty"

    evidence_files = [finding.get("file", ""), finding.get("_original_file", "")]
    normalized_files = [str(value).lower().strip(" <>`'\"") for value in evidence_files if value]
    finding_file = normalized_files[0] if normalized_files else ""
    finding_file_base = finding_file.split("/")[-1] if finding_file else ""
    evidence_bases = {value.split("/")[-1] for value in normalized_files}

    # 1. File path validation
    mentioned_files = extract_mentioned_files(output_text)
    for f in mentioned_files:
        f_base = f.split("/")[-1]

        # Check if matches finding file or basename
        if normalized_files and (
            f in normalized_files
            or f_base in evidence_bases
            or any(value.endswith(f) for value in normalized_files)
        ):
            continue

        if any(value.startswith(("http://", "https://")) for value in normalized_files):
            continue

        # Check if matches an allowed platform configuration file
        if any(allowed in f or f_base == allowed for allowed in _ALLOWED_PLATFORM_FILES):
            continue

        # If it's a specific invented source file, reject
        return False, f"Output hallucinated file '{f}' not present in finding evidence (expected '{finding_file}')"

    # 2. Line number validation
    finding_line = finding.get("line")
    mentioned_lines = extract_mentioned_lines(output_text)
    if mentioned_lines:
        if finding_line is None:
            # Finding has no line number specified, but model invented one
            return False, f"Output hallucinated specific line number {mentioned_lines[0]} not present in finding evidence"
        else:
            try:
                line_int = int(finding_line)
                if any(ml != line_int for ml in mentioned_lines):
                    return False, f"Output claimed line {mentioned_lines[0]} which diverges from evidence line {line_int}"
            except (ValueError, TypeError):
                pass

    # 3. Database Table validation. Free-form remediation syntax is not
    # treated as evidence; file, line, and table references remain strict.
    finding_tables = {
        str(value).lower().strip(" <>`'\"")
        for value in (finding.get("table", ""), finding.get("_original_table", ""))
        if value
    }
    if finding_tables and finding.get("category") == "missing_access_control":
        # Check if model hallucinated a different specific table name by inspecting table references
        table_refs = re.findall(r"\btable\s+['\"`]?([a-zA-Z0-9_]+)['\"`]?", output_text, re.IGNORECASE)
        for tr in table_refs:
            tr_lower = tr.lower()
            if tr_lower not in finding_tables | {"the", "affected", "each", "this", "target"}:
                return False, f"Output referenced table '{tr}' but evidence specified table '{next(iter(finding_tables), '')}'"

    return True, None


def enforce_grounding_or_fallback(
    output_text: str,
    finding: dict[str, Any],
    fallback_value: Any,
    agent_name: str = "Agent",
) -> Any:
    """Enforces evidence validation; falls back to deterministic template if hallucination detected."""
    is_valid, reason = validate_evidence_grounding(output_text, finding)
    if not is_valid:
        logger.warning(
            "[%s] Grounding check failed: %s. Falling back to deterministic template.",
            agent_name,
            reason,
        )
        return fallback_value
    return output_text

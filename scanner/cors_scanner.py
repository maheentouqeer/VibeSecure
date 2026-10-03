"""Static source-level checks for unsafe wildcard CORS configuration."""

import re
from pathlib import Path

SOURCE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# Match the common Express/Koa-style cors({ origin: "*" }) form without
# treating ordinary origin strings elsewhere in a repo as vulnerabilities.
_CORS_CALL_PATTERN = re.compile(
    r"""\bcors\s*\(\s*\{(?:(?!\}\s*\)).){0,800}?\borigin\s*:\s*['"]\*['"]""",
    re.IGNORECASE | re.DOTALL,
)

# Also catch direct response/header configuration such as:
# res.setHeader("Access-Control-Allow-Origin", "*")
_HEADER_PATTERN = re.compile(
    r"""Access-Control-Allow-Origin['"]?\s*[,=:]\s*['"]\*['"]""",
    re.IGNORECASE,
)


def _finding(repo_path: Path, file: Path, start: int) -> dict:
    line = file.read_text(errors="ignore").count("\n", 0, start) + 1
    return {
        "category": "cors_misconfig",
        "label": "CORS allows any origin (*)",
        "file": file.relative_to(repo_path).as_posix(),
        "line": line,
        "raw_severity": "high",
    }


def check_static_cors(repo_path: Path) -> list[dict]:
    """Detect explicit wildcard CORS in application source files."""
    findings: list[dict] = []

    for file in repo_path.rglob("*"):
        if not file.is_file() or file.suffix.lower() not in SOURCE_EXTS:
            continue
        if any(part in {".git", "node_modules", "dist", "build", ".next"} for part in file.parts):
            continue

        try:
            text = file.read_text(errors="ignore")
        except Exception:
            continue

        match = _CORS_CALL_PATTERN.search(text)
        if match:
            findings.append(_finding(repo_path, file, match.start()))
            continue

        match = _HEADER_PATTERN.search(text)
        if match:
            findings.append(_finding(repo_path, file, match.start()))

    return findings

"""Conservative hardening checks for common AI-generated web-app mistakes.

These are small, high-signal additions to complement Semgrep rather than
replace it. Every finding includes the exact file and line so downstream
agents can stay evidence-grounded.
"""
from pathlib import Path
import re


SOURCE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".php"}


_PATTERNS = (
    (
        "xss_risk",
        "Potential unsafe HTML injection",
        re.compile(r"\bdangerouslySetInnerHTML\s*=", re.IGNORECASE),
        "high",
        "Untrusted HTML is inserted directly into the rendered page.",
    ),
    (
        "sql_injection",
        "Potential SQL string interpolation",
        re.compile(r"""(?:query|execute|executemany)\s*\(\s*(?:f["']|`[^`]*\$\{|\w+\s*\+|["'][^"']*["']\s*\+)""", re.IGNORECASE),
        "high",
        "A database operation appears to build SQL from interpolated or concatenated strings.",
    ),
    (
        "weak_password_hash",
        "Weak password hashing primitive",
        re.compile(r"""(?:password|passwd|pwd)[\w\s.-]{0,40}=\s*(?:hashlib\.(?:md5|sha1)|md5\s*\(|sha1\s*\()""", re.IGNORECASE),
        "high",
        "A password-related value appears to rely on a weak general-purpose hash.",
    ),
    (
        "public_secret_env",
        "Potential secret exposed through public environment variable",
        re.compile(r"""(?:NEXT_PUBLIC|VITE)_[A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE_KEY|PASSWORD|SERVICE_ROLE|ADMIN_KEY)[A-Z0-9_]*""", re.IGNORECASE),
        "critical",
        "A client-exposed environment variable name suggests a credential that should remain server-side.",
    ),
)


def _line(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def scan_hardening(repo_path: Path) -> list[dict]:
    findings: list[dict] = []
    for file in repo_path.rglob("*"):
        if not file.is_file() or file.suffix.lower() not in SOURCE_EXTS:
            continue
        if any(part in {".git", "node_modules", "dist", "build", ".next", "__pycache__"} for part in file.parts):
            continue
        try:
            text = file.read_text(errors="ignore")
        except Exception:
            continue

        for category, label, pattern, severity, message in _PATTERNS:
            for match in pattern.finditer(text):
                findings.append(
                    {
                        "category": category,
                        "label": label,
                        "file": file.relative_to(repo_path).as_posix(),
                        "line": _line(text, match.start()),
                        "message": message,
                        "raw_severity": severity,
                    }
                )
    return findings

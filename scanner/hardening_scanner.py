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

    (
        "client_side_authorization",
        "Client-side authorization decision may be trusted",
        re.compile(r"""(?:user_roles|isAdmin|is_admin|hasRole|has_role|permissions)""", re.IGNORECASE),
        "high",
        "A client-side role or permission check appears to gate access; authorization must also be enforced server-side.",
    ),
    (
        "csrf_disabled",
        "CSRF protection explicitly disabled",
        re.compile(r"""@csrf_exempt\b|\bcsrf_exempt\s*\(|\b(?:WTF_CSRF_ENABLED|CSRF_ENABLED|CSRF_PROTECTION_ENABLED)\s*=\s*(?:false|0|off)\b|\bcsrf[_ -]?protection\s*(?:[:=]|is)\s*(?:false|disabled|off)\b""", re.IGNORECASE),
        "high",
        "The code explicitly disables or exempts a CSRF protection mechanism.",
    ),
    (
        "insecure_cookie_config",
        "Insecure authentication cookie configuration",
        re.compile(r"""(?:set_cookie|setcookie|cookies?\.(?:set|append))\s*\([^\n]{0,700}\b(?:secure|httponly)\s*=\s*false\b|(?:set_cookie|setcookie|cookies?\.(?:set|append))\s*\([^\n]{0,700}\bsamesite\s*=\s*['"]none['"]""", re.IGNORECASE),
        "high",
        "A cookie-setting call explicitly disables Secure/HttpOnly or uses SameSite=None, which can weaken an authentication boundary.",
    ),
    (
        "rate_limit_disabled",
        "Rate limiting explicitly disabled",
        re.compile(r"""\b(?:RATE_LIMIT|RATELIMIT|RATE_LIMITING|RATELIMIT_ENABLED|RATE_LIMIT_ENABLED)\b\s*(?:[:=]|is)\s*(?:false|0|off|disabled)\b|\bskip[_ -]?rate[_ -]?limit\b""", re.IGNORECASE),
        "medium",
        "The code explicitly disables or bypasses rate limiting, leaving sensitive actions more exposed to automated abuse.",
    ),
    (
        "security_logging_disabled",
        "Security logging explicitly disabled",
        re.compile(r"""\blogging\.disable\s*\(|\blogger\.disabled\s*=\s*(?:true|1)\b|\b(?:SECURITY|AUDIT)_LOG(?:GING)?_ENABLED\b\s*(?:[:=]|is)\s*(?:false|0|off|disabled)\b|\bdisable[_ -]?security[_ -]?logging\b""", re.IGNORECASE),
        "medium",
        "Security or audit logging is explicitly disabled, reducing visibility into authentication and high-risk events.",
    ),
    (
        "unsafe_file_upload",
        "File upload lacks visible type/size validation",
        re.compile(r"""(?:\.storage|\.bucket)\.from\([^\n]{0,240}\)\.upload\s*\(""", re.IGNORECASE),
        "high",
        "A storage upload call was found without nearby evidence of file type and size validation.",
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
                if category == "client_side_authorization":
                    # Require a stronger signal than a generic "permission" string:
                    # role data is being read in the client, or an admin/role gate is named.
                    window = text[max(0, match.start() - 900): min(len(text), match.end() + 900)].lower()
                    if "user_roles" not in window and not re.search(r"\bis[_-]?admin\b|\bhas[_-]?role\b", window):
                        continue
                if category == "unsafe_file_upload":
                    window = text[max(0, match.start() - 1200): min(len(text), match.end() + 900)]
                    # A visible type OR size check is enough to avoid this
                    # conservative finding; stronger validation can be added later.
                    if re.search(r"file\.type|file\.size|allowedTypes|maxSize|sizeLimit", window, re.IGNORECASE):
                        continue
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

    package_json = repo_path / "package.json"
    if package_json.is_file():
        lockfiles = (
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lock",
            "bun.lockb",
        )
        if not any((repo_path / lockfile).is_file() for lockfile in lockfiles):
            findings.append(
                {
                    "category": "missing_dependency_lockfile",
                    "label": "Dependency manifest has no lockfile",
                    "file": "package.json",
                    "line": 1,
                    "message": "A package manifest is present, but no recognized dependency lockfile was found.",
                    "raw_severity": "medium",
                }
            )

    return findings

"""Lightweight hardcoded-secret detector with regex and entropy scoring.

Zero external dependencies so it always works at a hackathon demo, even
offline. Swap this out for Gitleaks (`gitleaks detect --source=<path>
--report-format json`) once you have time -- it has a much bigger,
maintained rule set. Keep this as the guaranteed fallback.
"""
import math
import re
import hashlib
from pathlib import Path

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret Key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "GitHub Token": r"ghp_[0-9A-Za-z]{36}",
    "Generic Bearer Secret": r"(?i)(?:api_key|apikey|secret|token)\s*[:=]\s*['\"][0-9A-Za-z\-_]{20,}(?=['\"]|\s|$)",
}

SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", ".next"}

# Lockfiles and minified bundles are wall-to-wall integrity hashes that look
# exactly like high-entropy secrets; they are never where a human put a secret.
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "npm-shrinkwrap.json", "composer.lock", "poetry.lock",
}
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".lock")

# Strings that are hashes/checksums/ids, not credentials.
_HASH_PREFIXES = ("sha1-", "sha256-", "sha384-", "sha512-", "md5-")
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]{32,}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _looks_like_hash_or_id(candidate: str) -> bool:
    return (
        candidate.lower().startswith(_HASH_PREFIXES)
        or bool(_HEX_ONLY.match(candidate))
        or bool(_UUID.match(candidate))
    )


TEXT_EXTS = {".js", ".ts", ".tsx", ".jsx", ".py", ".env", ".json", ".yml", ".yaml", ".md", ".txt"}

# Candidate string match for entropy analysis (e.g., quotes or assignments).
# Deliberately broad -- excludes only the quote character itself and
# whitespace, so symbol-heavy secrets (which are often the highest-entropy,
# most "secure-looking" ones) aren't invisible to this check.
POTENTIAL_SECRET_STR_RE = re.compile(r"""['"]([^'"\s]{16,128})['"]""")


_SECRET_CONTEXT_RE = re.compile(
   r"(?i)\\b(?:secret|token|api[_-]?key|password|passwd|credential|authorization|auth[_-]?token)\\b"
)
_PUBLIC_CONFIG_RE = re.compile(
   r"(?i)\\b(?:VITE|NEXT_PUBLIC|PUBLIC)[A-Z0-9_]*(?:SUPABASE|FIREBASE|CLIENT|PUBLISHABLE|ANON|PUBLIC)[A-Z0-9_]*\\b"
)

def _is_public_config_line(line: str) -> bool:
   return bool(_PUBLIC_CONFIG_RE.search(line))


def _is_secret_context_line(line: str) -> bool:
   return bool(_SECRET_CONTEXT_RE.search(line))

def _masked_snippet(text: str, start: int, end: int) -> tuple[int, str]:
    """Return the finding line and a small source excerpt with the secret removed."""
    line_number = text.count("\n", 0, start) + 1
    lines = text.splitlines()
    first = line_number - 1
    last = line_number
    excerpt = lines[first:last]
    offset = line_number - first - 1
    if 0 <= offset < len(excerpt):
        line = excerpt[offset]
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", start)
        if line_end < 0:
            line_end = len(text)
        local_start = max(0, start - line_start)
        local_end = min(len(line), end - line_start)
        redacted_line = line[:local_start] + "[secret redacted]" + line[local_end:]
        redacted_line = re.sub(
            r"(['\"`])(?:(?!\1).)*\1",
            lambda match: f"{match.group(1)}[secret redacted]{match.group(1)}",
            redacted_line,
        )
        excerpt[offset] = re.sub(
            r"(\b[A-Z][A-Z0-9_]*\s*=\s*)(?!['\"`\[])([^\s,;}\]]+)",
            r"\1[secret redacted]",
            redacted_line,
        )
        excerpt[offset] = re.sub(
            r"(\b[A-Za-z_][A-Za-z0-9_-]*\s*:\s*)(?!['\"`\[])([^\s,;}\]]+)",
            r"\1[secret redacted]",
            excerpt[offset],
        )
    return line_number, "\n".join(excerpt)


def shannon_entropy(data: str) -> float:
    """Calculate Shannon Entropy (bits per character) of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char_code in set(data):
        prob = data.count(char_code) / length
        entropy -= prob * math.log2(prob)
    return entropy


def scan_secrets(repo_path: Path) -> list[dict]:
    findings = []
    for file in repo_path.rglob("*"):
        if not file.is_file():
            continue
        if any(part in SKIP_DIRS for part in file.parts):
            continue
        if file.suffix not in TEXT_EXTS and file.name != ".env":
            continue
        if file.name in SKIP_FILES or file.name.endswith(SKIP_SUFFIXES):
            continue
        try:
            text = file.read_text(errors="ignore")
        except Exception:
            continue

        matched_spans = set()

        # 1. Pattern matching (ordered from specific provider keys to generic bearer tokens)
        for label, pattern in PATTERNS.items():
            for match in re.finditer(pattern, text):
                span = (match.start(), match.end())
                # Avoid duplicate / overlapping regex match spans for the same token
                if any(max(span[0], m_start) < min(span[1], m_end) for m_start, m_end in matched_spans):
                    continue
                matched_spans.add(span)
                line, snippet = _masked_snippet(text, match.start(), match.end())
                findings.append({
                    "category": "hardcoded_secret",
                    "label": label,
                    "file": file.relative_to(repo_path).as_posix(),
                    "match_preview": match.group(0)[:6] + "...(masked)",
                    "line": line,
                    "snippet": snippet,
                    "_match_hash": hashlib.sha256(match.group(0).encode()).hexdigest(),
                    "raw_severity": "critical",
                })

        # 2. Entropy scoring for non-pattern matched high-entropy strings.
        # Require either very high entropy or clear secret-ish context. This
        # removes most frontend/public/config false positives while still
        # catching arbitrary high-entropy credentials.
        for match in POTENTIAL_SECRET_STR_RE.finditer(text):
            span = match.span(1)
            if any(m_start <= span[0] and span[1] <= m_end for m_start, m_end in matched_spans):
                continue

            candidate = match.group(1)
            if any(candidate.lower().startswith(p) for p in ["example", "placeholder", "your_", "xxxx"]):
                continue
            if _looks_like_hash_or_id(candidate):
                continue

            line_start = text.rfind("\\n", 0, match.start()) + 1
            line_end = text.find("\\n", match.start())
            if line_end < 0:
                line_end = len(text)
            context_line = text[line_start:line_end]

            # Public client/publishable configuration is intentionally exposed
            # to browsers and should not be treated as a leaked secret.
            if _is_public_config_line(context_line):
                continue

            entropy = shannon_entropy(candidate)
            if entropy >= 4.8 or (entropy >= 4.5 and _is_secret_context_line(context_line)):
                matched_spans.add(span)
                line, snippet = _masked_snippet(text, match.start(), match.end())
                findings.append({
                    "category": "hardcoded_secret",
                    "label": f"High Entropy Secret (entropy: {entropy:.2f})",
                    "file": file.relative_to(repo_path).as_posix(),
                    "match_preview": candidate[:6] + "...(masked)",
                    "line": line,
                    "snippet": snippet,
                    "_match_hash": hashlib.sha256(candidate.encode()).hexdigest(),
                    "raw_severity": "high",
                })
    unique_findings = []
    seen = set()
    for finding in findings:
        key = (finding.get("category"), finding.get("file"), finding.get("_match_hash"))
        if key in seen:
            continue
        seen.add(key)
        finding.pop("_match_hash", None)
        unique_findings.append(finding)
    return unique_findings

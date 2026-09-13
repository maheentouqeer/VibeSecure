"""Lightweight hardcoded-secret detector with regex and entropy scoring.

Zero external dependencies so it always works at a hackathon demo, even
offline. Swap this out for Gitleaks (`gitleaks detect --source=<path>
--report-format json`) once you have time -- it has a much bigger,
maintained rule set. Keep this as the guaranteed fallback.
"""
import math
import re
from pathlib import Path

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret Key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "GitHub Token": r"ghp_[0-9A-Za-z]{36}",
    "Generic Bearer Secret": r"(?i)(?:api_key|apikey|secret|token)\s*[:=]\s*['\"][0-9A-Za-z\-_]{20,}(?=['\"]|\s|$)",
}

SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", ".next"}
TEXT_EXTS = {".js", ".ts", ".tsx", ".jsx", ".py", ".env", ".json", ".yml", ".yaml", ".md", ".txt"}

# Candidate string match for entropy analysis (e.g., quotes or assignments).
# Deliberately broad -- excludes only the quote character itself and
# whitespace, so symbol-heavy secrets (which are often the highest-entropy,
# most "secure-looking" ones) aren't invisible to this check.
POTENTIAL_SECRET_STR_RE = re.compile(r"""['"]([^'"\s]{16,128})['"]""")


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
        try:
            text = file.read_text(errors="ignore")
        except Exception:
            continue

        matched_spans = set()

        # 1. Pattern matching
        for label, pattern in PATTERNS.items():
            for match in re.finditer(pattern, text):
                matched_spans.add((match.start(), match.end()))
                findings.append({
                    "category": "hardcoded_secret",
                    "label": label,
                    "file": str(file.relative_to(repo_path)),
                    "match_preview": match.group(0)[:6] + "...(masked)",
                    "raw_severity": "critical",
                })

        # 2. Entropy scoring for non-pattern matched high-entropy strings
        for match in POTENTIAL_SECRET_STR_RE.finditer(text):
            span = match.span(1)
            # Avoid duplicate flagging if already covered by regex match
            if any(m_start <= span[0] and span[1] <= m_end for m_start, m_end in matched_spans):
                continue

            candidate = match.group(1)
            # Skip obvious common placeholder/dummy strings
            if any(candidate.lower().startswith(p) for p in ["example", "placeholder", "your_", "xxxx"]):
                continue

            entropy = shannon_entropy(candidate)
            # High entropy threshold for secrets (typically > 4.5 for alphanumeric strings)
            if entropy >= 4.5 and len(candidate) >= 16:
                matched_spans.add(span)
                findings.append({
                    "category": "hardcoded_secret",
                    "label": f"High Entropy Secret (entropy: {entropy:.2f})",
                    "file": str(file.relative_to(repo_path)),
                    "match_preview": candidate[:6] + "...(masked)",
                    "raw_severity": "high",
                })

    return findings

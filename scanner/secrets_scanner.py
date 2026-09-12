"""Lightweight hardcoded-secret detector.

Zero external dependencies so it always works at a hackathon demo, even
offline. Swap this out for Gitleaks (`gitleaks detect --source=<path>
--report-format json`) once you have time -- it has a much bigger,
maintained rule set. Keep this as the guaranteed fallback.
"""
import re
from pathlib import Path

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "GitHub Token": r"ghp_[0-9A-Za-z]{36}",
    "Generic Bearer Secret": r"(?i)(?:api_key|apikey|secret|token)\s*[:=]\s*['\"][0-9A-Za-z\-_]{20,}(?=['\"]|\s|$)",
}

SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", ".next"}
TEXT_EXTS = {".js", ".ts", ".tsx", ".jsx", ".py", ".env", ".json", ".yml", ".yaml", ".md", ".txt"}


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
        for label, pattern in PATTERNS.items():
            for match in re.finditer(pattern, text):
                findings.append({
                    "category": "hardcoded_secret",
                    "label": label,
                    "file": str(file.relative_to(repo_path)),
                    "match_preview": match.group(0)[:6] + "...(masked)",
                    "raw_severity": "critical",
                })
    return findings

"""Guesses which vibe-coding platform/stack a repo was built with.

This is a heuristic fingerprint, not a certainty -- good enough to pick
the right fix-prompt style (Supabase vs. plain Postgres vs. Replit env
vars, etc). Extend the signatures dict as you learn more platform quirks.
"""
import json
from pathlib import Path

SIGNATURES = {
    "lovable_supabase": {
        "files": ["package.json"],
        "contains": ["@supabase/supabase-js", "lovable"],
    },
    "bolt_v0": {
        "files": ["package.json"],
        "contains": ["vite", "@vercel/"],
    },
    "replit": {
        "files": [".replit", "replit.nix"],
        "contains": [],
    },
}


def detect_platform(repo_path: Path) -> str:
    package_json = repo_path / "package.json"
    package_text = ""
    if package_json.exists():
        try:
            package_text = package_json.read_text(errors="ignore").lower()
        except Exception:
            pass

    for platform, sig in SIGNATURES.items():
        file_hit = any((repo_path / f).exists() for f in sig["files"])
        contains_hit = any(term in package_text for term in sig["contains"]) if sig["contains"] else False
        if sig["contains"]:
            if file_hit and contains_hit:
                return platform
        elif file_hit:
            return platform

    return "generic"

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


def is_supabase_project(repo_path: Path) -> bool:
    """True only when the repo shows real evidence of using Supabase --
    a `supabase/` CLI project directory, or `@supabase/supabase-js` as an
    actual dependency in package.json. Used to gate Supabase-specific
    checks (like RLS) so they don't fire on any repo that merely happens
    to contain a `.sql` file with a CREATE TABLE statement."""
    if (repo_path / "supabase").is_dir():
        return True

    package_json = repo_path / "package.json"
    if package_json.exists():
        try:
            package_text = package_json.read_text(errors="ignore").lower()
        except Exception:
            package_text = ""
        if "@supabase/supabase-js" in package_text:
            return True

    return False


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

"""Runs Semgrep's free, pre-built rule packs against the repo.

`p/security-audit` and `p/secrets` cover the bulk of SQL injection,
unsafe deserialization, and additional secret patterns -- you do not
need to write these rules yourself. Requires `pip install semgrep`.
"""
import json
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def _relative_path(path: str, repo_path: Path) -> str:
    """Semgrep reports paths that may not share a prefix with repo_path
    (symlinked temp dirs such as /var vs /private/var on macOS, or Windows
    short names); a plain relative_to() would raise and abort the scan."""
    if not path:
        return ""
    try:
        return Path(path).resolve().relative_to(repo_path.resolve()).as_posix()
    except (ValueError, OSError):
        try:
            return Path(os.path.relpath(path, repo_path)).as_posix()
        except ValueError:
            return path


def run_semgrep(repo_path: Path) -> list[dict]:
    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config=p/security-audit",
                "--config=p/secrets",
                "--json",
                "--quiet",
                str(repo_path),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        data = json.loads(result.stdout or "{}")
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as err:
        # A failed/missing/timed-out Semgrep run must not silently look
        # like "no static-analysis findings" -- that produces different
        # finding counts across identical scans with no explanation.
        # Surface it as a low-severity finding instead of swallowing it.
        logger.warning("Semgrep scan failed or unavailable: %s", err)
        return [{
            "category": "scan_incomplete",
            "label": "Static analysis (Semgrep) did not complete",
            "file": "",
            "message": f"{type(err).__name__}: {err}",
            "raw_severity": "low",
        }]

    findings = []
    for r in data.get("results", []):
        findings.append({
            "category": "static_analysis",
            "label": r.get("check_id", "unknown_rule"),
            "file": _relative_path(r.get("path", ""), repo_path),
            "line": r.get("start", {}).get("line") or 0,
            "message": r.get("extra", {}).get("message", ""),
            "raw_severity": r.get("extra", {}).get("severity", "medium").lower(),
        })
    return findings

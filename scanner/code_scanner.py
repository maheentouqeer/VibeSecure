"""Runs Semgrep's free, pre-built rule packs against the repo.

`p/security-audit` and `p/secrets` cover the bulk of SQL injection,
unsafe deserialization, and additional secret patterns -- you do not
need to write these rules yourself. Requires `pip install semgrep`.
"""
import json
import subprocess
from pathlib import Path


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
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return []

    findings = []
    for r in data.get("results", []):
        findings.append({
            "category": "static_analysis",
            "label": r.get("check_id", "unknown_rule"),
            "file": str(Path(r["path"]).relative_to(repo_path)) if r.get("path") else "",
            "line": r.get("start", {}).get("line"),
            "message": r.get("extra", {}).get("message", ""),
            "raw_severity": r.get("extra", {}).get("severity", "medium").lower(),
        })
    return findings

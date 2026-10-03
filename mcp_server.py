"""VibeSecure MCP server for AI coding environments.

The stdio server is intentionally local-first: it scans the caller's workspace
or an explicitly supplied public target and returns structured, actionable
findings. It never prints to stdout outside the MCP protocol.

Primary tools:
  scan_repository(repo_url)         scan a public Git repository
  scan_local_workspace(path)        scan files already present on disk
  scan_live_url(url)                run passive, read-only HTTP checks
  get_scan_status(scan_id)          inspect a completed local MCP scan
  get_findings(scan_id)             return stored findings for a scan
  rescan(scan_id)                   re-run the same target

Compatibility aliases:
  scan_workspace(path)
  scan_url(target)
  verify_fixes(path, fingerprints)

Remote MCP with per-account API-key authentication is a separate transport
concern and should be added when the SaaS API-key table/metering layer exists.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

import anyio
from mcp.server.fastmcp import FastMCP

from agents.verify_agent import fingerprint
from orchestrator import enrich, run_full_scan, scan_path
from scanner.live_scanner import scan_live_url as scan_live_target
from scanner.url_safety import assert_public_url

mcp = FastMCP("VibeSecure")

MAX_FINDINGS = 50
MAX_STORED_SCANS = 50
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Local process cache. The SaaS backend remains the source of truth for web/API
# scans; this cache gives an MCP client a stable scan_id for the duration of
# its local MCP session and enables get_findings/rescan without another URL.
_SCAN_STORE: dict[str, dict[str, Any]] = {}


def _present(findings: list[dict]) -> dict:
    ordered = sorted(findings, key=lambda f: SEVERITY_RANK.get(f.get("severity"), 4))
    counts = {
        sev: sum(1 for f in findings if f.get("severity") == sev)
        for sev in SEVERITY_RANK
    }
    return {
        "summary": counts,
        "total": len(findings),
        "truncated": len(findings) > MAX_FINDINGS,
        "findings": [
            {
                "fingerprint": fingerprint(f),
                "severity": f.get("severity"),
                "label": f.get("label"),
                "file": f.get("file"),
                "line": f.get("line"),
                "table": f.get("table"),
                "what_it_means": f.get("what_it_means"),
                "why_it_matters": f.get("why_it_matters"),
                "fix_prompt": f.get("fix_prompt"),
                "status": f.get("status", "open"),
            }
            for f in ordered[:MAX_FINDINGS]
        ],
    }


def _resolve_dir(path: str) -> Path:
    folder = Path(path).expanduser().resolve()
    if not folder.is_dir():
        raise ValueError(f"'{path}' is not a directory.")
    return folder


def _remember_scan(
    *,
    target: str,
    target_type: str,
    platform: str,
    findings: list[dict],
    commit: str | None = None,
) -> str:
    scan_id = str(uuid.uuid4())
    _SCAN_STORE[scan_id] = {
        "scan_id": scan_id,
        "target": target,
        "target_type": target_type,
        "platform": platform,
        "findings": findings,
        "commit": commit,
        "status": "completed",
        "created_at": time.time(),
    }

    # Keep the newest local MCP scans only; this is deliberately bounded.
    while len(_SCAN_STORE) > MAX_STORED_SCANS:
        oldest = min(_SCAN_STORE.items(), key=lambda item: item[1]["created_at"])[0]
        _SCAN_STORE.pop(oldest, None)

    return scan_id


def _result_payload(record: dict[str, Any]) -> dict:
    return {
        "scan_id": record["scan_id"],
        "target": record["target"],
        "target_type": record["target_type"],
        "platform": record["platform"],
        "commit": record.get("commit"),
        "status": record["status"],
        **_present(record["findings"]),
    }


def _scan_local(folder: Path) -> tuple[list[dict], str]:
    raw, platform = scan_path(folder)
    return enrich(raw, platform), platform


def _scan_public_repo(repo_url: str) -> tuple[list[dict], str, str | None]:
    result = run_full_scan(repo_url)
    return result["findings"], result["platform"], result.get("commit_sha")


def _scan_live(url: str) -> tuple[list[dict], str]:
    assert_public_url(url)
    return scan_live_target(url), "generic"


def _is_repo_url(target: str) -> bool:
    lower = target.lower().rstrip("/")
    return (
        "github.com/" in lower
        or "gitlab.com/" in lower
        or "bitbucket.org/" in lower
        or lower.endswith(".git")
    )


@mcp.tool()
async def scan_repository(repo_url: str) -> dict:
    """Scan a public Git repository and return severity-grouped findings.

    The scanner clones the repository, runs source-level checks plus the
    static-analysis engine, then enriches findings with explanations and fix
    prompts. Use scan_local_workspace for code already on the user's machine.
    """
    if not _is_repo_url(repo_url):
        raise ValueError("scan_repository expects a public Git repository URL.")
    findings, platform, commit = await anyio.to_thread.run_sync(_scan_public_repo, repo_url)
    scan_id = _remember_scan(
        target=repo_url,
        target_type="repo",
        platform=platform,
        findings=findings,
        commit=commit,
    )
    return _result_payload(_SCAN_STORE[scan_id])


@mcp.tool()
async def scan_local_workspace(path: str = ".") -> dict:
    """Scan the caller's local project directory without cloning or uploading it."""
    folder = _resolve_dir(path)
    findings, platform = await anyio.to_thread.run_sync(_scan_local, folder)
    scan_id = _remember_scan(
        target=str(folder),
        target_type="local_workspace",
        platform=platform,
        findings=findings,
    )
    return _result_payload(_SCAN_STORE[scan_id])


@mcp.tool()
async def scan_live_url(url: str) -> dict:
    """Run passive, read-only checks against a live public application URL."""
    findings, platform = await anyio.to_thread.run_sync(_scan_live, url)
    scan_id = _remember_scan(
        target=url,
        target_type="live_url",
        platform=platform,
        findings=findings,
    )
    return _result_payload(_SCAN_STORE[scan_id])


@mcp.tool()
async def get_scan_status(scan_id: str) -> dict:
    """Return the current status and summary for a local MCP scan."""
    record = _SCAN_STORE.get(scan_id)
    if not record:
        raise ValueError(f"Unknown MCP scan_id: {scan_id}")
    return {
        "scan_id": scan_id,
        "status": record["status"],
        "target_type": record["target_type"],
        "platform": record["platform"],
        "total": len(record["findings"]),
    }


@mcp.tool()
async def get_findings(scan_id: str) -> dict:
    """Return the stored enriched findings for a previous MCP scan."""
    record = _SCAN_STORE.get(scan_id)
    if not record:
        raise ValueError(f"Unknown MCP scan_id: {scan_id}")
    return _result_payload(record)


@mcp.tool()
async def rescan(scan_id: str) -> dict:
    """Re-run a previous MCP scan and return resolved/still-open/new findings."""
    record = _SCAN_STORE.get(scan_id)
    if not record:
        raise ValueError(f"Unknown MCP scan_id: {scan_id}")

    previous = record["findings"]
    target_type = record["target_type"]

    if target_type == "repo":
        findings, platform, commit = await anyio.to_thread.run_sync(
            _scan_public_repo, record["target"]
        )
    elif target_type == "local_workspace":
        folder = _resolve_dir(record["target"])
        findings, platform = await anyio.to_thread.run_sync(_scan_local, folder)
        commit = None
    else:
        findings, platform = await anyio.to_thread.run_sync(_scan_live, record["target"])
        commit = None

    current_by_fp = {fingerprint(f): f for f in findings}
    previous_by_fp = {fingerprint(f): f for f in previous}

    resolved = [previous_by_fp[fp] for fp in sorted(set(previous_by_fp) - set(current_by_fp))]
    still_present = [current_by_fp[fp] for fp in sorted(set(previous_by_fp) & set(current_by_fp))]
    new_findings = [current_by_fp[fp] for fp in sorted(set(current_by_fp) - set(previous_by_fp))]

    record["findings"] = findings
    record["platform"] = platform
    record["commit"] = commit
    record["status"] = "completed"

    return {
        "scan_id": scan_id,
        "target": record["target"],
        "platform": platform,
        "status": "completed",
        "resolved": _present(resolved),
        "still_present": _present(still_present),
        "new_findings": _present(new_findings),
    }


# Backward-compatible tool names for existing VS Code/Cursor/Claude configs.


@mcp.tool()
async def scan_workspace(path: str = ".") -> dict:
    """Compatibility alias for scan_local_workspace."""
    return await scan_local_workspace(path)


@mcp.tool()
async def scan_url(target: str) -> dict:
    """Compatibility alias: route a repo URL to repository scanning, otherwise use passive live checks."""
    if _is_repo_url(target):
        return await scan_repository(target)
    return await scan_live_url(target)


@mcp.tool()
async def verify_fixes(path: str, fingerprints: list[str]) -> dict:
    """Compatibility helper that re-scans a local workspace and compares fingerprints."""
    result = await scan_local_workspace(path)
    current = {item["fingerprint"] for item in result["findings"]}
    wanted = set(fingerprints)
    return {
        "resolved": sorted(wanted - current),
        "still_present": sorted(wanted & current),
        "new_findings": [item for item in result["findings"] if item["fingerprint"] not in wanted],
        "scan_id": result["scan_id"],
    }


if __name__ == "__main__":
    mcp.run()

"""Secure-VibeCode MCP server.

Lets an AI coding tool (Claude Code, Cursor, VS Code Copilot agent mode,
Claude Desktop, ...) scan the project you are working on and fix what it
finds without leaving the editor. It runs on YOUR machine over stdio:
`scan_workspace` reads files straight from disk, so nothing is cloned and no
GitHub credentials are needed.

Run:   python mcp_server.py
Client config (VS Code .vscode/mcp.json, Claude Desktop, Cursor):
  {"command": "python", "args": ["/path/to/secure-vibecode/mcp_server.py"]}

Tools:
  scan_workspace(path)             scan a local folder
  verify_fixes(path, fingerprints) re-scan and report which findings are gone
  scan_url(target)                 scan a public repo URL or live app URL

Set GEMINI_API_KEY for AI-written explanations and fix prompts; without it
deterministic templates are used. stdout is the MCP protocol channel, so
this module must never print to it.
"""
from pathlib import Path

import anyio
from mcp.server.fastmcp import FastMCP

from agents.verify_agent import fingerprint
from orchestrator import enrich, run_full_scan, scan_path

mcp = FastMCP("secure-vibecode")

MAX_FINDINGS = 50
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _present(findings: list[dict]) -> dict:
    ordered = sorted(findings, key=lambda f: SEVERITY_RANK.get(f.get("severity"), 4))
    counts = {sev: sum(1 for f in findings if f.get("severity") == sev) for sev in SEVERITY_RANK}
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
                "what_it_means": f.get("what_it_means"),
                "why_it_matters": f.get("why_it_matters"),
                "fix_prompt": f.get("fix_prompt"),
            }
            for f in ordered[:MAX_FINDINGS]
        ],
    }


def _resolve_dir(path: str) -> Path:
    folder = Path(path).expanduser().resolve()
    if not folder.is_dir():
        raise ValueError(f"'{path}' is not a directory.")
    return folder


def _scan_local(folder: Path) -> tuple[list[dict], str]:
    raw, platform = scan_path(folder)
    return enrich(raw, platform), platform


@mcp.tool()
async def scan_workspace(path: str = ".") -> dict:
    """Scan a local project folder for security problems (hardcoded secrets,
    missing Supabase row-level security, unsafe code patterns) and return
    each finding with a plain-English explanation and a ready-to-use fix
    prompt. Apply the fix prompts, then call verify_fixes to confirm."""
    folder = _resolve_dir(path)
    findings, platform = await anyio.to_thread.run_sync(_scan_local, folder)
    return {"platform": platform, **_present(findings)}


@mcp.tool()
async def verify_fixes(path: str, fingerprints: list[str]) -> dict:
    """Re-scan a local project folder and report which previously reported
    findings (identified by the `fingerprint` values scan_workspace returned)
    are now resolved, which are still present, and any new findings."""
    folder = _resolve_dir(path)
    findings, _ = await anyio.to_thread.run_sync(_scan_local, folder)

    current = {fingerprint(f): f for f in findings}
    wanted = set(fingerprints)
    return {
        "resolved": sorted(wanted - current.keys()),
        "still_present": sorted(wanted & current.keys()),
        "new_findings": _present([f for fp, f in current.items() if fp not in wanted])["findings"],
    }


@mcp.tool()
async def scan_url(target: str) -> dict:
    """Scan a public git repository URL (GitHub, GitLab, Bitbucket) or a
    live deployed app URL. Private, loopback and internal addresses are
    refused. For code on your own disk, use scan_workspace instead."""
    result = await anyio.to_thread.run_sync(run_full_scan, target)
    return {"platform": result["platform"], "commit": result.get("commit_sha"), **_present(result["findings"])}


if __name__ == "__main__":
    mcp.run()

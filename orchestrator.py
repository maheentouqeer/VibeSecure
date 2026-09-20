"""Orchestrator: sequences scanners and agents into one scan pipeline.

Two entry points everyone else builds against:
  run_full_scan(target) -> dict
  rescan(target, previous_findings) -> list[dict]
"""
from pathlib import Path

from scanner.repo_utils import clone_repo, cleanup, head_commit
from scanner.url_safety import assert_public_url
from scanner.platform_detector import detect_platform, is_supabase_project
from scanner.secrets_scanner import scan_secrets
from scanner.code_scanner import run_semgrep
from scanner.supabase_rls_checker import check_rls
from scanner.live_scanner import scan_live_url
from agents.triage_agent import triage
from agents.explainer_agent import explain
from agents.fixprompt_agent import generate_fix_prompt

# Known git hosts get routed straight to a clone. This is not an
# exhaustive list -- anything else still gets a clone attempt first
# (see _run_repo_scan / run_full_scan below) before we assume it's a
# live app URL, so GitLab, Bitbucket, and self-hosted git servers all
# still work correctly instead of being silently misrouted to the
# live-URL scanner the way a plain "github.com" substring check would.
_KNOWN_GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")


def _looks_like_repo_target(target: str) -> bool:
    target_lower = target.lower()
    if any(host in target_lower for host in _KNOWN_GIT_HOSTS):
        return True
    if target_lower.endswith(".git"):
        return True
    return False


def scan_path(repo_path: Path) -> tuple[list[dict], str]:
    """Runs the source-level scanners against an already-local directory.
    Shared by the clone-based scan and the MCP local-workspace mode."""
    raw_findings: list[dict] = []
    platform = detect_platform(repo_path)
    raw_findings += scan_secrets(repo_path)
    raw_findings += run_semgrep(repo_path)
    if is_supabase_project(repo_path):
        raw_findings += check_rls(repo_path)
    return raw_findings, platform


def enrich(raw_findings: list[dict], platform: str) -> list[dict]:
    """Triage, explain, and write a fix prompt for each raw finding."""
    enriched = []
    for finding in triage(raw_findings):
        explanation = explain(finding)
        fix_prompt = generate_fix_prompt(finding, platform)
        enriched.append({**finding, **explanation, "fix_prompt": fix_prompt})
    return enriched


def _run_repo_scan(target: str, unchanged_since: str | None = None, github_token: str | None = None):
    """Clones target and scans it. Returns (raw_findings, platform, commit_sha),
    or (None, None, commit_sha) when the checked-out commit equals
    `unchanged_since` and the scan work was skipped. Raises if target isn't
    actually a clonable git repo -- callers decide what to do with that."""
    repo_path = clone_repo(target, token=github_token)
    try:
        commit_sha = head_commit(repo_path)
        if unchanged_since and commit_sha == unchanged_since:
            return None, None, commit_sha
        raw_findings, platform = scan_path(repo_path)
    finally:
        cleanup(repo_path)
    return raw_findings, platform, commit_sha


def run_full_scan(target: str, unchanged_since: str | None = None, github_token: str | None = None) -> dict:
    """target: a repo URL (GitHub, GitLab, Bitbucket, or any other git
    host reachable over HTTPS) or a live deployed app URL.

    Known git hosts (and anything ending in .git) go straight to a
    clone -- if that clone fails, the error is allowed to propagate,
    since a broken/private/inaccessible repo URL on a *known* git host
    should surface as a real error, not silently get treated as a live
    website (which would produce meaningless findings against the git
    host's own homepage instead of a clear failure).

    Anything else is ambiguous, so we try cloning it anyway -- this
    covers unrecognized git hosts -- and only fall back to a live-URL
    scan once cloning has actually failed, rather than guessing upfront.

    If `unchanged_since` is the commit SHA of a previous scan and the repo
    is still at that commit, the expensive scanner and LLM work is skipped
    and the result has "unchanged": True with no findings.

    `github_token` is a user's own GitHub token for cloning their private
    repositories; it is only ever offered to github.com (see clone_repo).
    """
    assert_public_url(target)

    commit_sha = None
    if _looks_like_repo_target(target):
        raw_findings, platform, commit_sha = _run_repo_scan(target, unchanged_since, github_token)
    else:
        try:
            raw_findings, platform, commit_sha = _run_repo_scan(target, unchanged_since, github_token)
        except Exception:
            raw_findings = scan_live_url(target)
            platform = "generic"

    if raw_findings is None:
        return {"target": target, "platform": None, "findings": [], "commit_sha": commit_sha, "unchanged": True}

    return {
        "target": target,
        "platform": platform,
        "findings": enrich(raw_findings, platform),
        "commit_sha": commit_sha,
        "unchanged": False,
    }


def rescan(target: str, previous_findings: list[dict]) -> list[dict]:
    from agents.verify_agent import diff_findings

    new_scan = run_full_scan(target)
    return diff_findings(previous_findings, new_scan["findings"])

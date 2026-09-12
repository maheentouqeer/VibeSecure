"""Orchestrator: sequences scanners and agents into one scan pipeline.

Two entry points everyone else builds against:
  run_full_scan(target) -> dict
  rescan(target, previous_findings) -> list[dict]
"""
from pathlib import Path

from scanner.repo_utils import clone_repo, cleanup
from scanner.platform_detector import detect_platform
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


def _run_repo_scan(target: str) -> tuple[list[dict], str]:
    """Clones target and runs the source-level scanners against it.
    Raises if target isn't actually a clonable git repo -- callers
    decide what to do with that (see run_full_scan)."""
    raw_findings: list[dict] = []
    repo_path = clone_repo(target)
    try:
        platform = detect_platform(repo_path)
        raw_findings += scan_secrets(repo_path)
        raw_findings += run_semgrep(repo_path)
        raw_findings += check_rls(repo_path)
    finally:
        cleanup(repo_path)
    return raw_findings, platform


def run_full_scan(target: str) -> dict:
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
    """
    if _looks_like_repo_target(target):
        raw_findings, platform = _run_repo_scan(target)
    else:
        try:
            raw_findings, platform = _run_repo_scan(target)
        except Exception:
            raw_findings = scan_live_url(target)
            platform = "generic"

    triaged = triage(raw_findings)

    enriched = []
    for finding in triaged:
        explanation = explain(finding)
        fix_prompt = generate_fix_prompt(finding, platform)
        enriched.append({**finding, **explanation, "fix_prompt": fix_prompt})

    return {"target": target, "platform": platform, "findings": enriched}


def rescan(target: str, previous_findings: list[dict]) -> list[dict]:
    from agents.verify_agent import diff_findings

    new_scan = run_full_scan(target)
    return diff_findings(previous_findings, new_scan["findings"])

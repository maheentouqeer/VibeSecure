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


def _is_url_only(target: str) -> bool:
    return "github.com" not in target


def run_full_scan(target: str) -> dict:
    """target: either a public GitHub repo URL or a live deployed app URL."""
    raw_findings: list[dict] = []
    platform = "generic"

    if _is_url_only(target):
        raw_findings += scan_live_url(target)
    else:
        repo_path = clone_repo(target)
        try:
            platform = detect_platform(repo_path)
            raw_findings += scan_secrets(repo_path)
            raw_findings += run_semgrep(repo_path)
            raw_findings += check_rls(repo_path)
        finally:
            cleanup(repo_path)

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

"""Orchestrator tests against a real local git repository (no network, no LLM)."""
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

import orchestrator


def _git(repo, *args):
    subprocess.run(
        ["git", "-c", "user.email=t@t.test", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True,
    )


@pytest.fixture()
def source_repo(tmp_path):
    repo = tmp_path / "source"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "aws.ts").write_text("const key = 'AKIA1234567890ABCDEF';")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


@pytest.fixture(autouse=True)
def _offline(monkeypatch, source_repo, tmp_path):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(orchestrator, "assert_public_url", lambda url: None)
    monkeypatch.setattr(orchestrator, "run_semgrep", lambda path: [])

    counter = {"n": 0}

    def fake_clone(url, token=None):
        counter["n"] += 1
        dest = tmp_path / f"clone{counter['n']}"
        # Ignore lock files: a real `git clone` reads objects over the git
        # protocol rather than copying the filesystem, so it never sees
        # git's background maintenance briefly locking the source repo's
        # object store -- copytree does, and can otherwise race it (list a
        # *.lock file, then find it gone by the time it tries to copy it).
        shutil.copytree(source_repo, dest, ignore=shutil.ignore_patterns("*.lock"))
        return dest

    monkeypatch.setattr(orchestrator, "clone_repo", fake_clone)


def _head(repo):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()


def test_scan_reports_the_commit_it_scanned_and_finds_the_secret(source_repo):
    result = orchestrator.run_full_scan("https://github.com/example/app")
    assert result["commit_sha"] == _head(source_repo)
    assert result["unchanged"] is False
    assert any(f["label"] == "AWS Access Key" for f in result["findings"])


def test_unchanged_commit_short_circuits_before_any_scanning(source_repo, monkeypatch):
    sha = _head(source_repo)

    def must_not_scan(*a, **k):
        raise AssertionError("scanners ran for an unchanged commit")

    monkeypatch.setattr(orchestrator, "scan_secrets", must_not_scan)
    monkeypatch.setattr(orchestrator, "triage", must_not_scan)

    result = orchestrator.run_full_scan("https://github.com/example/app", unchanged_since=sha)
    assert result["unchanged"] is True
    assert result["findings"] == []
    assert result["commit_sha"] == sha


def test_new_commit_is_scanned_even_when_unchanged_since_is_set(source_repo):
    result = orchestrator.run_full_scan("https://github.com/example/app", unchanged_since="0" * 40)
    assert result["unchanged"] is False
    assert result["findings"]


def test_enrich_and_scan_path_work_on_a_local_directory_without_cloning(source_repo, monkeypatch):
    monkeypatch.setattr(orchestrator, "clone_repo", lambda url: (_ for _ in ()).throw(AssertionError("cloned")))
    raw, platform = orchestrator.scan_path(source_repo)
    findings = orchestrator.enrich(raw, platform)

    assert platform == "generic"
    assert findings and all(f["what_it_means"] and f["fix_prompt"] for f in findings)

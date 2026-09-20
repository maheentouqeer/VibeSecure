"""Credential-handling tests for repository cloning."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from scanner import repo_utils


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://github.com/owner/repo", True),
        ("https://github.com/owner/repo.git", True),
        ("https://www.github.com/owner/repo", True),
        ("https://user@github.com/owner/repo", True),
        ("https://GitHub.com/owner/repo", True),
        ("https://evil.example/github.com/x.git", False),
        ("https://evil.example/?u=github.com/x", False),
        ("https://github.com.evil.example/owner/repo", False),
        ("https://notgithub.com/owner/repo", False),
        ("https://gitlab.com/owner/repo", False),
        ("not a url", False),
        ("http://[::1", False),
    ],
)
def test_credentials_are_only_for_github_itself(url, expected):
    assert repo_utils._is_github_url(url) is expected


def _capture_clone_env(monkeypatch):
    seen = {}
    # DNS pinning is covered in test_dns_rebinding.py; keep these tests off the network.
    monkeypatch.setattr(repo_utils, "git_pin_env", lambda url, env: env)

    def fake_clone_from(url, to_path, depth, env):
        seen["env"] = env
        seen["url"] = url
        return None

    monkeypatch.setattr(repo_utils.git.Repo, "clone_from", staticmethod(fake_clone_from))
    return seen


def test_server_token_is_never_offered_to_a_lookalike_host(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "server-secret")
    seen = _capture_clone_env(monkeypatch)
    repo_utils.cleanup(repo_utils.clone_repo("https://evil.example/github.com/x.git"))

    assert "GIT_ASKPASS" not in seen["env"]
    assert "VIBESECURE_GIT_ASKPASS_SECRET" not in seen["env"]


def test_token_is_offered_to_github_and_the_explicit_token_wins(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "server-secret")
    seen = _capture_clone_env(monkeypatch)

    repo_utils.cleanup(repo_utils.clone_repo("https://github.com/o/r"))
    assert seen["env"]["VIBESECURE_GIT_ASKPASS_SECRET"] == "server-secret"

    repo_utils.cleanup(repo_utils.clone_repo("https://github.com/o/r", token="users-own-token"))
    assert seen["env"]["VIBESECURE_GIT_ASKPASS_SECRET"] == "users-own-token"
    assert "users-own-token" not in seen["url"]  # never embedded in the URL


def test_explicit_token_is_not_sent_to_other_hosts(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seen = _capture_clone_env(monkeypatch)
    repo_utils.cleanup(repo_utils.clone_repo("https://gitlab.com/o/r", token="users-own-token"))
    assert "VIBESECURE_GIT_ASKPASS_SECRET" not in seen["env"]

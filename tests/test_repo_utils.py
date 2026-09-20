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
    monkeypatch.setenv("ALLOW_SERVER_GITHUB_TOKEN", "1")
    seen = _capture_clone_env(monkeypatch)
    repo_utils.cleanup(repo_utils.clone_repo("https://evil.example/github.com/x.git"))

    assert "GIT_ASKPASS" not in seen["env"]
    assert "VIBESECURE_GIT_ASKPASS_SECRET" not in seen["env"]


def test_token_is_offered_to_github_and_the_explicit_token_wins(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "server-secret")
    monkeypatch.setenv("ALLOW_SERVER_GITHUB_TOKEN", "1")
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


# ------------------------------------------- the server-wide token is opt-in


@pytest.fixture()
def server_token(monkeypatch):
    for var in ("GITHUB_PAT", "VIBESECURE_GITHUB_TOKEN", "ALLOW_SERVER_GITHUB_TOKEN", "SERVER_GITHUB_TOKEN_OWNERS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "server-secret")
    monkeypatch.setattr(repo_utils, "_warned_server_token", False)


def test_the_server_token_is_ignored_unless_explicitly_allowed(server_token):
    assert repo_utils.server_token_for("https://github.com/anyone/private-repo") is None


def test_it_is_used_once_allowed(server_token, monkeypatch):
    monkeypatch.setenv("ALLOW_SERVER_GITHUB_TOKEN", "1")
    assert repo_utils.server_token_for("https://github.com/anyone/repo") == "server-secret"


@pytest.mark.parametrize("value", ["", "0", "true", "yes", "2"])
def test_only_the_exact_value_1_turns_it_on(server_token, monkeypatch, value):
    monkeypatch.setenv("ALLOW_SERVER_GITHUB_TOKEN", value)
    assert repo_utils.server_token_for("https://github.com/o/r") is None


def test_an_owner_allowlist_limits_which_repositories_get_it(server_token, monkeypatch):
    monkeypatch.setenv("ALLOW_SERVER_GITHUB_TOKEN", "1")
    monkeypatch.setenv("SERVER_GITHUB_TOKEN_OWNERS", "my-org, MyUser")

    assert repo_utils.server_token_for("https://github.com/my-org/private") == "server-secret"
    assert repo_utils.server_token_for("https://github.com/MYUSER/thing.git") == "server-secret"  # case-insensitive
    assert repo_utils.server_token_for("https://github.com/someone-else/private") is None
    assert repo_utils.server_token_for("https://github.com/my-org-evil/private") is None  # exact owner, not a prefix
    assert repo_utils.server_token_for("https://github.com/") is None
    assert repo_utils.server_token_for("https://github.com") is None


def test_alternate_token_variable_names_are_covered_by_the_same_switch(monkeypatch):
    for var in ("GITHUB_TOKEN", "GITHUB_PAT", "VIBESECURE_GITHUB_TOKEN", "ALLOW_SERVER_GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GITHUB_PAT", "pat-secret")
    assert repo_utils.server_token_for("https://github.com/o/r") is None
    monkeypatch.setenv("ALLOW_SERVER_GITHUB_TOKEN", "1")
    assert repo_utils.server_token_for("https://github.com/o/r") == "pat-secret"


def test_nothing_happens_when_no_token_is_set(monkeypatch):
    for var in ("GITHUB_TOKEN", "GITHUB_PAT", "VIBESECURE_GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ALLOW_SERVER_GITHUB_TOKEN", "1")
    assert repo_utils.server_token_for("https://github.com/o/r") is None


def test_ignoring_the_token_is_logged_once_so_it_is_not_a_silent_surprise(server_token, caplog):
    import logging

    with caplog.at_level(logging.WARNING, logger="scanner.repo_utils"):
        for _ in range(3):
            repo_utils.server_token_for("https://github.com/o/r")
    messages = [r.message for r in caplog.records if "ignored" in r.message]
    assert len(messages) == 1 and "ALLOW_SERVER_GITHUB_TOKEN=1" in messages[0]
    assert "server-secret" not in caplog.text


def test_cloning_never_offers_the_ignored_server_token_but_still_offers_a_users_own(server_token, monkeypatch):
    seen = {}
    monkeypatch.setattr(repo_utils, "git_pin_env", lambda url, env: env)
    monkeypatch.setattr(
        repo_utils.git.Repo, "clone_from",
        staticmethod(lambda url, to_path, depth, env: seen.update(env=env)),
    )

    repo_utils.cleanup(repo_utils.clone_repo("https://github.com/o/private"))
    assert "VIBESECURE_GIT_ASKPASS_SECRET" not in seen["env"]  # ignored: nothing offered

    repo_utils.cleanup(repo_utils.clone_repo("https://github.com/o/private", token="users-own"))
    assert seen["env"]["VIBESECURE_GIT_ASKPASS_SECRET"] == "users-own"  # a user's connection is unaffected

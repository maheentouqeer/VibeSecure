"""Utilities for cloning repositories safely in the scanner runtime."""
import os
import shutil
import tempfile
from urllib.parse import urlparse
from pathlib import Path

import git
from git.exc import GitCommandNotFound, GitCommandError


def _configure_git() -> None:
    """Configure GitPython to use the system git executable."""
    executable = os.getenv("GIT_PYTHON_GIT_EXECUTABLE") or shutil.which("git")
    if not executable:
        raise RuntimeError(
            "Git is not installed in the backend runtime. "
            "Install the system git package on Railway and set "
            "GIT_PYTHON_GIT_EXECUTABLE if necessary."
        )
    git.Git.refresh(path=executable)


_configure_git()


def _github_token() -> str | None:
    """Return an optional GitHub token for cloning private GitHub repos."""
    return (
        os.getenv("GITHUB_TOKEN")
        or os.getenv("GITHUB_PAT")
        or os.getenv("VIBESECURE_GITHUB_TOKEN")
    )


def _is_github_url(url: str) -> bool:
    """True only when the URL's host is github.com itself. A substring test
    would also match https://evil.example/github.com/x.git, handing the
    credential to whoever runs that host."""
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    return host in ("github.com", "www.github.com")


is_github_url = _is_github_url


def clone_repo(github_url: str, token: str | None = None) -> Path:
    """Clone a repository to a temporary directory.

    Public repositories work without credentials. For private GitHub
    repositories a token is supplied through Git's askpass mechanism rather
    than embedding it in the URL: the explicit `token` argument (a user's own
    connected GitHub account) wins over the server-wide environment token.
    Credentials are only ever offered to github.com.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="svc_scan_"))
    askpass_dir: Path | None = None

    try:
        clone_env = os.environ.copy()
        token = (token or _github_token()) if _is_github_url(github_url) else None

        if token:
            # Git invokes this helper when it needs HTTP credentials. The
            # secret stays in the process environment and is not part of the
            # clone URL or command line shown in Git errors.
            askpass_dir = Path(tempfile.mkdtemp(prefix="svc_git_"))
            askpass = askpass_dir / "askpass.py"
            askpass.write_text(
                "import os, sys\n"
                "prompt = sys.argv[1].lower() if len(sys.argv) > 1 else ''\n"
                "if 'username' in prompt:\n"
                "    print('x-access-token')\n"
                "else:\n"
                "    print(os.environ.get('VIBESECURE_GIT_ASKPASS_SECRET', ''))\n",
                encoding="utf-8",
            )
            clone_env["VIBESECURE_GIT_ASKPASS_SECRET"] = token
            clone_env["GIT_ASKPASS"] = str(askpass)
            clone_env["GIT_TERMINAL_PROMPT"] = "0"

        git.Repo.clone_from(
            github_url,
            tmp_dir,
            depth=1,
            env=clone_env,
        )
        return tmp_dir
    except (GitCommandNotFound, GitCommandError) as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Unable to clone repository: {exc}") from exc
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    finally:
        if askpass_dir:
            shutil.rmtree(askpass_dir, ignore_errors=True)


def head_commit(path: Path) -> str | None:
    """Full SHA of the checked-out HEAD, or None if it can't be read."""
    try:
        return git.Repo(path).head.commit.hexsha
    except Exception:
        return None


def cleanup(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)

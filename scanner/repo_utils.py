"""Utilities for cloning repositories safely in the scanner runtime."""
import logging
import os
import shutil
import tempfile
from urllib.parse import urlparse
from pathlib import Path

import git
from scanner.url_safety import git_pin_env
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


logger = logging.getLogger(__name__)

_configure_git()


_warned_server_token = False


def _github_token() -> str | None:
    """The raw server-wide GitHub token from the environment, if one is set.
    Not used directly for cloning: see server_token_for()."""
    return (
        os.getenv("GITHUB_TOKEN")
        or os.getenv("GITHUB_PAT")
        or os.getenv("VIBESECURE_GITHUB_TOKEN")
    )


def server_token_for(url: str) -> str | None:
    """The server-wide GitHub token, if it may be used for this repository.

    A server-wide token lets ANYONE who can submit a URL scan whatever the
    token can read, so it is opt-in:
      ALLOW_SERVER_GITHUB_TOKEN=1         turns it on (otherwise it is ignored)
      SERVER_GITHUB_TOKEN_OWNERS=a,b      optional but strongly advised: only use it for
                                          repositories owned by these GitHub users/orgs
    Users' own connected GitHub accounts (see backend/github_oauth.py) are
    unaffected by this."""
    global _warned_server_token
    token = _github_token()
    if not token:
        return None
    if os.getenv("ALLOW_SERVER_GITHUB_TOKEN") != "1":
        if not _warned_server_token:
            _warned_server_token = True
            logger.warning(
                "A server-wide GitHub token is set but ignored. Set ALLOW_SERVER_GITHUB_TOKEN=1 to use it "
                "(and SERVER_GITHUB_TOKEN_OWNERS to limit it to your own repositories)."
            )
        return None
    owners = [o.strip().lower() for o in os.getenv("SERVER_GITHUB_TOKEN_OWNERS", "").split(",") if o.strip()]
    if owners:
        segments = [p for p in urlparse(url).path.split("/") if p]
        if not segments or segments[0].lower() not in owners:
            return None
    return token


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
        token = (token or server_token_for(github_url)) if _is_github_url(github_url) else None

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

        # Pin the host to the addresses just validated, so git cannot re-resolve
        # it to something internal (DNS rebinding). Raises if the host isn't public.
        clone_env = git_pin_env(github_url, clone_env)

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

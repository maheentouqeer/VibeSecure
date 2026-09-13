"""Utilities for cloning repositories safely in the scanner runtime."""
import os
import shutil
import tempfile
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


def clone_repo(github_url: str) -> Path:
    """Clone a public repository to a temporary directory."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="svc_scan_"))
    try:
        git.Repo.clone_from(github_url, tmp_dir, depth=1)
        return tmp_dir
    except (GitCommandNotFound, GitCommandError) as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Unable to clone repository: {exc}") from exc
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def cleanup(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)

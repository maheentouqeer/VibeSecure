"""Clone a public GitHub repo to a temp directory for scanning."""
import shutil
import tempfile
from pathlib import Path

import git


def clone_repo(github_url: str) -> Path:
    """Clones a public repo to a fresh temp dir and returns the path.

    Caller is responsible for calling cleanup(path) when done.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="svc_scan_"))
    git.Repo.clone_from(github_url, tmp_dir, depth=1)
    return tmp_dir


def cleanup(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)

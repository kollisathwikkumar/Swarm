from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

from git import Repo as GitRepo

SENSITIVE_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "credentials.json",
    "*secret*",
]


def is_sensitive_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").lstrip("/")
    if norm == ".git" or norm.startswith(".git/"):
        return True
    name = Path(norm).name
    return any(fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(name, pat) for pat in SENSITIVE_PATTERNS)


def validate_repo_path(raw_path: str, allowed_root: Path | None = None) -> Path:
    resolved = Path(raw_path).expanduser().resolve()
    if allowed_root is not None:
        root_res = allowed_root.resolve()
        if resolved != root_res and root_res not in resolved.parents:
            raise PermissionError(f"Path traversal rejected: {resolved} is outside {root_res}")
    if not resolved.exists() or not resolved.is_dir():
        raise FileNotFoundError(f"Directory does not exist: {resolved}")
    if not (resolved / ".git").exists():
        raise ValueError(f"Directory is not a Git repository: {resolved}")
    return resolved


def inspect_repository(repo_path: Path) -> dict[str, Any]:
    repo = GitRepo(str(repo_path))
    try:
        active_branch = repo.active_branch.name
    except TypeError:
        active_branch = "HEAD"

    branches = [h.name for h in repo.heads]
    commits = [
        {
            "sha": c.hexsha,
            "message": c.message.strip().splitlines()[0] if c.message else "",
            "author": str(c.author),
            "date": c.committed_datetime.isoformat(),
        }
        for c in list(repo.iter_commits(max_count=20))
    ]
    staged = [item.a_path for item in repo.index.diff("HEAD") if item.a_path and not is_sensitive_path(item.a_path)] if repo.head.is_valid() else []
    unstaged = [item.a_path for item in repo.index.diff(None) if item.a_path and not is_sensitive_path(item.a_path)]
    untracked = [p for p in repo.untracked_files if not is_sensitive_path(p)]

    return {
        "name": repo_path.name,
        "local_path": str(repo_path),
        "active_branch": active_branch,
        "branches": branches,
        "commits": commits,
        "staged_files": staged,
        "unstaged_files": unstaged,
        "untracked_files": untracked,
    }

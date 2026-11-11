from __future__ import annotations

import contextlib
import re
from pathlib import Path
from typing import Any

from git import GitCommandError
from git import Repo as GitRepo
from repository_reader import is_sensitive_path

_DIFF_HDR = re.compile(r"^diff --git a/(.*?) b/(.*?)$")


def _filter_diff_sensitive_files(diff_text: str) -> tuple[str, list[str]]:
    if not diff_text.strip():
        return "", []
    kept_blocks: list[str] = []
    changed_paths: list[str] = []
    current_block: list[str] = []
    current_skip = False
    current_path = ""

    for line in diff_text.splitlines():
        m = _DIFF_HDR.match(line)
        if m:
            if current_block and not current_skip:
                kept_blocks.append("\n".join(current_block))
                if current_path:
                    changed_paths.append(current_path)
            b_path = m.group(2) if m.group(2) != "/dev/null" else m.group(1)
            current_path = b_path
            current_skip = is_sensitive_path(b_path)
            current_block = [line]
            continue
        current_block.append(line)

    if current_block and not current_skip:
        kept_blocks.append("\n".join(current_block))
        if current_path:
            changed_paths.append(current_path)

    return "\n".join(kept_blocks), list(dict.fromkeys(changed_paths))


def extract_diff(
    repo_path: Path,
    *,
    mode: str = "working_tree",
    base_ref: str = "HEAD~1",
    target_ref: str = "HEAD",
) -> dict[str, Any]:
    repo = GitRepo(str(repo_path))
    head_sha = repo.head.commit.hexsha if repo.head.is_valid() else "UNBORN"
    try:
        base_branch = repo.active_branch.name
    except TypeError:
        base_branch = "HEAD"

    if mode == "staged":
        raw_diff = repo.git.diff("--cached")
        base_commit = head_sha
        target_commit = "STAGED"
        target_branch = "staged"
    elif mode == "unstaged":
        raw_diff = repo.git.diff()
        base_commit = head_sha
        target_commit = "UNSTAGED"
        target_branch = "unstaged"
    elif mode == "commits":
        for ref_val in (base_ref, target_ref):
            cleaned = (ref_val or "").strip()
            if not cleaned or cleaned.startswith("-") or any(c.isspace() or ord(c) < 32 for c in cleaned):
                raise ValueError(f"Invalid Git ref: {ref_val!r}")
        base_commit = repo.git.rev_parse("--verify", base_ref.strip())
        target_commit = repo.git.rev_parse("--verify", target_ref.strip())
        raw_diff = repo.git.diff(f"{base_commit}..{target_commit}")
        target_branch = target_ref.strip()
    else:
        staged = repo.git.diff("--cached")
        unstaged = repo.git.diff()
        untracked_diffs: list[str] = []
        for uf in repo.untracked_files:
            if is_sensitive_path(uf):
                continue
            fp = (repo_path / uf).resolve()
            if repo_path.resolve() in fp.parents and fp.exists() and fp.is_file() and fp.stat().st_size < 100_000:
                lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
                body = "\n".join(f"+{ln}" for ln in lines)
                untracked_diffs.append(
                    f"diff --git a/{uf} b/{uf}\nnew file mode 100644\n--- /dev/null\n+++ b/{uf}\n@@ -0,0 +1,{len(lines)} @@\n{body}"
                )
        raw_diff = "\n".join(p for p in (staged, unstaged, *untracked_diffs) if p.strip())
        base_commit = head_sha
        target_commit = "WORKING_TREE"
        target_branch = "working_tree"

    filtered_diff, changed_paths = _filter_diff_sensitive_files(raw_diff)
    snapshots: dict[str, str] = {}
    for rel in changed_paths:
        if is_sensitive_path(rel):
            continue
        fp = (repo_path / rel).resolve()
        if repo_path.resolve() in fp.parents and fp.exists() and fp.is_file() and fp.stat().st_size < 120_000:
            if target_commit in ("WORKING_TREE", "STAGED", "UNSTAGED"):
                snapshots[rel] = fp.read_text(encoding="utf-8", errors="replace")
            else:
                with contextlib.suppress(GitCommandError):
                    snapshots[rel] = repo.git.show(f"{target_commit}:{rel}")

    return {
        "repository_name": repo_path.name,
        "local_path": str(repo_path),
        "base_branch": base_branch,
        "target_branch": target_branch,
        "base_commit": base_commit,
        "target_commit": target_commit,
        "diff_text": filtered_diff,
        "changed_paths": changed_paths,
        "file_snapshots": snapshots,
    }

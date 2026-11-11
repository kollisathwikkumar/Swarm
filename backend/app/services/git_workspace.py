from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import os
import shutil
import stat
import tempfile
from pathlib import Path

from app.config import get_settings

DEFAULT_SENSITIVE_EXCLUDES = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "credentials.json",
]


def is_excluded_path(rel_path: str, patterns: list[str] | None = None) -> bool:
    norm = rel_path.replace("\\", "/").lstrip("/")
    if not norm or ".." in Path(norm).parts or norm.startswith(".git/") or norm == ".git":
        return True
    active = (patterns or []) + DEFAULT_SENSITIVE_EXCLUDES
    filename = Path(norm).name
    return any(fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(filename, pat) for pat in active)


def validate_git_ref(ref: str) -> str:
    """Reject empty refs, whitespace/control chars, `..`, and option-like leading `-` (prevents Git flag injection)."""
    cleaned = (ref or "").strip()
    if (
        not cleaned
        or len(cleaned) > 256
        or cleaned.startswith("-")
        or any(ch.isspace() or ord(ch) < 32 for ch in cleaned)
        or ".." in cleaned
        or "@{" in cleaned
        or "\\" in cleaned
    ):
        raise ValueError(f"Invalid Git ref: {ref!r}")
    return cleaned


def resolve_within_dir(root_dir: Path, rel_path: str) -> Path | None:
    """Resolve `rel_path` safely inside `root_dir`, returning None if it escapes `root_dir`."""
    clean = (rel_path or "").replace("\\", "/").lstrip("/")
    if not clean or "\x00" in clean:
        return None
    root_res = root_dir.resolve()
    candidate = (root_res / clean).resolve()
    if root_res not in candidate.parents:
        return None
    return candidate


async def _run_git(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        "git",
        *args,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.CancelledError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(ProcessLookupError, OSError):
            await proc.wait()
        raise
    except TimeoutError:
        proc.kill()
        await proc.communicate()
        return 124, "", f"git {' '.join(args)} timed out after {timeout}s"
    return proc.returncode or 0, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace")


async def _git_env_with_askpass(token: str | None) -> tuple[dict[str, str], Path | None]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if not token:
        return env, None
    fd, raw_path = tempfile.mkstemp(prefix="rb_askpass_", suffix=".sh")
    os.close(fd)
    askpass_file = Path(raw_path)
    askpass_file.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  *Username*) echo "x-access-token" ;;\n'
        '  *) printf "%s\\n" "$RB_GIT_TOKEN" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    os.chmod(askpass_file, stat.S_IRUSR | stat.S_IXUSR)
    env["GIT_ASKPASS"] = str(askpass_file)
    env["RB_GIT_TOKEN"] = token
    return env, askpass_file


async def prepare_review_workspace(
    *,
    review_id: str,
    source_type: str,
    remote_url: str | None,
    local_path: str | None,
    base_commit: str,
    target_commit: str,
    diff_text: str = "",
    file_snapshots: dict[str, str] | None = None,
    github_token: str | None = None,
    excluded_patterns: list[str] | None = None,
) -> Path:
    """
    Create an isolated workspace directory checked out at the exact target_commit
    (plus any submitted working-tree snapshots/diff) so scanners never touch live user repos
    and never run against stale branches.
    """
    settings = get_settings()
    work_dir = settings.resolved_workspace_dir / review_id
    if work_dir.exists():
        shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    askpass_file: Path | None = None
    try:
        if source_type == "github" and remote_url:
            safe_target = validate_git_ref(target_commit)
            env, askpass_file = await _git_env_with_askpass(github_token)
            rc, _, err = await _run_git(
                ["clone", "--no-checkout", "--", remote_url, str(work_dir)],
                env=env,
                timeout=180,
            )
            if rc != 0:
                # Fallback: clone shallow or fetch PR ref explicitly
                raise RuntimeError(f"Failed to clone GitHub repository: {err}")
            # Fetch target commit (including PR head commits if not on main refs)
            await _run_git(["fetch", "origin", "--", safe_target], cwd=work_dir, env=env)
            if base_commit and base_commit != "EMPTY_TREE":
                safe_base = validate_git_ref(base_commit)
                await _run_git(["fetch", "origin", "--", safe_base], cwd=work_dir, env=env)
            rc, _, err = await _run_git(["checkout", "--force", safe_target], cwd=work_dir, env=env)
            if rc != 0:
                await _run_git(["fetch", "--all"], cwd=work_dir, env=env)
                rc2, _, err2 = await _run_git(["checkout", "--force", safe_target], cwd=work_dir, env=env)
                if rc2 != 0:
                    raise RuntimeError(f"Failed to checkout commit {safe_target}: {err2 or err}")
        elif source_type == "local" and local_path:
            src_path = Path(local_path).resolve()
            if not (src_path / ".git").exists():
                raise RuntimeError(f"Local path is not a valid git repository: {src_path}")
            # Copy cleanly without copying sensitive files or .git hooks issues
            rc, _, err = await _run_git(["clone", "--no-hardlinks", "--", str(src_path), str(work_dir)])
            if rc != 0:
                raise RuntimeError(f"Failed to isolate local git repository: {err}")
            if target_commit and target_commit not in ("WORKING_TREE", "STAGED", "UNSTAGED"):
                safe_target = validate_git_ref(target_commit)
                rc_co, _, _ = await _run_git(["checkout", "--force", safe_target], cwd=work_dir)
                if rc_co != 0:
                    await _run_git(["checkout", "--force", "HEAD"], cwd=work_dir)
            else:
                await _run_git(["checkout", "--force", "HEAD"], cwd=work_dir)
            # Apply uncommitted local diff if review includes working tree changes
            if diff_text.strip() and target_commit in ("WORKING_TREE", "STAGED", "UNSTAGED"):
                patch_file = work_dir / ".rb_pending.patch"
                patch_file.write_text(diff_text, encoding="utf-8")
                await _run_git(["apply", "--whitespace=nowarn", str(patch_file)], cwd=work_dir)
                patch_file.unlink(missing_ok=True)
        else:
            raise RuntimeError("Repository has neither remote_url nor local_path")

        # Overlay explicit submitted file snapshots (for remote Local Companion submissions!)
        if file_snapshots:
            for rel_path, content in file_snapshots.items():
                if is_excluded_path(rel_path, excluded_patterns):
                    continue
                target_file = resolve_within_dir(work_dir, rel_path)
                if target_file is None:
                    continue
                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(content, encoding="utf-8")

        # Remove sensitive files inside the isolated scan workspace
        for root_dir, _, files in os.walk(work_dir):
            if "/.git" in root_dir or root_dir.endswith("/.git"):
                continue
            for fname in files:
                full = Path(root_dir) / fname
                rel = str(full.relative_to(work_dir))
                if is_excluded_path(rel, excluded_patterns):
                    full.unlink(missing_ok=True)

        return work_dir
    finally:
        if askpass_file and askpass_file.exists():
            askpass_file.unlink(missing_ok=True)


async def verify_patch_applicability(
    workspace_dir: Path, file_path: str, unified_diff: str
) -> tuple[bool, str]:
    """Validate that a unified diff cleanly applies using `git apply --check`."""
    if not unified_diff.strip():
        return False, "Empty unified diff"
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False, encoding="utf-8") as tf:
        tf.write(unified_diff if unified_diff.endswith("\n") else unified_diff + "\n")
        patch_path = Path(tf.name)
    try:
        rc, out, err = await _run_git(["apply", "--check", str(patch_path)], cwd=workspace_dir)
        if rc == 0:
            return True, "git apply --check succeeded cleanly"
        return False, (err or out or "git apply --check failed").strip()
    finally:
        patch_path.unlink(missing_ok=True)


async def apply_patch_to_local_repo(local_path: str, unified_diff: str) -> tuple[bool, str]:
    """Apply an explicitly developer-approved patch to a local git repository."""
    repo_dir = Path(local_path).resolve()
    if not (repo_dir / ".git").exists():
        return False, f"Not a valid git repository: {repo_dir}"
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False, encoding="utf-8") as tf:
        tf.write(unified_diff if unified_diff.endswith("\n") else unified_diff + "\n")
        patch_path = Path(tf.name)
    try:
        rc_chk, out_chk, err_chk = await _run_git(["apply", "--check", str(patch_path)], cwd=repo_dir)
        if rc_chk != 0:
            return False, f"Patch check failed: {(err_chk or out_chk).strip()}"
        rc, out, err = await _run_git(["apply", str(patch_path)], cwd=repo_dir)
        if rc != 0:
            return False, f"Patch apply failed: {(err or out).strip()}"
        return True, "Patch cleanly applied to local working tree"
    finally:
        patch_path.unlink(missing_ok=True)


async def probe_github_remote_head(
    remote_url: str, *, github_token: str | None = None
) -> tuple[bool, str, str]:
    """Use `git ls-remote --symref` (bypasses REST API 60/hr rate limit) to verify repo and default branch."""
    env, askpass_file = await _git_env_with_askpass(github_token)
    try:
        rc, out, err = await _run_git(
            ["ls-remote", "--symref", remote_url, "HEAD"],
            env=env,
            timeout=30,
        )
        if rc != 0:
            return False, "main", (err or out or "git ls-remote failed").strip()
        default_branch = "main"
        for line in out.splitlines():
            if line.startswith("ref: refs/heads/"):
                branch_part = line.split()[0].replace("ref: refs/heads/", "")
                if branch_part:
                    default_branch = branch_part
                break
        return True, default_branch, ""
    finally:
        if askpass_file and askpass_file.exists():
            askpass_file.unlink(missing_ok=True)


async def ensure_github_mirror(
    owner: str,
    name: str,
    *,
    remote_url: str | None = None,
    ref: str | None = None,
    github_token: str | None = None,
) -> Path:
    """
    Maintain a shallow local Git clone mirror for fast, REST-rate-limit-free codebase browsing.
    """
    settings = get_settings()
    mirrors_root = settings.resolved_workspace_dir / "_mirrors"
    mirrors_root.mkdir(parents=True, exist_ok=True)
    safe_owner = "".join(c for c in owner if c.isalnum() or c in ("-", "_", "."))
    safe_name = "".join(c for c in name if c.isalnum() or c in ("-", "_", "."))
    mirror_dir = mirrors_root / f"{safe_owner}__{safe_name}"
    url = remote_url or f"https://github.com/{owner}/{name}.git"

    env, askpass_file = await _git_env_with_askpass(github_token)
    try:
        if not (mirror_dir / ".git").exists():
            if mirror_dir.exists():
                shutil.rmtree(mirror_dir, ignore_errors=True)
            args = ["clone", "--depth=50", "--", url, str(mirror_dir)]
            rc, _, err = await _run_git(args, env=env, timeout=120)
            if rc != 0:
                raise RuntimeError(f"Failed cloning repository mirror: {err.strip()}")
        else:
            await _run_git(["fetch", "--depth=50", "origin"], cwd=mirror_dir, env=env, timeout=60)
        if ref:
            safe_ref = validate_git_ref(ref)
            await _run_git(["fetch", "--depth=50", "origin", "--", safe_ref], cwd=mirror_dir, env=env, timeout=45)
        return mirror_dir
    finally:
        if askpass_file and askpass_file.exists():
            askpass_file.unlink(missing_ok=True)

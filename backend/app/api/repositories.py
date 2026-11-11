from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, HTTPException
from git import GitCommandError, InvalidGitRepositoryError
from git import Repo as GitRepo
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, resolve_github_token
from app.config import get_settings
from app.database.session import get_db
from app.integrations.github_client import GitHubAPIError, GitHubClient, parse_github_repo_input
from app.models.tables import CodeChange, Repository, Review, User
from app.orchestration.coordinator import (
    launch_review_job,
    load_effective_agent_configs,
    seed_agent_runs,
)
from app.scanners.git_diff_tool import parse_unified_diff
from app.services.git_workspace import (
    ensure_github_mirror,
    is_excluded_path,
    resolve_within_dir,
    validate_git_ref,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/repositories", tags=["repositories"])


class ConnectLocalRepoRequest(BaseModel):
    local_path: str = Field(min_length=1, max_length=1000)
    name: str | None = None


class UpdateRepositoryRequest(BaseModel):
    auto_review_webhooks: bool | None = None
    default_branch: str | None = None


class CompanionSubmitRequest(BaseModel):
    repository_name: str = Field(min_length=1, max_length=255)
    local_path: str = Field(min_length=1, max_length=1000)
    base_branch: str = "main"
    target_branch: str = "HEAD"
    base_commit: str
    target_commit: str
    diff_text: str
    file_snapshots: dict[str, str] = Field(default_factory=dict)


def _extract_local_git_diff(repo_path: Path, mode: str, base_ref: str = "HEAD~1", target_ref: str = "HEAD") -> tuple[str, str, str, dict[str, str]]:
    git_repo = GitRepo(str(repo_path))
    head_sha = git_repo.head.commit.hexsha if git_repo.head.is_valid() else "UNBORN"

    if mode == "staged":
        diff_text = git_repo.git.diff("--cached")
        base_commit = head_sha
        target_commit = "STAGED"
    elif mode == "unstaged":
        diff_text = git_repo.git.diff()
        base_commit = head_sha
        target_commit = "UNSTAGED"
    elif mode == "working_tree":
        staged = git_repo.git.diff("--cached")
        unstaged = git_repo.git.diff()
        # Also include untracked non-sensitive files as synthetic unified diff hunks
        untracked_diffs: list[str] = []
        for uf in git_repo.untracked_files:
            if is_excluded_path(uf):
                continue
            p = resolve_within_dir(repo_path, uf)
            if p is not None and p.exists() and p.is_file() and p.stat().st_size < 100_000:
                text = p.read_text(encoding="utf-8", errors="replace")
                lines = text.splitlines()
                body = "\n".join(f"+{ln}" for ln in lines)
                untracked_diffs.append(
                    f"diff --git a/{uf} b/{uf}\nnew file mode 100644\n--- /dev/null\n+++ b/{uf}\n@@ -0,0 +1,{len(lines)} @@\n{body}"
                )
        diff_text = "\n".join(part for part in (staged, unstaged, *untracked_diffs) if part.strip())
        base_commit = head_sha
        target_commit = "WORKING_TREE"
    else:
        safe_base_ref = validate_git_ref(base_ref)
        safe_target_ref = validate_git_ref(target_ref)
        base_commit = git_repo.git.rev_parse("--verify", safe_base_ref)
        target_commit = git_repo.git.rev_parse("--verify", safe_target_ref)
        diff_text = git_repo.git.diff(f"{base_commit}..{target_commit}")

    snapshots: dict[str, str] = {}
    for parsed in parse_unified_diff(diff_text):
        if is_excluded_path(parsed.path) or parsed.status == "deleted":
            continue
        fp = resolve_within_dir(repo_path, parsed.path)
        if fp is not None and fp.exists() and fp.is_file() and fp.stat().st_size < 120_000:
            if target_commit in ("WORKING_TREE", "STAGED", "UNSTAGED"):
                snapshots[parsed.path] = fp.read_text(encoding="utf-8", errors="replace")
            else:
                try:
                    snapshots[parsed.path] = git_repo.git.show(f"{target_commit}:{parsed.path}")
                except GitCommandError as exc:
                    logger.debug("Skipping snapshot for %s at %s: %s", parsed.path, target_commit, exc)

    return base_commit, target_commit, diff_text, snapshots


@router.get("")
async def list_repositories(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repos = (
        await db.execute(
            select(Repository).where(Repository.user_id == user.id).order_by(Repository.created_at.desc())
        )
    ).scalars().all()

    items = []
    for r in repos:
        rev_count = (
            await db.execute(select(func.count(Review.id)).where(Review.repository_id == r.id))
        ).scalar_one()
        latest_rev = (
            await db.execute(
                select(Review).where(Review.repository_id == r.id).order_by(Review.started_at.desc()).limit(1)
            )
        ).scalar_one_or_none()
        items.append(
            {
                "id": r.id,
                "source_type": r.source_type,
                "full_name": r.full_name,
                "owner": r.owner,
                "name": r.name,
                "description": r.description,
                "default_branch": r.default_branch,
                "html_url": r.html_url,
                "local_path": r.local_path,
                "is_private": r.is_private,
                "auto_review_webhooks": r.auto_review_webhooks,
                "last_synced_at": r.last_synced_at.isoformat() if r.last_synced_at else None,
                "review_count": rev_count,
                "latest_recommendation": latest_rev.recommendation if latest_rev else None,
                "latest_review_id": latest_rev.id if latest_rev else None,
            }
        )
    return {"repositories": items}


@router.post("/local")
async def connect_local_repository(
    payload: ConnectLocalRepoRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    resolved = Path(payload.local_path).expanduser().resolve()
    if not resolved.exists() or not (resolved / ".git").exists():
        raise HTTPException(status_code=400, detail=f"Not a valid Git repository: {resolved}")

    git_repo = GitRepo(str(resolved))
    try:
        active_branch = git_repo.active_branch.name
    except TypeError:
        active_branch = "HEAD"

    name = (payload.name or resolved.name).strip()
    full_name = f"local/{name}"
    existing = (
        await db.execute(
            select(Repository).where(
                Repository.user_id == user.id,
                Repository.source_type == "local",
                Repository.local_path == str(resolved),
            )
        )
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    if existing:
        existing.default_branch = active_branch
        existing.last_synced_at = now
        repo = existing
    else:
        repo = Repository(
            user_id=user.id,
            source_type="local",
            full_name=full_name,
            owner="local",
            name=name,
            description=f"Local Git repository at {resolved}",
            default_branch=active_branch,
            local_path=str(resolved),
            last_synced_at=now,
        )
        db.add(repo)
    await db.commit()
    await db.refresh(repo)

    detected_github_repo = None
    try:
        if git_repo.remotes:
            origin_url = git_repo.remotes.origin.url
            if "github.com" in origin_url.lower():
                detected_github_repo = parse_github_repo_input(origin_url)["full_name"]
    except (AttributeError, IndexError, ValueError) as exc:
        logger.debug("No parseable GitHub origin remote at %s: %s", resolved, exc)

    return {
        "repository": {
            "id": repo.id,
            "full_name": repo.full_name,
            "source_type": repo.source_type,
            "default_branch": repo.default_branch,
            "local_path": repo.local_path,
        },
        "detected_github_repo": detected_github_repo,
    }


@router.patch("/{repo_id}")
async def update_repository(
    repo_id: str,
    payload: UpdateRepositoryRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo = (
        await db.execute(
            select(Repository).where(Repository.id == repo_id, Repository.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    if payload.auto_review_webhooks is not None:
        repo.auto_review_webhooks = payload.auto_review_webhooks
    if payload.default_branch is not None and payload.default_branch.strip():
        try:
            repo.default_branch = validate_git_ref(payload.default_branch)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    await db.commit()
    return {
        "repository": {
            "id": repo.id,
            "auto_review_webhooks": repo.auto_review_webhooks,
            "default_branch": repo.default_branch,
        }
    }


@router.delete("/{repo_id}")
async def delete_repository(
    repo_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo = (
        await db.execute(
            select(Repository).where(Repository.id == repo_id, Repository.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    await db.delete(repo)
    await db.commit()
    return {"deleted": True}


@router.get("/{repo_id}/local-inspect")
async def inspect_local_repository(
    repo_id: str,
    mode: str = "working_tree",
    base_ref: str = "HEAD~1",
    target_ref: str = "HEAD",
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo = (
        await db.execute(
            select(Repository).where(Repository.id == repo_id, Repository.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not repo or repo.source_type != "local" or not repo.local_path:
        raise HTTPException(status_code=404, detail="Local repository not found")

    repo_path = Path(repo.local_path).resolve()
    if not (repo_path / ".git").exists():
        raise HTTPException(status_code=400, detail="Local repository path is no longer a Git repo")

    git_repo = GitRepo(str(repo_path))
    branches = [h.name for h in git_repo.heads]
    commits = [
        {
            "sha": c.hexsha,
            "message": c.message.strip().splitlines()[0] if c.message else "",
            "author": str(c.author),
            "date": c.committed_datetime.isoformat(),
        }
        for c in list(git_repo.iter_commits(max_count=20))
    ]
    try:
        base_commit, target_commit, diff_text, _ = _extract_local_git_diff(
            repo_path, mode=mode, base_ref=base_ref, target_ref=target_ref
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    parsed = parse_unified_diff(diff_text)
    return {
        "branches": branches,
        "commits": commits,
        "base_commit": base_commit,
        "target_commit": target_commit,
        "diff_text": diff_text,
        "changed_files": [p.to_dict() for p in parsed],
    }


@router.get("/companion/status")
async def check_local_companion_status(user: User = Depends(get_current_user)) -> dict:
    url = get_settings().local_companion_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{url}/health")
        return {"online": resp.status_code == 200, "url": url, "details": resp.json() if resp.status_code == 200 else {}}
    except (httpx.HTTPError, ValueError) as exc:
        return {"online": False, "url": url, "error": str(exc)}


@router.post("/companion/submit")
async def submit_from_local_companion(
    payload: CompanionSubmitRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    resolved = str(Path(payload.local_path).expanduser().resolve())
    repo = (
        await db.execute(
            select(Repository).where(
                Repository.user_id == user.id,
                Repository.source_type == "local",
                Repository.local_path == resolved,
            )
        )
    ).scalar_one_or_none()
    if not repo:
        repo = Repository(
            user_id=user.id,
            source_type="local",
            full_name=f"local/{payload.repository_name}",
            owner="local",
            name=payload.repository_name,
            description=f"Local companion repository at {resolved}",
            default_branch=payload.base_branch,
            local_path=resolved,
            last_synced_at=datetime.now(UTC),
        )
        db.add(repo)
        await db.flush()

    safe_snapshots = {
        k: v for k, v in payload.file_snapshots.items() if not is_excluded_path(k)
    }
    parsed = parse_unified_diff(payload.diff_text)
    cc = CodeChange(
        repository_id=repo.id,
        source_mode="local_diff",
        base_branch=payload.base_branch,
        target_branch=payload.target_branch,
        base_commit=payload.base_commit,
        target_commit=payload.target_commit,
        diff_text=payload.diff_text,
        changed_files=[p.to_dict() for p in parsed],
        file_snapshots=safe_snapshots,
    )
    db.add(cc)
    await db.flush()

    rev = Review(
        repository_id=repo.id,
        code_change_id=cc.id,
        triggered_by="local_companion",
        base_commit=payload.base_commit,
        target_commit=payload.target_commit,
        review_status="queued",
        recommendation="Pending",
    )
    db.add(rev)
    await db.flush()
    configs = await load_effective_agent_configs(db)
    await seed_agent_runs(db, rev.id, configs)
    await db.commit()
    launch_review_job(rev.id)
    return {"review_id": rev.id, "repository_id": repo.id, "status": "queued"}


@router.get("/{repo_id}/tree")
async def get_repository_tree(
    repo_id: str,
    ref: str | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo = (
        await db.execute(
            select(Repository).where(Repository.id == repo_id, Repository.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    target_ref = (ref or repo.default_branch or "main").strip()
    try:
        target_ref = validate_git_ref(target_ref)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if repo.source_type == "github":
        token = await resolve_github_token(user.id, db)
        gh = GitHubClient(token)
        try:
            branches_raw = await gh.list_branches(repo.owner, repo.name)
            branches = [b["name"] for b in branches_raw]
            if not ref and repo.default_branch not in branches and branches:
                target_ref = branches[0]
            tree_res = await gh.get_repo_tree(repo.owner, repo.name, target_ref)
            items = [
                {
                    "path": item["path"],
                    "type": "dir" if item.get("type") == "tree" else "file",
                    "size": item.get("size") or 0,
                    "sha": item.get("sha", ""),
                }
                for item in tree_res.get("tree", [])
                if item.get("path") and not is_excluded_path(item["path"])
            ]
            truncated = bool(tree_res.get("truncated", False))
        except GitHubAPIError as exc:
            # Fallback to local shallow Git mirror when REST API hits unauthenticated rate limits
            try:
                mirror_dir = await ensure_github_mirror(
                    repo.owner,
                    repo.name,
                    remote_url=repo.remote_url,
                    ref=target_ref,
                    github_token=token,
                )
            except (RuntimeError, OSError, GitCommandError, InvalidGitRepositoryError, ValueError) as m_exc:
                raise HTTPException(
                    status_code=exc.status_code,
                    detail=f"GitHub tree error: {exc.message} (Mirror fallback failed: {m_exc})",
                ) from m_exc
            git_mirror = GitRepo(str(mirror_dir))
            branches = [
                r_ref.name.replace("origin/", "")
                for r_ref in git_mirror.remotes.origin.refs
                if not r_ref.name.endswith("/HEAD")
            ] or [target_ref]
            ls_target = f"origin/{target_ref}" if f"origin/{target_ref}" in [r_ref.name for r_ref in git_mirror.remotes.origin.refs] else "HEAD"
            raw_tree = git_mirror.git.ls_tree("-r", "-l", ls_target)
            items = []
            for line in raw_tree.splitlines():
                meta, _, fpath = line.partition("\t")
                if not fpath or is_excluded_path(fpath):
                    continue
                parts = meta.split()
                obj_type = parts[1] if len(parts) > 1 else "blob"
                obj_sha = parts[2] if len(parts) > 2 else ""
                size_str = parts[3] if len(parts) > 3 else "0"
                items.append(
                    {
                        "path": fpath,
                        "type": "dir" if obj_type == "tree" else "file",
                        "size": int(size_str) if size_str.isdigit() else 0,
                        "sha": obj_sha,
                    }
                )
            truncated = False

        return {
            "repository": {
                "id": repo.id,
                "full_name": repo.full_name,
                "source_type": repo.source_type,
                "default_branch": repo.default_branch,
                "html_url": repo.html_url,
            },
            "ref": target_ref,
            "branches": branches,
            "truncated": truncated,
            "items": items,
        }

    # Local Git repository tree
    if not repo.local_path:
        raise HTTPException(status_code=400, detail="Local repository has no path")
    repo_path = Path(repo.local_path).resolve()
    if not (repo_path / ".git").exists():
        raise HTTPException(status_code=400, detail="Local repository path is no longer a Git repo")

    git_repo = GitRepo(str(repo_path))
    branches = [h.name for h in git_repo.heads]
    items: list[dict] = []
    if ref and ref != "WORKING_TREE":
        raw_tree = git_repo.git.ls_tree("-r", "-l", target_ref, "--")
        for line in raw_tree.splitlines():
            # <mode> <type> <sha> <size>\t<path>
            meta, _, fpath = line.partition("\t")
            if not fpath or is_excluded_path(fpath):
                continue
            parts = meta.split()
            obj_type = parts[1] if len(parts) > 1 else "blob"
            obj_sha = parts[2] if len(parts) > 2 else ""
            size_str = parts[3] if len(parts) > 3 else "0"
            items.append(
                {
                    "path": fpath,
                    "type": "dir" if obj_type == "tree" else "file",
                    "size": int(size_str) if size_str.isdigit() else 0,
                    "sha": obj_sha,
                }
            )
    else:
        target_ref = "WORKING_TREE"
        for p in sorted(repo_path.rglob("*")):
            if p.is_symlink():
                continue
            rel = str(p.relative_to(repo_path)).replace("\\", "/")
            if any(part in (".git", "node_modules", ".venv", "__pycache__", ".next") for part in p.parts):
                continue
            if is_excluded_path(rel):
                continue
            items.append(
                {
                    "path": rel,
                    "type": "dir" if p.is_dir() else "file",
                    "size": p.stat().st_size if p.is_file() else 0,
                    "sha": "",
                }
            )

    return {
        "repository": {
            "id": repo.id,
            "full_name": repo.full_name,
            "source_type": repo.source_type,
            "default_branch": repo.default_branch,
            "html_url": repo.html_url,
        },
        "ref": target_ref,
        "branches": ["WORKING_TREE", *branches],
        "truncated": False,
        "items": items,
    }


@router.get("/{repo_id}/file")
async def get_repository_file_content(
    repo_id: str,
    path: str,
    ref: str | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo = (
        await db.execute(
            select(Repository).where(Repository.id == repo_id, Repository.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    clean_path = path.replace("\\", "/").lstrip("/")
    if not clean_path or is_excluded_path(clean_path):
        raise HTTPException(status_code=403, detail="Access to this path is restricted")

    if repo.source_type == "github":
        try:
            target_ref = validate_git_ref((ref or repo.default_branch or "main").strip())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        token = await resolve_github_token(user.id, db)
        gh = GitHubClient(token)
        try:
            content, sha = await gh.get_file_content(repo.owner, repo.name, clean_path, target_ref)
        except GitHubAPIError as exc:
            # Fallback to local shallow Git mirror when REST API is rate-limited
            try:
                mirror_dir = await ensure_github_mirror(
                    repo.owner,
                    repo.name,
                    remote_url=repo.remote_url,
                    ref=target_ref,
                    github_token=token,
                )
                git_mirror = GitRepo(str(mirror_dir))
                show_ref = (
                    f"origin/{target_ref}"
                    if f"origin/{target_ref}" in [r_ref.name for r_ref in git_mirror.remotes.origin.refs]
                    else "HEAD"
                )
                content = git_mirror.git.show(f"{show_ref}:{clean_path}")
                sha = ""
            except (RuntimeError, OSError, GitCommandError, InvalidGitRepositoryError, ValueError):
                raise HTTPException(status_code=exc.status_code, detail=f"GitHub file error: {exc.message}")
        is_binary = "\x00" in content[:4096]
        return {
            "path": clean_path,
            "ref": target_ref,
            "sha": sha,
            "size": len(content.encode("utf-8")),
            "is_binary": is_binary,
            "content": "" if is_binary else content,
        }

    target_ref = (ref or "WORKING_TREE").strip()
    if target_ref != "WORKING_TREE":
        try:
            target_ref = validate_git_ref(target_ref)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    if not repo.local_path:
        raise HTTPException(status_code=400, detail="Local repository has no path")
    repo_path = Path(repo.local_path).resolve()
    if target_ref != "WORKING_TREE":
        git_repo = GitRepo(str(repo_path))
        try:
            content = git_repo.git.show(f"{target_ref}:{clean_path}")
        except (GitCommandError, InvalidGitRepositoryError) as exc:
            raise HTTPException(status_code=404, detail=f"File not found at {target_ref}: {exc}")
        is_binary = "\x00" in content[:4096]
        return {
            "path": clean_path,
            "ref": target_ref,
            "sha": "",
            "size": len(content.encode("utf-8")),
            "is_binary": is_binary,
            "content": "" if is_binary else content,
        }

    file_path = (repo_path / clean_path).resolve()
    if repo_path not in file_path.parents:
        raise HTTPException(status_code=403, detail="Path traversal blocked")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    raw_bytes = file_path.read_bytes()
    is_binary = b"\x00" in raw_bytes[:4096]
    content = "" if is_binary else raw_bytes.decode("utf-8", errors="replace")
    return {
        "path": clean_path,
        "ref": "WORKING_TREE",
        "sha": "",
        "size": len(raw_bytes),
        "is_binary": is_binary,
        "content": content,
    }

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from git import GitCommandError, InvalidGitRepositoryError
from git import Repo as GitRepo
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, resolve_github_token
from app.api.repositories import _extract_local_git_diff
from app.database.session import get_db
from app.integrations.github_client import GitHubAPIError, GitHubClient
from app.models.tables import (
    AgentRun,
    CodeChange,
    Finding,
    PatchSuggestion,
    Repository,
    Review,
    ReviewArtifact,
    User,
)
from app.orchestration.cancellation import cancel_review_execution
from app.orchestration.coordinator import (
    launch_review_job,
    load_effective_agent_configs,
    persist_review_stopped,
    seed_agent_runs,
)
from app.scanners.code_engines import CODE_EXTENSIONS, prioritize_repo_files
from app.scanners.git_diff_tool import parse_unified_diff
from app.services.git_workspace import ensure_github_mirror, is_excluded_path, resolve_within_dir

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reviews", tags=["reviews"])


def _build_full_repo_payload(
    snapshots: dict[str, str], ordered_paths: list[str], fallback_label: str
) -> tuple[str, list[dict[str, Any]]]:
    """Build synthetic unified diff and aligned changed_files list from loaded file snapshots."""
    populated = [fp for fp in ordered_paths if fp in snapshots]
    diff_chunks: list[str] = []
    changed_files: list[dict[str, Any]] = []
    for fp in populated:
        content = snapshots[fp]
        lines = content.splitlines()
        capped = min(len(lines), 600)
        body = "\n".join(f"+{ln}" for ln in lines[:capped])
        patch = (
            f"diff --git a/{fp} b/{fp}\n"
            f"new file mode 100644\n"
            f"--- /dev/null\n"
            f"+++ b/{fp}\n"
            f"@@ -0,0 +1,{capped} @@\n"
            f"{body}"
        )
        diff_chunks.append(patch)
        changed_files.append(
            {
                "path": fp,
                "status": "added",
                "additions": len(lines),
                "deletions": 0,
                "changed_lines": list(range(1, min(len(lines), 200) + 1)),
                "patch": patch,
            }
        )
    diff_text = "\n".join(diff_chunks) or (
        f"diff --git a/README.md b/README.md\n--- /dev/null\n+++ b/README.md\n@@ -0,0 +1,1 @@\n+{fallback_label}"
    )
    return diff_text, changed_files


class CreateReviewRequest(BaseModel):
    repository_id: str
    # GitHub PR mode
    pr_number: int | None = None
    # GitHub single-commit review mode
    commit_sha: str | None = None
    # GitHub / Local full codebase audit mode
    full_codebase: bool = False
    # GitHub compare / local commit range mode
    base_ref: str | None = None
    target_ref: str | None = None
    # Local mode: working_tree | staged | unstaged | commits
    local_mode: str = "working_tree"


def _review_summary_dict(r: Review, repo: Repository, cc: CodeChange | None) -> dict[str, Any]:
    return {
        "id": r.id,
        "repository_id": r.repository_id,
        "repository_name": repo.full_name,
        "source_type": repo.source_type,
        "triggered_by": r.triggered_by,
        "base_commit": r.base_commit,
        "target_commit": r.target_commit,
        "base_branch": cc.base_branch if cc else "",
        "target_branch": cc.target_branch if cc else "",
        "pr_number": cc.pr_number if cc else None,
        "pr_title": cc.pr_title if cc else None,
        "review_status": r.review_status,
        "recommendation": r.recommendation,
        "recommendation_reason": r.recommendation_reason,
        "diff_summary": r.diff_summary,
        "github_review_id": r.github_review_id,
        "github_published_at": r.github_published_at.isoformat() if r.github_published_at else None,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
    }


async def _create_and_start_review(
    *,
    repo: Repository,
    user: User,
    db: AsyncSession,
    pr_number: int | None = None,
    commit_sha: str | None = None,
    full_codebase: bool = False,
    base_ref: str | None = None,
    target_ref: str | None = None,
    local_mode: str = "working_tree",
    triggered_by: str = "manual",
) -> Review:
    snapshots: dict[str, str] = {}
    if repo.source_type == "github":
        token = await resolve_github_token(user.id, db)
        gh = GitHubClient(token)
        if full_codebase:
            branch = (target_ref or repo.default_branch or "main").strip()
            blob_paths: list[str] = []
            try:
                commits = await gh.list_commits(repo.owner, repo.name, sha=branch, per_page=1)
                head_sha = commits[0]["sha"] if commits else branch
                tree_res = await gh.get_repo_tree(repo.owner, repo.name, head_sha)
                raw_paths = [
                    item["path"]
                    for item in tree_res.get("tree", [])
                    if item.get("type") == "blob"
                    and item.get("path", "").endswith(CODE_EXTENSIONS)
                    and not is_excluded_path(item.get("path", ""))
                    and (item.get("size") or 0) < 120_000
                ]
                blob_paths = prioritize_repo_files(raw_paths)[:50]
                sem = asyncio.Semaphore(8)

                async def _fetch_blob(fp: str) -> None:
                    async with sem:
                        try:
                            content, _ = await gh.get_file_content(repo.owner, repo.name, fp, head_sha)
                            snapshots[fp] = content
                        except (GitHubAPIError, UnicodeDecodeError) as f_exc:
                            logger.debug("Skipping blob %s during full scan: %s", fp, f_exc)

                await asyncio.gather(*(_fetch_blob(fp) for fp in blob_paths))
            except GitHubAPIError as exc:
                try:
                    mirror_dir = await ensure_github_mirror(
                        repo.owner,
                        repo.name,
                        remote_url=repo.remote_url,
                        ref=branch,
                        github_token=token,
                    )
                except (RuntimeError, OSError, ValueError) as m_exc:
                    raise HTTPException(
                        status_code=exc.status_code, detail=f"{exc.message} (Mirror failed: {m_exc})"
                    ) from m_exc
                git_mirror = GitRepo(str(mirror_dir))
                head_sha = git_mirror.head.commit.hexsha
                raw_tree = git_mirror.git.ls_tree("-r", "--name-only", "HEAD")
                raw_paths = [
                    p
                    for p in raw_tree.splitlines()
                    if p.endswith(CODE_EXTENSIONS) and not is_excluded_path(p)
                ]
                blob_paths = prioritize_repo_files(raw_paths)[:50]
                for fp in blob_paths:
                    fp_full = resolve_within_dir(mirror_dir, fp)
                    if fp_full is not None and fp_full.exists() and fp_full.stat().st_size < 120_000:
                        snapshots[fp] = fp_full.read_text(encoding="utf-8", errors="replace")

            diff_text, changed_files = _build_full_repo_payload(
                snapshots, blob_paths, f"Full codebase audit at {head_sha}"
            )
            base_commit = "EMPTY_TREE"
            target_commit = head_sha
            base_branch = "empty"
            target_branch = branch
            pr_title = f"Full Codebase Audit ({branch})"
            pr_url = repo.html_url
            source_mode = "github_full_repo"
        elif pr_number is not None:
            try:
                pr = await gh.get_pull_request(repo.owner, repo.name, pr_number)
                diff_text, files = await gh.get_pull_request_diff(repo.owner, repo.name, pr_number)
            except GitHubAPIError as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.message)
            base_branch = pr["base"]["ref"]
            target_branch = pr["head"]["ref"]
            base_commit = pr["base"]["sha"]
            target_commit = pr["head"]["sha"]
            pr_title = pr.get("title")
            pr_url = pr.get("html_url")
            source_mode = "github_pr"
            parsed = parse_unified_diff(diff_text)
            changed_files = [p.to_dict() for p in parsed] if parsed else [
                {
                    "path": f["filename"],
                    "status": f.get("status", "modified"),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "changed_lines": [],
                    "patch": f.get("patch", ""),
                }
                for f in files
            ]
        elif commit_sha:
            try:
                c_data = await gh.get_commit_diff(repo.owner, repo.name, commit_sha.strip())
            except GitHubAPIError as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.message)
            diff_text = c_data["diff_text"]
            base_commit = c_data["base_commit"]
            target_commit = c_data["target_commit"]
            base_branch = base_commit[:8]
            target_branch = target_commit[:8]
            pr_title = c_data["message"].splitlines()[0] if c_data.get("message") else None
            pr_url = None
            source_mode = "github_commit"
            changed_files = [p.to_dict() for p in parse_unified_diff(diff_text)]
        else:
            b_ref = base_ref or repo.default_branch
            t_ref = target_ref or repo.default_branch
            try:
                cmp_data = await gh.compare_commits(repo.owner, repo.name, b_ref, t_ref)
            except GitHubAPIError as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.message)
            diff_text = cmp_data.get("diff_text", "")
            commits = cmp_data.get("commits", [])
            base_commit = (cmp_data.get("base_commit") or {}).get("sha", b_ref)
            target_commit = commits[-1]["sha"] if commits else (cmp_data.get("merge_base_commit") or {}).get("sha", t_ref)
            base_branch = b_ref
            target_branch = t_ref
            pr_title = None
            pr_url = None
            source_mode = "github_compare"
            changed_files = [p.to_dict() for p in parse_unified_diff(diff_text)]
    else:
        if not repo.local_path:
            raise HTTPException(status_code=400, detail="Local repository has no path")
        repo_path = Path(repo.local_path).resolve()
        if not (repo_path / ".git").exists():
            raise HTTPException(status_code=400, detail=f"Not a valid Git repository: {repo_path}")
        if full_codebase:
            try:
                git_repo = GitRepo(str(repo_path))
                head_sha = git_repo.head.commit.hexsha if git_repo.head.is_valid() else "WORKING_TREE"
            except (InvalidGitRepositoryError, GitCommandError, ValueError):
                head_sha = "WORKING_TREE"
            raw_paths: list[str] = []
            for p in repo_path.rglob("*"):
                if p.is_symlink() or not p.is_file():
                    continue
                if any(
                    part in (".git", "node_modules", ".venv", "__pycache__", ".next", "dist")
                    for part in p.parts
                ):
                    continue
                rel = str(p.relative_to(repo_path)).replace(os.sep, "/")
                if not rel.endswith(CODE_EXTENSIONS) or is_excluded_path(rel):
                    continue
                if p.stat().st_size < 120_000:
                    raw_paths.append(rel)
            blob_paths = prioritize_repo_files(raw_paths)[:50]
            for fp in blob_paths:
                fp_full = resolve_within_dir(repo_path, fp)
                if fp_full is not None and fp_full.exists():
                    snapshots[fp] = fp_full.read_text(encoding="utf-8", errors="replace")
            branch = (target_ref or repo.default_branch or "HEAD").strip()
            diff_text, changed_files = _build_full_repo_payload(
                snapshots, blob_paths, f"Local full codebase audit at {head_sha}"
            )
            base_commit = "EMPTY_TREE"
            target_commit = head_sha
            base_branch = "empty"
            target_branch = branch
            pr_title = f"Full Codebase Audit ({branch})"
            pr_url = None
            source_mode = "local_full_repo"
        else:
            b_ref = base_ref or "HEAD~1"
            t_ref = target_ref or "HEAD"
            base_commit, target_commit, diff_text, snapshots = _extract_local_git_diff(
                repo_path, mode=local_mode, base_ref=b_ref, target_ref=t_ref
            )
            base_branch = b_ref if local_mode == "commits" else repo.default_branch
            target_branch = t_ref if local_mode == "commits" else local_mode
            pr_title = None
            pr_url = None
            source_mode = "local_commits" if local_mode == "commits" else "local_diff"
            changed_files = [p.to_dict() for p in parse_unified_diff(diff_text)]

    if not diff_text.strip():
        raise HTTPException(
            status_code=400,
            detail="No code diff found between the selected refs/working tree.",
        )

    cc = CodeChange(
        repository_id=repo.id,
        source_mode=source_mode,
        pr_number=pr_number,
        pr_title=pr_title,
        pr_url=pr_url,
        base_branch=base_branch,
        target_branch=target_branch,
        base_commit=base_commit,
        target_commit=target_commit,
        diff_text=diff_text,
        changed_files=changed_files,
        file_snapshots=snapshots,
    )
    db.add(cc)
    await db.flush()

    rev = Review(
        repository_id=repo.id,
        code_change_id=cc.id,
        triggered_by=triggered_by,
        base_commit=base_commit,
        target_commit=target_commit,
        review_status="queued",
        recommendation="Pending",
    )
    db.add(rev)
    await db.flush()

    configs = await load_effective_agent_configs(db)
    await seed_agent_runs(db, rev.id, configs)

    await db.commit()
    await db.refresh(rev)
    launch_review_job(rev.id)
    return rev


@router.post("", status_code=status.HTTP_201_CREATED)
async def submit_review(
    payload: CreateReviewRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repo = (
        await db.execute(
            select(Repository).where(
                Repository.id == payload.repository_id, Repository.user_id == user.id
            )
        )
    ).scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    rev = await _create_and_start_review(
        repo=repo,
        user=user,
        db=db,
        pr_number=payload.pr_number,
        commit_sha=payload.commit_sha,
        full_codebase=payload.full_codebase,
        base_ref=payload.base_ref,
        target_ref=payload.target_ref,
        local_mode=payload.local_mode,
        triggered_by=f"manual:{user.email}",
    )
    return {"review_id": rev.id, "status": rev.review_status}


@router.get("")
async def list_reviews(
    repository_id: str | None = None,
    recommendation: str | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    stmt = (
        select(Review, Repository, CodeChange)
        .join(Repository, Review.repository_id == Repository.id)
        .join(CodeChange, Review.code_change_id == CodeChange.id)
        .where(Repository.user_id == user.id)
        .order_by(Review.started_at.desc())
    )
    if repository_id:
        stmt = stmt.where(Review.repository_id == repository_id)
    if recommendation:
        stmt = stmt.where(Review.recommendation == recommendation)

    rows = (await db.execute(stmt)).all()
    items = []
    for rev, repo, cc in rows:
        findings = (
            await db.execute(select(Finding).where(Finding.review_id == rev.id))
        ).scalars().all()
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            if f.severity in sev_counts:
                sev_counts[f.severity] += 1
        d = _review_summary_dict(rev, repo, cc)
        d["findings_count"] = len(findings)
        d["severity_counts"] = sev_counts
        items.append(d)
    return {"reviews": items}


@router.get("/{review_id}")
async def get_review_detail(
    review_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    row = (
        await db.execute(
            select(Review, Repository, CodeChange)
            .join(Repository, Review.repository_id == Repository.id)
            .join(CodeChange, Review.code_change_id == CodeChange.id)
            .where(Review.id == review_id, Repository.user_id == user.id)
        )
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Review not found")

    rev, repo, cc = row
    agent_runs = (
        await db.execute(select(AgentRun).where(AgentRun.review_id == rev.id))
    ).scalars().all()
    findings = (
        await db.execute(
            select(Finding).where(Finding.review_id == rev.id).order_by(Finding.priority_rank)
        )
    ).scalars().all()
    patches = (
        await db.execute(select(PatchSuggestion).where(PatchSuggestion.review_id == rev.id))
    ).scalars().all()
    artifacts = (
        await db.execute(select(ReviewArtifact).where(ReviewArtifact.review_id == rev.id))
    ).scalars().all()

    return {
        "review": _review_summary_dict(rev, repo, cc),
        "code_change": {
            "id": cc.id,
            "source_mode": cc.source_mode,
            "pr_number": cc.pr_number,
            "pr_title": cc.pr_title,
            "pr_url": cc.pr_url,
            "base_branch": cc.base_branch,
            "target_branch": cc.target_branch,
            "base_commit": cc.base_commit,
            "target_commit": cc.target_commit,
            "diff_text": cc.diff_text,
            "changed_files": cc.changed_files,
            "file_snapshots": cc.file_snapshots,
        },
        "agent_runs": [
            {
                "id": a.id,
                "agent_name": a.agent_name,
                "agent_label": a.agent_label,
                "model_used": a.model_used,
                "status": a.status,
                "summary": a.summary,
                "tool_results": a.tool_results,
                "error_message": a.error_message,
                "duration_ms": a.duration_ms,
                "started_at": a.started_at.isoformat() if a.started_at else None,
                "completed_at": a.completed_at.isoformat() if a.completed_at else None,
            }
            for a in agent_runs
        ],
        "findings": [
            {
                "id": f.id,
                "agent": f.agent,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "end_line": f.end_line,
                "evidence": f.evidence,
                "tool_name": f.tool_name,
                "rule_id": f.rule_id,
                "recommendation": f.recommendation,
                "verification_status": f.verification_status,
                "deduplicated_sources": f.deduplicated_sources,
                "priority_rank": f.priority_rank,
                "is_blocking": f.is_blocking,
            }
            for f in findings
        ],
        "patch_suggestions": [
            {
                "id": p.id,
                "finding_id": p.finding_id,
                "file_path": p.file_path,
                "title": p.title,
                "original_code": p.original_code,
                "proposed_code": p.proposed_code,
                "unified_diff": p.unified_diff,
                "explanation": p.explanation,
                "applicability_verified": p.applicability_verified,
                "validation_output": p.validation_output,
                "approval_status": p.approval_status,
                "applied_ref": p.applied_ref,
                "decided_by": p.decided_by,
                "decided_at": p.decided_at.isoformat() if p.decided_at else None,
            }
            for p in patches
        ],
        "artifacts": [
            {
                "id": art.id,
                "artifact_type": art.artifact_type,
                "title": art.title,
                "content_type": art.content_type,
                "content": art.content,
            }
            for art in artifacts
        ],
        "shared_state": rev.shared_state_json,
    }


@router.post("/{review_id}/rerun", status_code=status.HTTP_201_CREATED)
async def rerun_review(
    review_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    row = (
        await db.execute(
            select(Review, Repository, CodeChange)
            .join(Repository, Review.repository_id == Repository.id)
            .join(CodeChange, Review.code_change_id == CodeChange.id)
            .where(Review.id == review_id, Repository.user_id == user.id)
        )
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Review not found")
    _, repo, cc = row

    local_mode = (
        cc.target_branch
        if cc.target_branch in ("working_tree", "staged", "unstaged", "commits")
        else ("commits" if cc.source_mode == "local_commits" else "working_tree")
    )
    new_rev = await _create_and_start_review(
        repo=repo,
        user=user,
        db=db,
        pr_number=cc.pr_number,
        commit_sha=cc.target_commit if cc.source_mode == "github_commit" else None,
        full_codebase=cc.source_mode in ("github_full_repo", "local_full_repo"),
        base_ref=cc.base_branch,
        target_ref=cc.target_branch,
        local_mode=local_mode,
        triggered_by=f"rerun:{review_id[:8]}",
    )
    return {"review_id": new_rev.id, "status": new_rev.review_status}


@router.post("/{review_id}/stop")
async def stop_review(
    review_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    row = (
        await db.execute(
            select(Review, Repository)
            .join(Repository, Review.repository_id == Repository.id)
            .where(Review.id == review_id, Repository.user_id == user.id)
        )
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Review not found")

    await cancel_review_execution(review_id)
    result = await persist_review_stopped(review_id)
    return result


@router.delete("/{review_id}")
async def delete_review(
    review_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Leave and discard a review task (cancelling first if still active) cleanly from the database."""
    row = (
        await db.execute(
            select(Review, Repository)
            .join(Repository, Review.repository_id == Repository.id)
            .where(Review.id == review_id, Repository.user_id == user.id)
        )
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Review not found")

    rev, _ = row
    cc_id = rev.code_change_id
    await cancel_review_execution(review_id)
    await db.delete(rev)
    await db.flush()

    remaining_refs = (
        await db.execute(select(func.count(Review.id)).where(Review.code_change_id == cc_id))
    ).scalar_one()
    if remaining_refs == 0:
        cc = (await db.execute(select(CodeChange).where(CodeChange.id == cc_id))).scalar_one_or_none()
        if cc is not None:
            await db.delete(cc)

    await db.commit()
    return {"deleted": True, "review_id": review_id}


@router.get("/{review_id}/report")
async def download_review_report(
    review_id: str,
    format: str = "markdown",
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    row = (
        await db.execute(
            select(Review, Repository)
            .join(Repository, Review.repository_id == Repository.id)
            .where(Review.id == review_id, Repository.user_id == user.id)
        )
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Review not found")

    art_type = "consolidated_report_json" if format == "json" else "consolidated_report_md"
    art = (
        await db.execute(
            select(ReviewArtifact).where(
                ReviewArtifact.review_id == review_id,
                ReviewArtifact.artifact_type == art_type,
            )
        )
    ).scalar_one_or_none()
    if not art:
        raise HTTPException(status_code=404, detail="Report artifact not generated yet")

    ext = "json" if format == "json" else "md"
    return Response(
        content=art.content,
        media_type=art.content_type,
        headers={"Content-Disposition": f'attachment; filename="review-{review_id[:8]}.{ext}"'},
    )

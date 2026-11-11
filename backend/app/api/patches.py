from __future__ import annotations

import difflib
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, resolve_github_token
from app.database.session import get_db
from app.integrations.github_client import GitHubAPIError, GitHubClient
from app.models.tables import CodeChange, Finding, PatchSuggestion, Repository, Review, User
from app.services.git_workspace import apply_patch_to_local_repo, is_excluded_path

router = APIRouter(prefix="/api/patches", tags=["patches"])


def _extract_suggestion_hunk(
    original: str, proposed: str, fallback_line: int
) -> tuple[int | None, int, str]:
    """Compute a bounded GitHub PR suggestion replacement hunk instead of dumping the full file."""
    orig_lines = original.splitlines()
    prop_lines = proposed.splitlines()
    matcher = difflib.SequenceMatcher(a=orig_lines, b=prop_lines)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag == "insert":
            anchor = max(1, i1)
            prefix = [orig_lines[anchor - 1]] if orig_lines and i1 > 0 else []
            suffix = [orig_lines[0]] if orig_lines and i1 == 0 else []
            replacement = "\n".join(prefix + prop_lines[j1:j2] + suffix)
            return None, anchor, replacement
        start_line = i1 + 1
        end_line = max(start_line, i2)
        replacement = "\n".join(prop_lines[j1:j2])
        return (start_line if end_line > start_line else None), end_line, replacement
    return None, max(1, fallback_line), proposed


class PatchDecisionRequest(BaseModel):
    action: Literal[
        "approve",
        "reject",
        "apply_local",
        "publish_github_suggestion",
        "commit_to_github_branch",
    ]
    note: str | None = None


class BatchCommitGitHubRequest(BaseModel):
    patch_ids: list[str] | None = None
    review_id: str | None = None
    note: str | None = None


def _resolve_target_branch(repo: Repository, cc: CodeChange) -> str:
    """Resolve a writable branch name for GitHub Contents API updates."""
    if cc.source_mode in ("github_commit", "github_full_repo") or not cc.target_branch:
        return repo.default_branch
    return cc.target_branch


async def _commit_patch_to_github(
    *,
    patch: PatchSuggestion,
    repo: Repository,
    cc: CodeChange,
    gh: GitHubClient,
    actor_email: str,
    now: datetime,
) -> tuple[str | None, str]:
    """Commit a single patch's complete proposed_code safely onto the target GitHub branch."""
    if is_excluded_path(patch.file_path):
        raise HTTPException(status_code=403, detail="Cannot commit patch to restricted file path")
    if repo.source_type != "github":
        raise HTTPException(status_code=400, detail="GitHub repository required")

    branch = _resolve_target_branch(repo, cc)
    current_content, file_sha = await gh.get_file_content(
        repo.owner, repo.name, patch.file_path, branch
    )
    if (
        current_content != patch.original_code
        and current_content != patch.proposed_code
    ):
        raise HTTPException(
            status_code=409,
            detail=f"Target branch '{branch}' modified '{patch.file_path}' since this review ran. Re-run review before committing.",
        )

    commit_resp = await gh.commit_file_update(
        repo.owner,
        repo.name,
        path=patch.file_path,
        branch=branch,
        message=f"fix(swarm): {patch.title}",
        new_content=patch.proposed_code,
        file_sha=file_sha,
    )
    commit_sha = (commit_resp.get("commit") or {}).get("sha")
    patch.approval_status = "applied"
    patch.applied_ref = commit_sha
    patch.decided_by = actor_email
    patch.decided_at = now
    return commit_sha, branch


@router.get("")
async def list_patches(
    review_id: str | None = None,
    approval_status: str | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    stmt = (
        select(PatchSuggestion, Review, Repository)
        .join(Review, PatchSuggestion.review_id == Review.id)
        .join(Repository, Review.repository_id == Repository.id)
        .where(Repository.user_id == user.id)
        .order_by(PatchSuggestion.created_at.desc())
    )
    if review_id:
        stmt = stmt.where(PatchSuggestion.review_id == review_id)
    if approval_status:
        stmt = stmt.where(PatchSuggestion.approval_status == approval_status)

    rows = (await db.execute(stmt)).all()
    return {
        "patches": [
            {
                "id": p.id,
                "review_id": p.review_id,
                "repository_id": repo.id,
                "repository_name": repo.full_name,
                "source_type": repo.source_type,
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
                "decision_note": p.decision_note,
                "decided_by": p.decided_by,
                "decided_at": p.decided_at.isoformat() if p.decided_at else None,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p, rev, repo in rows
        ]
    }


@router.post("/commit-all-github")
async def commit_all_patches_to_github(
    payload: BatchCommitGitHubRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Approve and commit all pending/approved GitHub patches cleanly in batch."""
    stmt = (
        select(PatchSuggestion, Review, Repository, CodeChange)
        .join(Review, PatchSuggestion.review_id == Review.id)
        .join(Repository, Review.repository_id == Repository.id)
        .join(CodeChange, Review.code_change_id == CodeChange.id)
        .where(
            Repository.user_id == user.id,
            Repository.source_type == "github",
            PatchSuggestion.approval_status.in_(["pending_approval", "approved"]),
        )
        .order_by(PatchSuggestion.created_at.desc())
    )
    if payload.patch_ids:
        stmt = stmt.where(PatchSuggestion.id.in_(payload.patch_ids))
    if payload.review_id:
        stmt = stmt.where(PatchSuggestion.review_id == payload.review_id)

    rows = (await db.execute(stmt)).all()
    if not rows:
        raise HTTPException(
            status_code=400,
            detail="No pending or approved GitHub patches found to commit.",
        )

    token = await resolve_github_token(user.id, db)
    if not token:
        raise HTTPException(status_code=400, detail="No GitHub token connected")
    gh = GitHubClient(token)

    now = datetime.now(UTC)
    committed: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    seen_targets: set[tuple[str, str, str]] = set()

    for patch, _rev, repo, cc in rows:
        branch = _resolve_target_branch(repo, cc)
        target_key = (repo.id, branch, patch.file_path)
        if target_key in seen_targets:
            skipped.append(
                {
                    "patch_id": patch.id,
                    "title": patch.title,
                    "file_path": patch.file_path,
                    "reason": "Skipped older patch targeting the same file in this batch.",
                }
            )
            continue
        seen_targets.add(target_key)

        try:
            commit_sha, target_branch = await _commit_patch_to_github(
                patch=patch,
                repo=repo,
                cc=cc,
                gh=gh,
                actor_email=user.email,
                now=now,
            )
            if payload.note is not None:
                patch.decision_note = payload.note
            committed.append(
                {
                    "patch_id": patch.id,
                    "title": patch.title,
                    "file_path": patch.file_path,
                    "repository_name": repo.full_name,
                    "branch": target_branch,
                    "commit_sha": commit_sha,
                }
            )
        except HTTPException as exc:
            errors.append(
                {
                    "patch_id": patch.id,
                    "title": patch.title,
                    "file_path": patch.file_path,
                    "detail": str(exc.detail),
                }
            )
        except GitHubAPIError as exc:
            errors.append(
                {
                    "patch_id": patch.id,
                    "title": patch.title,
                    "file_path": patch.file_path,
                    "detail": exc.message,
                }
            )

    if committed:
        await db.commit()

    return {
        "committed_count": len(committed),
        "skipped_count": len(skipped),
        "failed_count": len(errors),
        "committed": committed,
        "skipped": skipped,
        "errors": errors,
    }


@router.post("/{patch_id}/decision")
async def decide_patch(
    patch_id: str,
    payload: PatchDecisionRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    row = (
        await db.execute(
            select(PatchSuggestion, Review, Repository, CodeChange)
            .join(Review, PatchSuggestion.review_id == Review.id)
            .join(Repository, Review.repository_id == Repository.id)
            .join(CodeChange, Review.code_change_id == CodeChange.id)
            .where(PatchSuggestion.id == patch_id, Repository.user_id == user.id)
        )
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Patch suggestion not found")

    patch, rev, repo, cc = row
    now = datetime.now(UTC)
    result_info: dict = {}

    if payload.action == "approve":
        patch.approval_status = "approved"
    elif payload.action == "reject":
        patch.approval_status = "rejected"
    elif payload.action == "apply_local":
        if is_excluded_path(patch.file_path):
            raise HTTPException(status_code=403, detail="Cannot apply patch to restricted file path")
        if repo.source_type != "local" or not repo.local_path:
            raise HTTPException(status_code=400, detail="Patch belongs to a non-local repository")
        ok, msg = await apply_patch_to_local_repo(repo.local_path, patch.unified_diff)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        patch.approval_status = "applied"
        patch.applied_ref = f"local:{repo.local_path}"
        result_info["apply_message"] = msg
    elif payload.action == "publish_github_suggestion":
        if repo.source_type != "github" or not cc.pr_number:
            raise HTTPException(status_code=400, detail="GitHub Pull Request required for PR suggestion comment")
        token = await resolve_github_token(user.id, db)
        if not token:
            raise HTTPException(status_code=400, detail="No GitHub token connected")
        gh = GitHubClient(token)
        finding = (
            await db.execute(select(Finding).where(Finding.id == patch.finding_id))
        ).scalar_one_or_none()
        target_line = (finding.line_number if finding and finding.line_number else 1)
        start_line, end_line, suggestion_snippet = _extract_suggestion_hunk(
            patch.original_code, patch.proposed_code, target_line
        )
        try:
            comment = await gh.create_pr_comment_suggestion(
                repo.owner,
                repo.name,
                cc.pr_number,
                commit_id=rev.target_commit,
                path=patch.file_path,
                line=end_line,
                start_line=start_line,
                suggestion_code=suggestion_snippet,
                explanation=patch.explanation,
            )
            patch.approval_status = "approved"
            patch.applied_ref = comment.get("html_url")
            result_info["comment_url"] = comment.get("html_url")
        except GitHubAPIError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)
    elif payload.action == "commit_to_github_branch":
        token = await resolve_github_token(user.id, db)
        if not token:
            raise HTTPException(status_code=400, detail="No GitHub token connected")
        gh = GitHubClient(token)
        try:
            commit_sha, _branch = await _commit_patch_to_github(
                patch=patch,
                repo=repo,
                cc=cc,
                gh=gh,
                actor_email=user.email,
                now=now,
            )
            result_info["commit_sha"] = commit_sha
        except GitHubAPIError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)

    patch.decision_note = payload.note
    patch.decided_by = user.email
    patch.decided_at = now
    await db.commit()
    await db.refresh(patch)

    return {
        "patch": {
            "id": patch.id,
            "approval_status": patch.approval_status,
            "applied_ref": patch.applied_ref,
            "decided_by": patch.decided_by,
            "decided_at": patch.decided_at.isoformat() if patch.decided_at else None,
        },
        **result_info,
    }

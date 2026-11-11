from __future__ import annotations

from datetime import datetime, timezone
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


class PatchDecisionRequest(BaseModel):
    action: Literal[
        "approve",
        "reject",
        "apply_local",
        "publish_github_suggestion",
        "commit_to_github_branch",
    ]
    note: str | None = None


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
    now = datetime.now(timezone.utc)
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
        try:
            comment = await gh.create_pr_comment_suggestion(
                repo.owner,
                repo.name,
                cc.pr_number,
                commit_id=rev.target_commit,
                path=patch.file_path,
                line=target_line,
                suggestion_code=patch.proposed_code,
                explanation=patch.explanation,
            )
            patch.approval_status = "approved"
            patch.applied_ref = comment.get("html_url")
            result_info["comment_url"] = comment.get("html_url")
        except GitHubAPIError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)
    elif payload.action == "commit_to_github_branch":
        if is_excluded_path(patch.file_path):
            raise HTTPException(status_code=403, detail="Cannot commit patch to restricted file path")
        if repo.source_type != "github":
            raise HTTPException(status_code=400, detail="GitHub repository required")
        token = await resolve_github_token(user.id, db)
        if not token:
            raise HTTPException(status_code=400, detail="No GitHub token connected")
        gh = GitHubClient(token)
        # Specific-commit reviews set cc.target_branch = sha[:8], which is not a writable branch name.
        branch = (
            repo.default_branch
            if cc.source_mode in ("github_commit", "github_full_repo") or not cc.target_branch
            else cc.target_branch
        )
        try:
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

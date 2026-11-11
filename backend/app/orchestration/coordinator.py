from __future__ import annotations

import asyncio
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import AGENT_METADATA, get_settings
from app.database.session import async_session_maker
from app.integrations.github_client import GitHubClient
from app.models.tables import (
    AgentLLMConfig,
    AgentRun,
    CodeChange,
    ConnectedAccount,
    Finding,
    PatchSuggestion,
    Repository,
    Review,
    ReviewArtifact,
    ReviewPolicy,
)
from app.orchestration.cancellation import (
    ReviewCancelledError,
    clear_review_cancelled,
    is_review_cancelled,
    register_review_task,
    review_id_var,
)
from app.orchestration.fanout_fanin import build_review_workflow
from app.orchestration.shared_state import AgentExecutionConfig, ReviewState
from app.services.crypto import decrypt_secret
from app.services.git_workspace import prepare_review_workspace
from app.services.websocket_manager import ws_manager

_ACTIVE_TASKS: set[asyncio.Task[Any]] = set()


async def persist_review_stopped(review_id: str) -> dict[str, Any]:
    """Persist stopped status for a review and any unfinished agent runs, then notify WebSocket clients."""
    now = datetime.now(timezone.utc)
    async with async_session_maker() as db:
        rev = (await db.execute(select(Review).where(Review.id == review_id))).scalar_one_or_none()
        if not rev:
            return {"review_id": review_id, "status": "not_found", "stopped": False}
        if rev.review_status in ("completed", "failed"):
            return {"review_id": review_id, "status": rev.review_status, "stopped": False}

        rev.review_status = "stopped"
        if rev.recommendation == "Pending":
            rev.recommendation = "Incomplete"
        rev.recommendation_reason = "Stopped by user before completion."
        rev.completed_at = rev.completed_at or now

        runs = (await db.execute(select(AgentRun).where(AgentRun.review_id == review_id))).scalars().all()
        for ar in runs:
            if ar.status in ("queued", "running"):
                ar.status = "stopped"
                ar.error_message = "Stopped by user"
                ar.completed_at = ar.completed_at or now
        await db.commit()

    await ws_manager.emit(
        review_id,
        "review_stopped",
        {
            "review_id": review_id,
            "status": "stopped",
            "reason": "Stopped by user before completion.",
        },
    )
    return {"review_id": review_id, "status": "stopped", "stopped": True}


async def load_effective_agent_configs(db: AsyncSession) -> dict[str, AgentExecutionConfig]:
    settings = get_settings()
    rows_res = await db.execute(select(AgentLLMConfig))
    db_configs = {row.agent_name: row for row in rows_res.scalars().all()}

    resolved: dict[str, AgentExecutionConfig] = {}
    for agent_name, meta in AGENT_METADATA.items():
        env_cfg = settings.get_env_agent_config(agent_name)
        row = db_configs.get(agent_name)
        model = row.model if row and row.model else env_cfg["model"]
        base_url = row.base_url if row and row.base_url else env_cfg["base_url"]
        db_key = decrypt_secret(row.encrypted_api_key) if row and row.encrypted_api_key else ""
        api_key = db_key or env_cfg["api_key"]
        temp = float(row.temperature) if row and row.temperature else 0.1
        resolved[agent_name] = AgentExecutionConfig(
            agent_name=agent_name,
            label=meta["label"],
            model=model,
            base_url=base_url,
            api_key=api_key,
            temperature=temp,
        )
    return resolved


async def _load_policy(db: AsyncSession) -> dict[str, Any]:
    res = await db.execute(select(ReviewPolicy).where(ReviewPolicy.name == "default"))
    policy = res.scalar_one_or_none()
    if not policy:
        policy = ReviewPolicy(name="default")
        db.add(policy)
        await db.commit()
        await db.refresh(policy)
    return {
        "block_on_critical": policy.block_on_critical,
        "block_on_high": policy.block_on_high,
        "require_tests_pass": policy.require_tests_pass,
        "require_all_mandatory_scans": policy.require_all_mandatory_scans,
        "enable_test_execution": policy.enable_test_execution,
        "auto_publish_github_review": policy.auto_publish_github_review,
        "excluded_paths": list(policy.excluded_paths or []),
    }


def _build_markdown_report(review: Review, repo: Repository, state: ReviewState) -> str:
    lines = [
        "# Swarm Automated Code Review Report",
        f"- **Repository:** `{repo.full_name}` ({repo.source_type})",
        f"- **Review ID:** `{review.id}`",
        f"- **Commits:** `{review.base_commit[:12]}` -> `{review.target_commit[:12]}`",
        f"- **Recommendation:** **{state.recommendation}**",
        f"- **Reason:** {state.recommendation_reason}",
        "",
        "## Diff Summary",
        state.diff_summary or "No summary produced.",
        "",
        f"## Consolidated Findings ({len(state.findings)})",
    ]
    if not state.findings:
        lines.append("No findings reported.")
    for idx, f in enumerate(state.findings, start=1):
        lines.extend(
            [
                f"### {idx}. [{f.get('severity')}] {f.get('title')} ({f.get('verification_status')})",
                f"- **Location:** `{f.get('file_path')}:{f.get('line_number') or 1}`",
                f"- **Sources:** {', '.join(f.get('deduplicated_sources') or [f.get('agent', 'Agent')])}",
                f"- **Evidence:** `{f.get('evidence', '')[:240]}`",
                f"- **Recommendation:** {f.get('recommendation', '')}",
                "",
            ]
        )
    if state.patch_proposals:
        lines.append(f"## Proposed Fixes ({len(state.patch_proposals)})")
        for p in state.patch_proposals:
            lines.extend(
                [
                    f"### {p.get('title')} (`{p.get('file_path')}`)",
                    f"- **Patch & Syntax Validation:** {'Verified' if p.get('applicability_verified') else 'Needs review'} ({p.get('validation_output', '')})",
                    f"- **Explanation:** {p.get('explanation')}",
                    "```diff",
                    p.get("unified_diff", ""),
                    "```",
                    "",
                ]
            )
    rm_tr = (state.agent_results.get("reviewer_manager") or {}).get("tool_results") or {}
    rejected_fps = rm_tr.get("rejected_false_positives") or []
    if rejected_fps:
        lines.append(f"## Filtered False Positives ({len(rejected_fps)})")
        for rfp in rejected_fps[:10]:
            lines.append(f"- **Rejected:** `{rfp.get('title')}` (`{rfp.get('file_path') or 'repo'}`) — {rfp.get('reason')}")
        lines.append("")
    return "\n".join(lines)


class ReviewCoordinator:
    """Prepares isolated review workspace, runs 6-agent workflow, and persists structured results."""

    @staticmethod
    async def execute_review(review_id: str) -> None:
        async with async_session_maker() as db:
            rev_res = await db.execute(select(Review).where(Review.id == review_id))
            review = rev_res.scalar_one_or_none()
            if not review or is_review_cancelled(review_id) or review.review_status == "stopped":
                return

            repo_res = await db.execute(select(Repository).where(Repository.id == review.repository_id))
            repo = repo_res.scalar_one_or_none()
            cc_res = await db.execute(select(CodeChange).where(CodeChange.id == review.code_change_id))
            code_change = cc_res.scalar_one_or_none()
            if not repo or not code_change:
                return

            review.review_status = "running"
            review.started_at = datetime.now(timezone.utc)
            await db.commit()

            await ws_manager.emit(
                review_id,
                "review_started",
                {
                    "repository_id": repo.id,
                    "repository_name": repo.full_name,
                    "base_commit": review.base_commit,
                    "target_commit": review.target_commit,
                },
            )

            ctx_token = review_id_var.set(review_id)
            workspace_dir: Path | None = None
            try:
                if is_review_cancelled(review_id):
                    raise ReviewCancelledError("Stopped by user")

                agent_configs = await load_effective_agent_configs(db)
                policy = await _load_policy(db)

                # Resolve GitHub token if repository is GitHub-backed
                github_token = get_settings().github_token.strip()
                if repo.source_type == "github":
                    acct_res = await db.execute(
                        select(ConnectedAccount)
                        .where(ConnectedAccount.user_id == repo.user_id, ConnectedAccount.provider == "github")
                        .order_by(ConnectedAccount.updated_at.desc())
                    )
                    acct = acct_res.scalars().first()
                    if acct and acct.encrypted_access_token:
                        decrypted = decrypt_secret(acct.encrypted_access_token)
                        if decrypted:
                            github_token = decrypted

                workspace_dir = await prepare_review_workspace(
                    review_id=review_id,
                    source_type=repo.source_type,
                    remote_url=repo.remote_url,
                    local_path=repo.local_path,
                    base_commit=code_change.base_commit,
                    target_commit=code_change.target_commit,
                    diff_text=code_change.diff_text,
                    file_snapshots=code_change.file_snapshots or {},
                    github_token=github_token,
                    excluded_patterns=policy.get("excluded_paths", []),
                )

                initial_state = ReviewState(
                    review_id=review_id,
                    repository_id=repo.id,
                    repository_name=repo.full_name,
                    source_type=repo.source_type,
                    base_commit=code_change.base_commit,
                    target_commit=code_change.target_commit,
                    workspace_dir=workspace_dir,
                    diff_text=code_change.diff_text,
                    changed_files=list(code_change.changed_files or []),
                    policy=policy,
                    agent_configs=agent_configs,
                )

                async def emit_and_persist(rid: str, event_type: str, payload: dict[str, Any]) -> None:
                    if is_review_cancelled(rid):
                        return
                    await ws_manager.emit(rid, event_type, payload)
                    agent_name = payload.get("agent_name")
                    if not agent_name:
                        return
                    try:
                        async with async_session_maker() as ev_db:
                            ar = (
                                await ev_db.execute(
                                    select(AgentRun).where(
                                        AgentRun.review_id == rid,
                                        AgentRun.agent_name == agent_name,
                                    )
                                )
                            ).scalar_one_or_none()
                            if ar:
                                if event_type in ("agent_started", "fan_in_started"):
                                    ar.status = "running"
                                    ar.started_at = datetime.now(timezone.utc)
                                elif event_type == "agent_progress":
                                    ar.status = "running"
                                    if payload.get("message"):
                                        ar.summary = str(payload["message"])
                                elif event_type in (
                                    "agent_completed",
                                    "reviewer_manager_completed",
                                    "fix_suggestion_completed",
                                ):
                                    ar.status = str(payload.get("status") or "completed")
                                    if payload.get("summary"):
                                        ar.summary = str(payload["summary"])
                                    elif payload.get("reason"):
                                        ar.summary = str(payload["reason"])
                                    if payload.get("duration_ms") is not None:
                                        ar.duration_ms = int(payload["duration_ms"])
                                    ar.completed_at = datetime.now(timezone.utc)
                                elif event_type == "agent_failed":
                                    ar.status = str(payload.get("status") or "failed")
                                    if payload.get("error"):
                                        ar.error_message = str(payload["error"])
                                    if payload.get("duration_ms") is not None:
                                        ar.duration_ms = int(payload["duration_ms"])
                                    ar.completed_at = datetime.now(timezone.utc)
                                await ev_db.commit()
                    except Exception:
                        pass

                workflow = build_review_workflow(emit_and_persist)
                wf_result = await asyncio.wait_for(workflow.run(initial_state), timeout=240.0)
                if is_review_cancelled(review_id):
                    raise ReviewCancelledError("Stopped by user")
                outputs = wf_result.get_outputs()
                final_state: ReviewState = outputs[-1] if outputs else initial_state

                # Persist all 6 AgentRun records cleanly
                await db.execute(delete(AgentRun).where(AgentRun.review_id == review_id))
                await db.execute(delete(Finding).where(Finding.review_id == review_id))
                await db.execute(delete(PatchSuggestion).where(PatchSuggestion.review_id == review_id))
                await db.execute(delete(ReviewArtifact).where(ReviewArtifact.review_id == review_id))

                for agent_key in AGENT_METADATA:
                    res = final_state.agent_results.get(agent_key)
                    if not res:
                        continue
                    db.add(
                        AgentRun(
                            review_id=review_id,
                            agent_name=res["agent_name"],
                            agent_label=res["agent_label"],
                            model_used=res["model_used"],
                            status=res["status"],
                            summary=res.get("summary", ""),
                            tool_results=res.get("tool_results", {}),
                            raw_output=res.get("raw_output", {}),
                            error_message=res.get("error_message"),
                            duration_ms=int(res.get("duration_ms", 0)),
                            completed_at=datetime.now(timezone.utc),
                        )
                    )

                persisted_findings: list[Finding] = []
                for f in final_state.findings:
                    finding_row = Finding(
                        review_id=review_id,
                        agent=str(f.get("agent") or "Reviewer Manager"),
                        category=str(f.get("category") or "general"),
                        severity=str(f.get("severity") or "Medium"),
                        title=str(f.get("title") or "Finding")[:300],
                        description=str(f.get("description") or ""),
                        file_path=str(f.get("file_path") or ""),
                        line_number=f.get("line_number"),
                        end_line=f.get("end_line"),
                        evidence=str(f.get("evidence") or ""),
                        tool_name=f.get("tool_name"),
                        rule_id=f.get("rule_id"),
                        recommendation=str(f.get("recommendation") or ""),
                        verification_status=str(f.get("verification_status") or "Needs Verification"),
                        deduplicated_sources=list(f.get("deduplicated_sources") or []),
                        priority_rank=int(f.get("priority_rank") or 100),
                        is_blocking=bool(f.get("is_blocking", False)),
                    )
                    db.add(finding_row)
                    persisted_findings.append(finding_row)

                await db.flush()

                for p in final_state.patch_proposals:
                    f_idx = int(p.get("finding_index", 0))
                    linked_finding_id = (
                        persisted_findings[f_idx].id
                        if 0 <= f_idx < len(persisted_findings)
                        else None
                    )
                    db.add(
                        PatchSuggestion(
                            review_id=review_id,
                            finding_id=linked_finding_id,
                            file_path=str(p["file_path"]),
                            title=str(p["title"])[:300],
                            original_code=str(p["original_code"]),
                            proposed_code=str(p["proposed_code"]),
                            unified_diff=str(p["unified_diff"]),
                            explanation=str(p["explanation"]),
                            applicability_verified=bool(p.get("applicability_verified", False)),
                            validation_output=str(p.get("validation_output", "")),
                            approval_status="pending_approval",
                        )
                    )

                review.diff_summary = final_state.diff_summary or f"Reviewed {len(final_state.changed_files)} changed file(s)."
                review.recommendation = final_state.recommendation
                review.recommendation_reason = final_state.recommendation_reason
                review.review_status = "completed"
                review.shared_state_json = final_state.to_snapshot()
                review.completed_at = datetime.now(timezone.utc)

                md_report = _build_markdown_report(review, repo, final_state)
                db.add(
                    ReviewArtifact(
                        review_id=review_id,
                        artifact_type="consolidated_report_md",
                        title="Consolidated Review Report (Markdown)",
                        content_type="text/markdown",
                        content=md_report,
                    )
                )
                db.add(
                    ReviewArtifact(
                        review_id=review_id,
                        artifact_type="consolidated_report_json",
                        title="Consolidated Review Report (JSON)",
                        content_type="application/json",
                        content=json.dumps(final_state.to_snapshot(), indent=2),
                    )
                )

                # Auto-publish back to GitHub PR + Commit Status if configured in ReviewPolicy
                if (
                    policy.get("auto_publish_github_review")
                    and repo.source_type == "github"
                    and code_change.pr_number
                    and github_token
                ):
                    try:
                        gh = GitHubClient(github_token)
                        gh_event = (
                            "APPROVE"
                            if final_state.recommendation == "Approve"
                            else "REQUEST_CHANGES"
                            if final_state.recommendation == "Request Changes"
                            else "COMMENT"
                        )
                        gh_resp = await gh.create_pull_request_review(
                            repo.owner,
                            repo.name,
                            code_change.pr_number,
                            commit_id=review.target_commit,
                            body=md_report[:60000],
                            event=gh_event,
                        )
                        review.github_review_id = gh_resp.get("id")
                        review.github_published_at = datetime.now(timezone.utc)
                        gh_state = (
                            "success"
                            if final_state.recommendation == "Approve"
                            else "failure"
                            if final_state.recommendation == "Request Changes"
                            else "error"
                        )
                        await gh.create_commit_status(
                            repo.owner,
                            repo.name,
                            review.target_commit,
                            state=gh_state,
                            description=f"ReviewBoard: {final_state.recommendation} ({len(final_state.findings)} findings)",
                        )
                    except Exception:
                        pass

                await db.commit()

                await ws_manager.emit(
                    review_id,
                    "review_completed",
                    {
                        "recommendation": review.recommendation,
                        "reason": review.recommendation_reason,
                        "findings_count": len(final_state.findings),
                        "patches_count": len(final_state.patch_proposals),
                    },
                )
            except (asyncio.CancelledError, ReviewCancelledError):
                try:
                    await db.rollback()
                except Exception:
                    pass
                await asyncio.shield(persist_review_stopped(review_id))
            except Exception as exc:
                if is_review_cancelled(review_id):
                    try:
                        await db.rollback()
                    except Exception:
                        pass
                    await asyncio.shield(persist_review_stopped(review_id))
                    return
                review.review_status = "failed"
                review.recommendation = "Incomplete"
                review.recommendation_reason = f"Review execution error: {exc}"
                review.completed_at = datetime.now(timezone.utc)
                await db.commit()
                await ws_manager.emit(
                    review_id,
                    "review_failed",
                    {"error": str(exc)},
                )
            finally:
                review_id_var.reset(ctx_token)
                if workspace_dir and workspace_dir.exists() and workspace_dir.name != "_mirrors":
                    try:
                        ws_root = get_settings().resolved_workspace_dir
                        if ws_root in workspace_dir.resolve().parents:
                            shutil.rmtree(workspace_dir, ignore_errors=True)
                    except Exception:
                        pass


def launch_review_job(review_id: str) -> None:
    """Dispatch review either to Celery+Redis (if enabled) or in-process FastAPI asyncio task."""
    clear_review_cancelled(review_id)
    settings = get_settings()
    if settings.celery_enabled:
        from app.services.tasks import run_review_celery_task

        run_review_celery_task.delay(review_id)
        return

    task = asyncio.create_task(ReviewCoordinator.execute_review(review_id))
    _ACTIVE_TASKS.add(task)
    register_review_task(review_id, task)
    task.add_done_callback(_ACTIVE_TASKS.discard)

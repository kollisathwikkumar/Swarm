from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import AGENT_METADATA
from app.database.session import async_session_maker
from app.integrations.github_client import GitHubClient
from app.models.tables import AgentRun, CodeChange, Repository, Review
from app.orchestration.coordinator import launch_review_job, load_effective_agent_configs
from app.scanners.git_diff_tool import parse_unified_diff


async def sync_repository_open_prs(
    repo: Repository,
    github_token: str,
    db: AsyncSession,
    *,
    auto_trigger_new_commits: bool = True,
) -> dict[str, Any]:
    """
    Sync open Pull Requests from GitHub for a repository.
    For any open PR whose exact head SHA has not been reviewed yet, optionally
    fetch the PR diff and trigger a 6-agent review automatically (no webhooks/ngrok needed!).
    """
    gh = GitHubClient(github_token)
    prs = await gh.list_pull_requests(repo.owner, repo.name, state="open")
    repo.last_synced_at = datetime.now(timezone.utc)

    triggered_reviews: list[str] = []
    skipped_existing = 0

    if auto_trigger_new_commits:
        configs = await load_effective_agent_configs(db)
        for pr in prs[:10]:
            head_sha = pr["head"]["sha"]
            base_sha = pr["base"]["sha"]
            existing_rev = (
                await db.execute(
                    select(Review).where(
                        Review.repository_id == repo.id,
                        Review.target_commit == head_sha,
                    )
                )
            ).scalar_one_or_none()
            if existing_rev:
                skipped_existing += 1
                continue

            pr_number = int(pr["number"])
            diff_text, files = await gh.get_pull_request_diff(repo.owner, repo.name, pr_number)
            if not diff_text.strip():
                continue

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
            cc = CodeChange(
                repository_id=repo.id,
                source_mode="github_pr",
                pr_number=pr_number,
                pr_title=pr.get("title"),
                pr_url=pr.get("html_url"),
                base_branch=pr["base"]["ref"],
                target_branch=pr["head"]["ref"],
                base_commit=base_sha,
                target_commit=head_sha,
                diff_text=diff_text,
                changed_files=changed_files,
            )
            db.add(cc)
            await db.flush()

            rev = Review(
                repository_id=repo.id,
                code_change_id=cc.id,
                triggered_by=f"github_sync:pr#{pr_number}",
                base_commit=base_sha,
                target_commit=head_sha,
                review_status="queued",
                recommendation="Pending",
            )
            db.add(rev)
            await db.flush()
            for key, meta in AGENT_METADATA.items():
                db.add(
                    AgentRun(
                        review_id=rev.id,
                        agent_name=key,
                        agent_label=meta["label"],
                        model_used=configs[key].model,
                        status="queued",
                    )
                )
            await db.commit()
            launch_review_job(rev.id)
            triggered_reviews.append(rev.id)

    await db.commit()
    return {
        "repository": repo.full_name,
        "open_prs": len(prs),
        "triggered_reviews": triggered_reviews,
        "already_reviewed": skipped_existing,
    }


async def github_background_poller(interval_seconds: int = 90) -> None:
    """
    Lightweight background sync watcher so GitHub PRs opened/updated while running locally
    are automatically picked up without requiring ngrok or public webhook URLs.
    """
    from app.api.deps import resolve_github_token

    while True:
        await asyncio.sleep(interval_seconds)
        try:
            async with async_session_maker() as db:
                repos = (
                    await db.execute(
                        select(Repository).where(
                            Repository.source_type == "github",
                            Repository.auto_review_webhooks.is_(True),
                        )
                    )
                ).scalars().all()
                for repo in repos:
                    try:
                        token = await resolve_github_token(repo.user_id, db)
                        await sync_repository_open_prs(
                            repo, token, db, auto_trigger_new_commits=True
                        )
                    except Exception:
                        continue
        except asyncio.CancelledError:
            break
        except Exception:
            continue

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.config import AGENT_METADATA
from app.database.session import get_db
from app.models.tables import AgentRun, Repository, Review, User
from app.orchestration.coordinator import load_effective_agent_configs

router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.get("/overview")
async def get_agents_overview(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    configs = await load_effective_agent_configs(db)
    rows = (
        await db.execute(
            select(AgentRun)
            .join(Review, AgentRun.review_id == Review.id)
            .join(Repository, Review.repository_id == Repository.id)
            .where(Repository.user_id == user.id)
            .order_by(Review.started_at.asc(), AgentRun.id.asc())
        )
    ).scalars().all()

    by_agent: dict[str, list[AgentRun]] = {k: [] for k in AGENT_METADATA}
    for r in rows:
        by_agent.setdefault(r.agent_name, []).append(r)

    agents = []
    for key, meta in AGENT_METADATA.items():
        runs = by_agent.get(key, [])
        completed = [r for r in runs if r.status == "completed"]
        avg_ms = int(sum(r.duration_ms for r in completed) / len(completed)) if completed else 0
        cfg = configs[key]
        agents.append(
            {
                "agent_name": key,
                "label": meta["label"],
                "role": meta["role"],
                "model": cfg.model,
                "has_api_key": bool(cfg.api_key),
                "total_runs": len(runs),
                "completed_runs": len(completed),
                "failed_runs": len([r for r in runs if r.status in ("failed", "incomplete")]),
                "avg_duration_ms": avg_ms,
                "latest_status": runs[-1].status if runs else "idle",
            }
        )
    return {"agents": agents}


@router.get("/runs")
async def list_recent_agent_runs(
    limit: int = 50,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    rows = (
        await db.execute(
            select(AgentRun, Review, Repository)
            .join(Review, AgentRun.review_id == Review.id)
            .join(Repository, Review.repository_id == Repository.id)
            .where(Repository.user_id == user.id)
            .order_by(Review.started_at.desc())
            .limit(limit)
        )
    ).all()
    return {
        "runs": [
            {
                "id": run.id,
                "review_id": rev.id,
                "repository_name": repo.full_name,
                "agent_name": run.agent_name,
                "agent_label": run.agent_label,
                "model_used": run.model_used,
                "status": run.status,
                "summary": run.summary,
                "error_message": run.error_message,
                "duration_ms": run.duration_ms,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            }
            for run, rev, repo in rows
        ]
    }

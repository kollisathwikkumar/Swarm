from __future__ import annotations

from collections import Counter, defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.database.session import get_db
from app.models.tables import AgentRun, Finding, PatchSuggestion, Repository, Review, User

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/summary")
async def analytics_summary(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    repos = (
        await db.execute(select(Repository).where(Repository.user_id == user.id))
    ).scalars().all()
    reviews = (
        await db.execute(
            select(Review)
            .join(Repository, Review.repository_id == Repository.id)
            .where(Repository.user_id == user.id)
            .order_by(Review.started_at.asc())
        )
    ).scalars().all()
    findings = (
        await db.execute(
            select(Finding)
            .join(Review, Finding.review_id == Review.id)
            .join(Repository, Review.repository_id == Repository.id)
            .where(Repository.user_id == user.id)
        )
    ).scalars().all()
    patches = (
        await db.execute(
            select(PatchSuggestion)
            .join(Review, PatchSuggestion.review_id == Review.id)
            .join(Repository, Review.repository_id == Repository.id)
            .where(Repository.user_id == user.id)
        )
    ).scalars().all()
    agent_runs = (
        await db.execute(
            select(AgentRun)
            .join(Review, AgentRun.review_id == Review.id)
            .join(Repository, Review.repository_id == Repository.id)
            .where(Repository.user_id == user.id)
        )
    ).scalars().all()

    rec_counts = Counter(r.recommendation for r in reviews)
    sev_counts = Counter(f.severity for f in findings)
    agent_counts = Counter(f.agent for f in findings)
    tool_counts = Counter(f.tool_name or "llm-review" for f in findings)
    ver_counts = Counter(f.verification_status for f in findings)
    file_counts = Counter(f.file_path for f in findings if f.file_path)
    patch_counts = Counter(p.approval_status for p in patches)

    daily_map: dict[str, dict[str, int]] = defaultdict(
        lambda: {"reviews": 0, "approve": 0, "request_changes": 0, "incomplete": 0}
    )
    for r in reviews:
        if r.started_at:
            day = r.started_at.strftime("%Y-%m-%d")
            daily_map[day]["reviews"] += 1
            if r.recommendation == "Approve":
                daily_map[day]["approve"] += 1
            elif r.recommendation == "Request Changes":
                daily_map[day]["request_changes"] += 1
            elif r.recommendation == "Incomplete":
                daily_map[day]["incomplete"] += 1

    latency_by_agent: dict[str, list[int]] = defaultdict(list)
    for ar in agent_runs:
        if ar.duration_ms > 0:
            latency_by_agent[ar.agent_label].append(ar.duration_ms)

    return {
        "totals": {
            "repositories": len(repos),
            "reviews": len(reviews),
            "findings": len(findings),
            "patches": len(patches),
            "approved_reviews": rec_counts.get("Approve", 0),
            "request_changes_reviews": rec_counts.get("Request Changes", 0),
            "incomplete_reviews": rec_counts.get("Incomplete", 0),
        },
        "severity_breakdown": {
            "Critical": sev_counts.get("Critical", 0),
            "High": sev_counts.get("High", 0),
            "Medium": sev_counts.get("Medium", 0),
            "Low": sev_counts.get("Low", 0),
        },
        "verification_breakdown": dict(ver_counts),
        "findings_by_agent": dict(agent_counts),
        "findings_by_tool": dict(tool_counts),
        "patch_status_breakdown": dict(patch_counts),
        "top_affected_files": [
            {"file_path": fp, "count": cnt} for fp, cnt in file_counts.most_common(10)
        ],
        "daily_timeline": [
            {"date": day, **vals} for day, vals in sorted(daily_map.items())
        ],
        "agent_avg_latency_ms": {
            label: int(sum(vals) / len(vals)) for label, vals in latency_by_agent.items() if vals
        },
    }

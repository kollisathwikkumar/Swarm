from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, update

from app.api import agents, analytics, auth, github, patches, repositories, reviews, settings
from app.config import get_settings
from app.database.session import async_session_maker, init_db
from app.models.tables import AgentRun, Review, ReviewPolicy
from app.services.github_sync import github_background_poller
from app.services.websocket_manager import ws_manager


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    async with async_session_maker() as db:
        res = await db.execute(select(ReviewPolicy).where(ReviewPolicy.name == "default"))
        if not res.scalar_one_or_none():
            db.add(ReviewPolicy(name="default"))

        # Cleanly close any stale running/queued reviews interrupted by a prior restart
        now = datetime.now(timezone.utc)
        await db.execute(
            update(Review)
            .where(Review.review_status.in_(["queued", "running"]))
            .values(
                review_status="failed",
                recommendation="Incomplete",
                recommendation_reason="Review interrupted by server restart. Click Re-run Review to execute again.",
                completed_at=now,
            )
        )
        await db.execute(
            update(AgentRun)
            .where(AgentRun.status.in_(["queued", "running"]))
            .values(
                status="failed",
                error_message="Interrupted before completion due to server restart.",
                completed_at=now,
            )
        )
        await db.commit()
    poller_task = asyncio.create_task(github_background_poller(interval_seconds=90))
    try:
        yield
    finally:
        poller_task.cancel()
        try:
            await poller_task
        except asyncio.CancelledError:
            pass


app_settings = get_settings()

app = FastAPI(
    title="ReviewBoard — Automated Code Review Board API",
    version="1.0.0",
    description="Multi-agent AI code review platform powered by Microsoft Agent Framework and DeepSeek.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=app_settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(github.router)
app.include_router(repositories.router)
app.include_router(reviews.router)
app.include_router(patches.router)
app.include_router(agents.router)
app.include_router(analytics.router)
app.include_router(settings.router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "reviewboard-backend"}


@app.websocket("/ws/reviews/{review_id}")
async def review_websocket(websocket: WebSocket, review_id: str) -> None:
    await ws_manager.connect_review(review_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect_review(review_id, websocket)


@app.websocket("/ws/activity")
async def activity_websocket(websocket: WebSocket) -> None:
    await ws_manager.connect_global(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect_global(websocket)

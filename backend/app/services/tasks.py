from __future__ import annotations

import asyncio

from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "swarm",
    broker=settings.redis_url,
    backend=settings.redis_url,
)


@celery_app.task(name="swarm.execute_review")
def run_review_celery_task(review_id: str) -> None:
    from app.orchestration.coordinator import ReviewCoordinator

    asyncio.run(ReviewCoordinator.execute_review(review_id))

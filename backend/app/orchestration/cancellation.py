from __future__ import annotations

import asyncio
from collections import OrderedDict
import contextvars
from typing import Any

# Tracks active review execution ID per async task context so HTTP SDK calls can abort on Stop.
review_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("rb_review_id", default="")


class ReviewCancelledError(asyncio.CancelledError):
    """Raised when a user explicitly stops a running review operation."""


_MAX_CANCELLED_HISTORY = 500
_CANCELLED_REVIEWS: OrderedDict[str, None] = OrderedDict()
_ACTIVE_TASKS: dict[str, asyncio.Task[Any]] = {}
_ACTIVE_HTTP_CLIENTS: dict[str, set[Any]] = {}


def mark_review_cancelled(review_id: str) -> None:
    if not review_id:
        return
    _CANCELLED_REVIEWS[review_id] = None
    _CANCELLED_REVIEWS.move_to_end(review_id)
    while len(_CANCELLED_REVIEWS) > _MAX_CANCELLED_HISTORY:
        _CANCELLED_REVIEWS.popitem(last=False)


def clear_review_cancelled(review_id: str) -> None:
    if review_id:
        _CANCELLED_REVIEWS.pop(review_id, None)


def is_review_cancelled(review_id: str) -> bool:
    return bool(review_id and review_id in _CANCELLED_REVIEWS)


def register_review_task(review_id: str, task: asyncio.Task[Any]) -> None:
    if not review_id:
        return
    _ACTIVE_TASKS[review_id] = task

    def _cleanup(done_task: asyncio.Task[Any]) -> None:
        if _ACTIVE_TASKS.get(review_id) is done_task:
            _ACTIVE_TASKS.pop(review_id, None)

    task.add_done_callback(_cleanup)


def register_http_client(review_id: str, client: Any) -> None:
    if not review_id or client is None:
        return
    _ACTIVE_HTTP_CLIENTS.setdefault(review_id, set()).add(client)


def unregister_http_client(review_id: str, client: Any) -> None:
    if not review_id or client is None:
        return
    bucket = _ACTIVE_HTTP_CLIENTS.get(review_id)
    if not bucket:
        return
    bucket.discard(client)
    if not bucket:
        _ACTIVE_HTTP_CLIENTS.pop(review_id, None)


async def cancel_review_execution(review_id: str) -> bool:
    """
    Immediately stop an active review and close all open DeepSeek HTTP clients so
    in-flight LLM streams abort immediately without consuming additional tokens.
    """
    mark_review_cancelled(review_id)

    clients = list(_ACTIVE_HTTP_CLIENTS.pop(review_id, set()))
    for client in clients:
        try:
            await asyncio.wait_for(client.close(), timeout=1.5)
        except Exception:
            pass

    task = _ACTIVE_TASKS.get(review_id)
    cancelled_task = False
    if task and not task.done():
        task.cancel("Stopped by user")
        cancelled_task = True
    return cancelled_task or bool(clients)

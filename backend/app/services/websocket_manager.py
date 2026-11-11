from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket


class WebSocketManager:
    """Broadcasts live multi-agent orchestration events to review and global streams."""

    def __init__(self) -> None:
        self._review_connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._global_connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect_review(self, review_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._review_connections[review_id].add(websocket)

    async def disconnect_review(self, review_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            self._review_connections[review_id].discard(websocket)
            if not self._review_connections[review_id]:
                self._review_connections.pop(review_id, None)

    async def connect_global(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._global_connections.add(websocket)

    async def disconnect_global(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._global_connections.discard(websocket)

    async def emit(self, review_id: str, event_type: str, payload: dict[str, Any]) -> None:
        message = {
            "review_id": review_id,
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        async with self._lock:
            targets = list(self._review_connections.get(review_id, set())) + list(
                self._global_connections
            )
        stale: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)
        if stale:
            async with self._lock:
                for ws in stale:
                    self._global_connections.discard(ws)
                    self._review_connections.get(review_id, set()).discard(ws)


ws_manager = WebSocketManager()

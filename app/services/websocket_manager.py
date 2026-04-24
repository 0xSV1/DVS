"""WebSocket connection manager for real-time challenge solve notifications.

Handles multiple concurrent WebSocket connections and broadcasts challenge
solve events to all connected clients. Buffers recent messages so clients
that connect shortly after a broadcast (e.g. after a redirect) still
receive the notification.
"""

from __future__ import annotations

import logging
import time

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# How long buffered messages are replayed to newly connecting clients (seconds)
_REPLAY_WINDOW = 5.0


class ConnectionManager:
    """Manage WebSocket connections for real-time notifications."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        self._recent_messages: list[tuple[float, str]] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection and replay recent messages."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.debug("WebSocket connected. Total: %d", len(self.active_connections))

        # Replay any messages broadcast within the replay window so clients
        # that reconnect after a redirect still see the notification.
        now = time.monotonic()
        for ts, msg in self._recent_messages:
            if now - ts <= _REPLAY_WINDOW:
                try:
                    await websocket.send_text(msg)
                except Exception:
                    break

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.debug("WebSocket disconnected. Total: %d", len(self.active_connections))

    async def broadcast(self, message: str) -> None:
        """Send a message to all connected WebSocket clients."""
        # Buffer for replay to clients that connect shortly after
        now = time.monotonic()
        self._recent_messages.append((now, message))
        # Prune expired entries
        self._recent_messages = [(ts, msg) for ts, msg in self._recent_messages if now - ts <= _REPLAY_WINDOW]

        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)

        # Clean up dead connections
        for conn in disconnected:
            self.disconnect(conn)

    async def send_personal(self, websocket: WebSocket, message: str) -> None:
        """Send a message to a specific WebSocket client."""
        try:
            await websocket.send_text(message)
        except Exception:
            self.disconnect(websocket)


# Singleton instance used across the application
manager = ConnectionManager()

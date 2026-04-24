"""Difficulty middleware: reads the session and sets request.state.difficulty.

Mirrors DVWA's security cookie that selects the active difficulty tier.
The difficulty level controls which handler file processes each request.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.constants import DIFFICULTY_LABELS, VALID_DIFFICULTIES


class DifficultyMiddleware(BaseHTTPMiddleware):
    """Read difficulty from session and expose it via request.state.difficulty."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        difficulty = request.session.get("difficulty", settings.DEFAULT_DIFFICULTY)

        # Validate the difficulty value
        if difficulty not in VALID_DIFFICULTIES:
            difficulty = settings.DEFAULT_DIFFICULTY

        request.state.difficulty = difficulty
        request.state.difficulty_label = DIFFICULTY_LABELS.get(difficulty, "Unknown")
        return await call_next(request)

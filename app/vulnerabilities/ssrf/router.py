"""SSRF vulnerability module router.

Provides a "URL preview" feature that fetches URLs server-side.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.ssrf.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/ssrf", tags=["ssrf"])

HANDLERS = {
    "intern": intern.handle_fetch,
    "junior": junior.handle_fetch,
    "senior": senior.handle_fetch,
    "tech_lead": tech_lead.handle_fetch,
}


@router.get("")
async def ssrf_page(
    request: Request,
    url: str = "",
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the SSRF challenge page with URL preview results."""
    difficulty = request.state.difficulty
    handler = HANDLERS.get(difficulty, HANDLERS["intern"])

    result = None
    if url:
        result = await handler(url)

        # Solved when an internal/localhost URL is fetched successfully
        internal_patterns = [
            "localhost",
            "127.",
            "0.0.0.0",
            "::1",
            "169.254",
            "metadata",
            "internal",
        ]
        await solve_if(
            db=db,
            challenge_key="ssrf_internal",
            condition=lambda: result.get("success") and any(p in url.lower() for p in internal_patterns),
            ws_manager=manager,
        )

    return templates.TemplateResponse(
        request=request,
        name="challenges/ssrf.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "url": url,
            "result": result,
            "challenge_name": "Microservice Mischief",
            "challenge_category": "A01 Broken Access Control",
        },
    )

"""Open redirect vulnerability module router.

Dispatches to tier-specific handlers for URL redirect validation.
Integrates solve_if() for challenge detection.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.open_redirect.handlers import intern, junior, senior, tech_lead

router = APIRouter(tags=["open_redirect"])

HANDLERS = {
    "intern": intern.handle_redirect,
    "junior": junior.handle_redirect,
    "senior": senior.handle_redirect,
    "tech_lead": tech_lead.handle_redirect,
}


@router.get("/challenges/open-redirect")
async def open_redirect_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the open redirect challenge page."""
    return templates.TemplateResponse(
        request=request,
        name="challenges/open_redirect.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "challenge_name": "Redirect to My Portfolio",
            "challenge_category": "A01 Broken Access Control",
        },
    )


@router.get("/redirect")
async def open_redirect(
    request: Request,
    url: str = "/",
    db: Session = Depends(get_db),
) -> object:
    """Redirect to a user-supplied URL, dispatched to tier-specific handler.

    OWASP: A01:2025 Broken Access Control
    CWE: CWE-601 (URL Redirection to Untrusted Site)
    """
    handler = HANDLERS[request.state.difficulty]
    redirect_url, is_external = handler(url)

    if is_external:
        await solve_if(
            db=db,
            challenge_key="open_redirect",
            condition=lambda: True,
            ws_manager=manager,
        )

    return RedirectResponse(url=redirect_url, status_code=302)

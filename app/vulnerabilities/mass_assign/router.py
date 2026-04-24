"""Mass assignment vulnerability module router.

Dispatches to tier-specific handlers for user profile update.
Integrates solve_if() for challenge detection.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.mass_assign.handlers import intern, junior, senior, tech_lead

router = APIRouter(tags=["mass_assign"])

HANDLERS = {
    "intern": intern.handle_update,
    "junior": junior.handle_update,
    "senior": senior.handle_update,
    "tech_lead": tech_lead.handle_update,
}


@router.get("/challenges/mass-assign")
async def mass_assign_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the mass assignment challenge page."""
    return templates.TemplateResponse(
        request=request,
        name="challenges/mass_assign.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "result": None,
            "challenge_name": "Promote Yourself in JSON",
            "challenge_category": "A01 Broken Access Control",
        },
    )


@router.post("/api/users/me")
async def update_profile(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> dict:
    """Update user profile, dispatched to tier-specific handler.

    OWASP: A01:2025 Broken Access Control
    CWE: CWE-915 (Improperly Controlled Modification of Dynamically-Determined
    Object Attributes)
    """
    if not current_user:
        return {"error": "Authentication required"}

    body = await request.json()
    handler = HANDLERS[request.state.difficulty]
    result = handler(current_user, body)
    db.commit()

    if body.get("role") == "admin":
        await solve_if(
            db=db,
            challenge_key="mass_assign",
            condition=lambda: current_user.role == "admin",
            ws_manager=manager,
        )

    return result

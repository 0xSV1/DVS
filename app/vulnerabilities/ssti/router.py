"""SSTI vulnerability module router.

Dispatches to the appropriate tier handler for template injection.
Integrates solve_if() for challenge detection.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.ssti.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/ssti", tags=["ssti"])

HANDLERS = {
    "intern": intern.handle_render,
    "junior": junior.handle_render,
    "senior": senior.handle_render,
    "tech_lead": tech_lead.handle_render,
}


@router.get("")
async def ssti_page(
    request: Request,
    name: str = "",
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the SSTI challenge page."""
    difficulty = request.state.difficulty
    handler = HANDLERS.get(difficulty, HANDLERS["intern"])

    result = None
    if name:
        result = handler(name)

        # Challenge: ssti_basic (Junior, difficulty 2)
        # Solved when template expressions are evaluated (e.g., {{7*7}} -> 49)
        await solve_if(
            db=db,
            challenge_key="ssti_basic",
            condition=lambda: result and "49" in result.get("output", "") and "7*7" in name,
            ws_manager=manager,
        )

        # Challenge: ssti_rce (Senior, difficulty 3)
        # Solved when class traversal patterns are detected in input
        # and the tier does not fully block template execution
        rce_patterns = [
            "__class__",
            "__subclasses__",
            "__globals__",
            "__builtins__",
            "popen",
        ]
        await solve_if(
            db=db,
            challenge_key="ssti_rce",
            condition=lambda: any(p in name for p in rce_patterns) and difficulty != "tech_lead",
            ws_manager=manager,
        )

    return templates.TemplateResponse(
        request=request,
        name="challenges/ssti.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "name_input": name,
            "result": result,
            "challenge_name": "Server-Side Template Injection",
            "challenge_category": "A05 Injection",
        },
    )

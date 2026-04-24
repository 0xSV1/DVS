"""Broken logging vulnerability module router.

Dispatches to tier-specific handlers for audit log exposure.
Integrates solve_if() for challenge detection.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.broken_logging.handlers import intern, junior, senior, tech_lead

router = APIRouter(tags=["broken_logging"])

HANDLERS = {
    "intern": intern.handle_get_logs,
    "junior": junior.handle_get_logs,
    "senior": senior.handle_get_logs,
    "tech_lead": tech_lead.handle_get_logs,
}


@router.get("/challenges/logging")
async def logging_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the broken logging challenge page, dispatched to tier-specific handler.

    OWASP: A09:2025 Security Logging and Monitoring Failures
    CWE: CWE-532 (Insertion of Sensitive Information into Log File)
    """
    handler = HANDLERS[request.state.difficulty]
    logs = handler(db, current_user)

    if logs and request.state.difficulty in ("intern", "junior"):
        await solve_if(
            db=db,
            challenge_key="broken_logging",
            condition=lambda: True,
            ws_manager=manager,
        )

    return templates.TemplateResponse(
        request=request,
        name="challenges/logging.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "logs": logs,
            "challenge_name": "console.log(password)",
            "challenge_category": "A09 Logging Failures",
        },
    )

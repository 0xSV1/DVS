"""Log injection vulnerability module router.

Dispatches to the appropriate tier handler for feedback submission
and log viewer. Integrates solve_if() for challenge detection.

OWASP: A09:2025 Security Logging and Monitoring Failures
CWE: CWE-117 (Improper Output Neutralization for Logs)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.log_injection.handlers import intern, junior, senior, tech_lead

router = APIRouter(tags=["log_injection"])

FEEDBACK_HANDLERS = {
    "intern": intern.handle_submit_feedback,
    "junior": junior.handle_submit_feedback,
    "senior": senior.handle_submit_feedback,
    "tech_lead": tech_lead.handle_submit_feedback,
}

USERNAME_HANDLERS = {
    "intern": intern.get_log_username,
    "junior": junior.get_log_username,
    "senior": senior.get_log_username,
    "tech_lead": tech_lead.get_log_username,
}

SOLVE_HANDLERS = {
    "intern": intern.check_log_injection_solve,
    "junior": junior.check_log_injection_solve,
    "senior": senior.check_log_injection_solve,
    "tech_lead": tech_lead.check_log_injection_solve,
}

# In-memory log storage (resets with app restart, like the ephemeral DB)
_log_entries: list[str] = []


@router.get("/challenges/log-injection")
async def log_injection_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the log injection challenge page with recent log entries."""
    return templates.TemplateResponse(
        request=request,
        name="challenges/log_injection.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "log_entries": list(reversed(_log_entries[-30:])),
            "result": None,
            "challenge_name": "Fake It Till You Ship It",
            "challenge_category": "A09 Logging Failures",
        },
    )


@router.post("/challenges/log-injection/submit")
async def submit_feedback(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Submit feedback to the audit log, dispatched to tier-specific handler."""
    difficulty = request.state.difficulty
    form = await request.form()
    feedback = form.get("feedback", "")
    form_username = form.get("username", "anonymous")

    username_handler = USERNAME_HANDLERS.get(difficulty, USERNAME_HANDLERS["intern"])
    display_name = username_handler(current_user, form_username)

    handler = FEEDBACK_HANDLERS.get(difficulty, FEEDBACK_HANDLERS["intern"])
    result = handler(feedback, display_name)

    if result.get("stored"):
        _log_entries.append(result["entry"])

    # Solve detection: dispatched to tier handler
    raw = result.get("raw_feedback", "")
    solve_handler = SOLVE_HANDLERS.get(difficulty, SOLVE_HANDLERS["intern"])
    if solve_handler(raw, feedback):
        await solve_if(
            db=db,
            challenge_key="log_injection",
            condition=lambda: True,
            ws_manager=manager,
        )

    return templates.TemplateResponse(
        request=request,
        name="challenges/log_injection.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "log_entries": list(reversed(_log_entries[-30:])),
            "result": result,
            "challenge_name": "Fake It Till You Ship It",
            "challenge_category": "A09 Logging Failures",
        },
    )

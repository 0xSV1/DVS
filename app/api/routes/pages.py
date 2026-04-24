"""Page routes: landing page, security/difficulty settings, about."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.constants import DIFFICULTY_COLORS, DIFFICULTY_LABELS, VALID_DIFFICULTIES
from app.models.challenge import Challenge
from app.models.user import User

router = APIRouter()


@router.get("/")
async def landing_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """DeployBro landing page: the satirical startup homepage."""
    challenge_count = db.query(Challenge).count()
    solved_count = db.query(Challenge).filter(Challenge.solved.is_(True)).count()

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "current_user": current_user,
            "challenge_count": challenge_count,
            "solved_count": solved_count,
            "difficulty": request.state.difficulty,
            "difficulty_label": DIFFICULTY_LABELS.get(request.state.difficulty, "Unknown"),
        },
    )


@router.get("/security")
async def security_page(request: Request) -> object:
    """Security settings page: set the global difficulty tier."""
    return templates.TemplateResponse(
        request=request,
        name="security.html",
        context={
            "difficulty": request.state.difficulty,
            "difficulty_labels": DIFFICULTY_LABELS,
            "difficulty_colors": DIFFICULTY_COLORS,
        },
    )


@router.post("/security")
async def set_difficulty(request: Request) -> RedirectResponse:
    """Update the difficulty tier stored in the session."""
    form = await request.form()
    difficulty = form.get("difficulty", "intern")

    if difficulty in VALID_DIFFICULTIES:
        request.session["difficulty"] = difficulty

    return RedirectResponse(url="/security", status_code=303)

"""CSRF vulnerability module router.

Dispatches to tier-specific handlers for fund transfer CSRF protection.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.csrf.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/csrf", tags=["csrf"])

HANDLERS = {
    "intern": intern.handle_transfer,
    "junior": junior.handle_transfer,
    "senior": senior.handle_transfer,
    "tech_lead": tech_lead.handle_transfer,
}


@router.get("")
async def csrf_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the CSRF challenge page."""
    difficulty = request.state.difficulty
    csrf_token = None
    if difficulty in ("senior", "tech_lead"):
        csrf_token = secrets.token_hex(32)
        request.session["csrf_token"] = csrf_token

    return templates.TemplateResponse(
        request=request,
        name="challenges/csrf.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "csrf_token": csrf_token,
            "result": None,
            "challenge_name": "One-Click Equity Dilution",
            "challenge_category": "A01 Broken Access Control",
        },
    )


@router.post("/transfer")
async def transfer_funds(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Handle fund transfer with per-difficulty CSRF protection."""
    difficulty = request.state.difficulty
    form = await request.form()
    handler = HANDLERS.get(difficulty, HANDLERS["intern"])

    form_data = {
        "recipient": form.get("recipient", ""),
        "amount": form.get("amount", "0"),
        "csrf_token": form.get("csrf_token", ""),
    }
    session_data = dict(request.session)
    header_data = {
        "origin": request.headers.get("origin", ""),
        "referer": request.headers.get("referer", ""),
    }

    result = handler(form_data, session_data, header_data)

    # Only vulnerable tiers (intern, junior, senior) can solve the challenge.
    # tech_lead has proper token rotation + Origin validation, so a legitimate
    # same-session transfer should never count as an exploit.
    if result.get("success") and difficulty != "tech_lead":
        await solve_if(
            db=db,
            challenge_key="csrf_transfer",
            condition=lambda: True,
            ws_manager=manager,
        )

    # Rotate token if needed
    csrf_token = None
    if difficulty in ("senior", "tech_lead"):
        csrf_token = secrets.token_hex(32)
        request.session["csrf_token"] = csrf_token

    return templates.TemplateResponse(
        request=request,
        name="challenges/csrf.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "csrf_token": csrf_token,
            "result": result,
            "challenge_name": "One-Click Equity Dilution",
            "challenge_category": "A01 Broken Access Control",
        },
    )

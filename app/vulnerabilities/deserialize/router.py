"""Insecure deserialization vulnerability module.

A "preferences" endpoint that accepts serialized data. At intern/junior tier,
uses pickle (RCE). At senior tier, uses JSON without validation. At tech_lead
tier, uses JSON with strict schema validation.

OWASP: A08:2025 Software and Data Integrity Failures
CWE: CWE-502 (Deserialization of Untrusted Data)

WARNING: Pickle deserialization at intern/junior tiers can lead to arbitrary
code execution. Gated behind the UNSAFE_CHALLENGES setting.
"""

from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.core.config import settings
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.deserialize.handlers import intern, junior, senior, tech_lead

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/challenges/deserialize", tags=["deserialize"])

HANDLERS = {
    "intern": intern,
    "junior": junior,
    "senior": senior,
    "tech_lead": tech_lead,
}


@router.get("")
async def deserialize_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the deserialization challenge page."""
    difficulty = request.state.difficulty
    handler = HANDLERS[difficulty]
    encoded, format_name = handler.get_default_prefs()

    return templates.TemplateResponse(
        request=request,
        name="challenges/deserialize.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "encoded_prefs": encoded,
            "format_name": format_name,
            "result": None,
            "challenge_name": "Unpickle Me This",
            "challenge_category": "A08 Data Integrity Failures",
        },
    )


@router.post("/load")
async def load_preferences(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Load user preferences from serialized data."""
    difficulty = request.state.difficulty
    handler = HANDLERS[difficulty]
    form = await request.form()
    data = form.get("data", "")

    try:
        raw = base64.b64decode(data)
    except Exception:
        result = {"success": False, "prefs": None, "error": "Invalid base64 encoding"}
        return _render(request, current_user, difficulty, handler, result)

    result = handler.handle_load(raw, unsafe_enabled=settings.UNSAFE_CHALLENGES)

    if result.get("_solved"):
        await solve_if(
            db=db,
            challenge_key="deserialize_pickle",
            condition=lambda: True,
            ws_manager=manager,
        )
        # Remove internal flag before rendering
        result.pop("_solved", None)

    return _render(request, current_user, difficulty, handler, result)


def _render(
    request: Request,
    current_user: User | None,
    difficulty: str,
    handler: object,
    result: dict,
) -> object:
    """Render the deserialization challenge page with results."""
    encoded, format_name = handler.get_default_prefs()

    return templates.TemplateResponse(
        request=request,
        name="challenges/deserialize.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "encoded_prefs": encoded,
            "format_name": format_name,
            "result": result,
            "challenge_name": "Unpickle Me This",
            "challenge_category": "A08 Data Integrity Failures",
        },
    )

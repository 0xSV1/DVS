"""Security misconfiguration vulnerability module.

Exposes debug endpoints, environment variables, default credentials,
and overly permissive CORS at lower difficulty tiers.

OWASP: A02:2025 Security Misconfiguration
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.misconfig.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/misconfig", tags=["misconfig"])

DEBUG_HANDLERS = {
    "intern": intern.handle_debug,
    "junior": junior.handle_debug,
    "senior": senior.handle_debug,
    "tech_lead": tech_lead.handle_debug,
}

CORS_HANDLERS = {
    "intern": intern.handle_cors,
    "junior": junior.handle_cors,
    "senior": senior.handle_cors,
    "tech_lead": tech_lead.handle_cors,
}

ENV_HANDLERS = {
    "intern": intern.handle_env,
    "junior": junior.handle_env,
    "senior": senior.handle_env,
    "tech_lead": tech_lead.handle_env,
}


@router.get("")
async def misconfig_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the misconfig challenge page."""
    return templates.TemplateResponse(
        request=request,
        name="challenges/misconfig.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "challenge_name": "Security Misconfiguration",
            "challenge_category": "A02 Security Misconfiguration",
        },
    )


@router.get("/debug")
async def debug_endpoint(
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    """Debug endpoint that leaks environment and configuration.

    OWASP: A02:2025 Security Misconfiguration
    CWE: CWE-215 (Insertion of Sensitive Information Into Debugging Code)

    Dispatches to tier-specific handler.
    """
    difficulty = request.state.difficulty
    handler = DEBUG_HANDLERS[difficulty]
    result = handler()

    # Solve challenge at tiers where information is actually leaked
    if difficulty != "tech_lead":
        await solve_if(
            db=db,
            challenge_key="misconfig_debug",
            condition=lambda: True,
            ws_manager=manager,
        )

    return result


@router.get("/cors-test")
async def cors_test(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict:
    """Endpoint with misconfigured CORS headers.

    OWASP: A02:2025 Security Misconfiguration
    CWE: CWE-942 (Permissive Cross-domain Policy)

    Dispatches to tier-specific handler.
    """
    difficulty = request.state.difficulty
    origin = request.headers.get("origin", "")
    handler = CORS_HANDLERS[difficulty]
    data, headers = handler(origin)

    for key, value in headers.items():
        response.headers[key] = value

    # Solve challenge based on tier:
    # Intern: auto-solves on visit (the point is seeing the misconfiguration)
    # Junior+: requires the player to send a cross-origin request with an Origin header
    if difficulty == "intern":
        await solve_if(
            db=db,
            challenge_key="misconfig_cors",
            condition=lambda: True,
            ws_manager=manager,
        )
    elif difficulty in ("junior", "senior"):
        has_cross_origin = origin != "" and "localhost" not in origin and "127.0.0.1" not in origin
        await solve_if(
            db=db,
            challenge_key="misconfig_cors",
            condition=lambda: has_cross_origin,
            ws_manager=manager,
        )

    return data


@router.get("/.env")
async def env_file(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """Serve the .env file at lower difficulty tiers.

    CWE: CWE-538 (Insertion of Sensitive Information into Externally-Accessible File)

    Dispatches to tier-specific handler.
    """
    difficulty = request.state.difficulty
    handler = ENV_HANDLERS[difficulty]
    content, status_code = handler()

    if status_code == 404:
        return Response(content="404 Not Found", status_code=404)

    await solve_if(
        db=db,
        challenge_key="info_disclosure",
        condition=lambda: True,
        ws_manager=manager,
    )

    return Response(
        content=content,
        media_type="text/plain",
    )

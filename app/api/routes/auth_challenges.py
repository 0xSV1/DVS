"""JWT authentication challenge routes.

Challenges: auth_jwt_none, auth_jwt_weak
Users can view their JWT, forge tokens, and submit them for verification.
"""

from __future__ import annotations

import base64
import json
import logging

import jwt
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.auth.handlers import intern as auth_intern
from app.vulnerabilities.auth.handlers import junior as auth_junior
from app.vulnerabilities.auth.handlers import senior as auth_senior
from app.vulnerabilities.auth.handlers import tech_lead as auth_tech_lead

VERIFY_HANDLERS = {
    "intern": auth_intern.verify_token,
    "junior": auth_junior.verify_token,
    "senior": auth_senior.verify_token,
    "tech_lead": auth_tech_lead.verify_token,
}

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/challenges/auth", tags=["auth-challenges"])


def _decode_token_parts(token: str) -> dict | None:
    """Decode a JWT into its header, payload, and signature for display."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        return {
            "header": json.dumps(header, indent=2),
            "payload": json.dumps(payload, indent=2),
            "signature": parts[2] if len(parts) > 2 else "(none)",
            "raw": token,
        }
    except Exception:
        return None


@router.get("")
async def auth_challenge_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the JWT authentication challenge page."""
    difficulty = request.state.difficulty
    current_token = request.cookies.get("access_token", "")
    token_parts = _decode_token_parts(current_token) if current_token else None

    return templates.TemplateResponse(
        request=request,
        name="challenges/auth_jwt.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "token_parts": token_parts,
            "result": None,
            "challenge_name": "JWT Authentication",
            "challenge_category": "A07 Auth Failures",
        },
    )


@router.post("/verify")
async def verify_jwt(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Verify a user-submitted JWT token.

    At intern tier, the 'none' algorithm is accepted (CWE-345).
    At junior/senior tier, the JWT uses weak secret "secret" (CWE-326).
    At tech_lead tier, strong secret with proper validation.
    """
    difficulty = request.state.difficulty
    form = await request.form()
    submitted_token = form.get("token", "")

    result = {"success": False, "message": "", "decoded": None}

    try:
        verify_handler = VERIFY_HANDLERS.get(difficulty, VERIFY_HANDLERS["intern"])
        decoded = verify_handler(submitted_token)
        if decoded is None:
            raise jwt.InvalidTokenError("Token verification failed")

        result["decoded"] = json.dumps(decoded, indent=2, default=str)

        # Check if the user forged an admin token
        claimed_role = decoded.get("role", "")
        claimed_sub = decoded.get("sub", "")

        is_forged = False
        if current_user:
            is_forged = str(claimed_sub) != str(current_user.id) or claimed_role == "admin"
        else:
            is_forged = claimed_role == "admin" or claimed_sub != ""

        if is_forged:
            result["success"] = True
            result["message"] = f"Token accepted! Claims: role={claimed_role}, sub={claimed_sub}"

            # Check for 'none' algorithm bypass
            try:
                header = json.loads(base64.urlsafe_b64decode(submitted_token.split(".")[0] + "=="))
                if header.get("alg", "").lower() == "none":
                    await solve_if(
                        db=db,
                        challenge_key="auth_jwt_none",
                        condition=lambda: True,
                        ws_manager=manager,
                    )
            except Exception:
                pass

            # Check for weak secret crack (forged admin token with HS256 only).
            # Tokens with alg:none must not count - that is a different attack.
            if claimed_role == "admin":
                try:
                    token_header = json.loads(base64.urlsafe_b64decode(submitted_token.split(".")[0] + "=="))
                    token_alg = token_header.get("alg", "").lower()
                except Exception:
                    token_alg = ""
                if token_alg == "hs256":
                    await solve_if(
                        db=db,
                        challenge_key="auth_jwt_weak",
                        condition=lambda: True,
                        ws_manager=manager,
                    )
        else:
            result["message"] = "Token is valid but not forged. Try changing the claims."

    except jwt.InvalidTokenError as e:
        result["message"] = f"Token rejected: {e}"
    except Exception as e:
        result["message"] = f"Error: {e}"

    # Re-get token_parts for display
    current_token = request.cookies.get("access_token", "")
    token_parts = _decode_token_parts(current_token) if current_token else None

    return templates.TemplateResponse(
        request=request,
        name="challenges/auth_jwt.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "token_parts": token_parts,
            "result": result,
            "challenge_name": "JWT Authentication",
            "challenge_category": "A07 Auth Failures",
        },
    )

"""Admin panel routes.

At intern tier: accessible without role check (idor_admin challenge).
At tech_lead tier: requires role=admin.

OWASP: A01:2025 Broken Access Control
CWE: CWE-269 (Improper Privilege Management)
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.challenge import Challenge
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.idor.handlers import intern as idor_intern
from app.vulnerabilities.idor.handlers import junior as idor_junior
from app.vulnerabilities.idor.handlers import senior as idor_senior
from app.vulnerabilities.idor.handlers import tech_lead as idor_tech_lead

ACCESS_HANDLERS = {
    "intern": idor_intern.check_admin_access,
    "junior": idor_junior.check_admin_access,
    "senior": idor_senior.check_admin_access,
    "tech_lead": idor_tech_lead.check_admin_access,
}

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("")
async def admin_panel(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Admin panel. Access control depends on difficulty tier."""
    difficulty = request.state.difficulty

    access_handler = ACCESS_HANDLERS.get(difficulty, ACCESS_HANDLERS["intern"])
    allowed, error_message = access_handler(current_user)
    if not allowed:
        return templates.TemplateResponse(
            request=request,
            name="challenges/admin.html",
            context={
                "current_user": current_user,
                "difficulty": difficulty,
                "access_denied": True,
                "users": [],
                "stats": {},
                "challenge_name": "Promotion Without the Standup",
                "challenge_category": "A01 Broken Access Control",
            },
        )

    # If we get here, user has access
    users = db.query(User).all()
    challenges = db.query(Challenge).all()

    user_list = [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "api_key": u.api_key,
        }
        for u in users
    ]

    stats = {
        "total_users": len(users),
        "total_challenges": len(challenges),
        "solved_challenges": sum(1 for c in challenges if c.solved),
        "admin_users": sum(1 for u in users if u.role == "admin"),
    }

    # Challenge: idor_admin
    # At intern/junior: solves when ANY user reaches the panel (the point is
    # that access control is completely absent, so even being here is the vuln).
    # At senior: solves when a user whose account is NOT "admin" reaches the
    # panel. This forces the player to forge a JWT or find another path, since
    # simply logging in as admin doesn't count.
    # At tech_lead: non-admins can't reach here (role verified from DB), so
    # it won't solve.
    if difficulty in ("intern", "junior"):
        # Any access to the admin panel proves broken access control
        reached_panel = True
    else:
        # Must be a non-admin account that bypassed the auth check
        reached_panel = current_user is not None and current_user.username != "admin"
    await solve_if(
        db=db,
        challenge_key="idor_admin",
        condition=lambda: reached_panel,
        ws_manager=manager,
    )

    return templates.TemplateResponse(
        request=request,
        name="challenges/admin.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "access_denied": False,
            "users": user_list,
            "stats": stats,
            "challenge_name": "Promotion Without the Standup",
            "challenge_category": "A01 Broken Access Control",
        },
    )

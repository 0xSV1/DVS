"""IDOR vulnerability module router.

Dispatches to the appropriate tier handler for user profile access.
Integrates solve_if() for challenge detection.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.idor.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/idor", tags=["idor"])

HANDLERS = {
    "intern": intern.handle_profile,
    "junior": junior.handle_profile,
    "senior": senior.handle_profile,
    "tech_lead": tech_lead.handle_profile,
}

ORDER_ACCESS_HANDLERS = {
    "intern": intern.check_order_access,
    "junior": junior.check_order_access,
    "senior": senior.check_order_access,
    "tech_lead": tech_lead.check_order_access,
}


@router.get("")
async def idor_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the IDOR challenge landing page."""
    users = db.query(User).all()
    return templates.TemplateResponse(
        request=request,
        name="challenges/idor.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "profile": None,
            "target_id": None,
            "users": [{"id": u.id, "username": u.username} for u in users],
            "order": None,
            "show_user_directory": True,
            "challenge_name": "Broken Access Control",
            "challenge_category": "A01 Broken Access Control",
        },
    )


@router.get("/profile/{user_id}")
async def view_profile(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """View a user profile, dispatched to tier handler."""
    difficulty = request.state.difficulty
    handler = HANDLERS.get(difficulty, HANDLERS["intern"])

    profile = handler(db, user_id, current_user)

    # Challenge: idor_profile
    # Solved only on vulnerable tiers where cross-user profile access exposes
    # private fields without proper authorization. Admin views at secure tiers
    # are legitimate and must not register as IDOR solves.
    if profile and not profile.get("error"):
        viewed_other = current_user is not None and current_user.id != user_id
        vulnerable_tier = difficulty in {"intern", "junior"}
        sensitive_exposed = any(k in profile for k in ("email", "role", "api_key", "password_hash"))
        await solve_if(
            db=db,
            challenge_key="idor_profile",
            condition=lambda: vulnerable_tier and viewed_other and sensitive_exposed,
            ws_manager=manager,
        )

    users = db.query(User).all()
    return templates.TemplateResponse(
        request=request,
        name="challenges/idor.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "profile": profile,
            "target_id": user_id,
            "users": [{"id": u.id, "username": u.username} for u in users],
            "order": None,
            "show_user_directory": True,
            "challenge_name": "Other People's OKRs",
            "challenge_category": "A01 Broken Access Control",
        },
    )


@router.get("/order/{order_id}")
async def view_order(
    order_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """View order details. IDOR at intern/junior tiers.

    OWASP: A01:2025 Broken Access Control
    CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
    """
    from app.models.product import Order

    difficulty = request.state.difficulty

    base_context = {
        "current_user": current_user,
        "difficulty": difficulty,
        "profile": None,
        "target_id": None,
        "users": [],
        "order": None,
        "show_user_directory": False,
        "challenge_name": "Peek at the Cap Table",
        "challenge_category": "A01 Broken Access Control",
    }

    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        base_context["profile"] = {"error": f"Order #{order_id} not found."}
        return templates.TemplateResponse(
            request=request,
            name="challenges/idor.html",
            context=base_context,
        )

    access_handler = ORDER_ACCESS_HANDLERS.get(difficulty, ORDER_ACCESS_HANDLERS["intern"])
    allowed, error_msg = access_handler(current_user, order.user_id)
    if not allowed:
        base_context["profile"] = {"error": error_msg}
        return templates.TemplateResponse(
            request=request,
            name="challenges/idor.html",
            context=base_context,
        )

    order_data = {
        "id": order.id,
        "user_id": order.user_id,
        "product_id": order.product_id,
        "quantity": order.quantity,
        "total_price": order.total_price,
        "status": order.status,
        "shipping_address": order.shipping_address,
        "credit_card_last4": order.credit_card_last4,
        "created_at": str(order.created_at) if order.created_at else None,
    }

    # Challenge: idor_order
    # Only solves when an authenticated user views an order that belongs to
    # someone else. Unauthenticated visits don't count; the player must log
    # in as one user and access another user's order by enumerating IDs.
    viewed_others_order = current_user is not None and current_user.id != order.user_id
    await solve_if(
        db=db,
        challenge_key="idor_order",
        condition=lambda: viewed_others_order,
        ws_manager=manager,
    )

    base_context["order"] = order_data
    return templates.TemplateResponse(
        request=request,
        name="challenges/idor.html",
        context=base_context,
    )

"""IDOR Profile: Tech Lead Tier (Actually Secure)

OWASP: A01:2025 Broken Access Control
CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
Difficulty: Tech Lead

Security: Strict ownership check using database-sourced role (not JWT).
Non-owners see only public fields. Admins verified via fresh DB query.
No sensitive fields exposed. This is the reference implementation.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.user import User


def handle_profile(db: Session, user_id: int, current_user: User | None) -> dict | None:
    """Fetch user profile with proper authorization.

    Args:
        db: Database session.
        user_id: Target user ID from URL path.
        current_user: Authenticated user; strict ownership verified.

    Returns:
        User profile dict with appropriate field visibility, or error/None.
    """
    if not current_user:
        return {"error": "Authentication required", "status": 401}

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

    # Re-verify role from DB (not from JWT claims)
    db_current = db.query(User).filter(User.id == current_user.id).first()
    is_owner = db_current and db_current.id == user_id
    is_admin = db_current and db_current.role == "admin"

    if not is_owner and not is_admin:
        # Return only public fields for non-owners
        return {
            "id": user.id,
            "username": user.username,
            "bio": user.bio,
        }

    # Owner or admin sees full profile (minus secrets)
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "bio": user.bio,
        "is_active": user.is_active,
        "created_at": str(user.created_at) if user.created_at else None,
    }


def check_order_access(current_user: User | None, order_user_id: int) -> tuple[bool, str | None]:
    """Check order access: strict ownership check.

    Args:
        current_user: Currently authenticated user.
        order_user_id: Owner of the order.

    Returns:
        Tuple of (allowed, error_message).
    """
    return (
        current_user is not None and current_user.id == order_user_id,
        "Access denied: you can only view your own orders",
    )


def check_admin_access(current_user: User | None) -> tuple[bool, str | None]:
    """Check admin panel access: requires authentication and admin role.

    Args:
        current_user: Currently authenticated user.

    Returns:
        Tuple of (allowed, error_message).
    """
    return (
        current_user is not None and current_user.role == "admin",
        "Admin access required",
    )

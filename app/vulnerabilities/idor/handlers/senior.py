"""IDOR Profile: Senior Tier (Code Reviewed)

OWASP: A01:2025 Broken Access Control
CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
Difficulty: Senior

Vulnerability: Ownership check is present, but admins can view any
profile. The check uses the role from the JWT claims rather than from
the database, enabling privilege escalation if the JWT secret is
compromised (which it is at intern/junior tier).

Exploit: Forge a JWT with role=admin, then access any profile.
Fix: Always check role from database, not JWT claims (see tech_lead.py)
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.user import User


def handle_profile(db: Session, user_id: int, current_user: User | None) -> dict | None:
    """Fetch user profile with ownership check (but JWT-based role check).

    Args:
        db: Database session.
        user_id: Target user ID from URL path.
        current_user: Authenticated user; ownership or admin role checked.

    Returns:
        User profile dict with sensitive fields removed, or error/None.
    """
    if not current_user:
        return {"error": "Authentication required", "status": 401}

    # Check ownership OR admin role
    if current_user.id != user_id and current_user.role != "admin":
        return {"error": "Access denied", "status": 403}

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

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
    """Check order access: requires authentication but not ownership.

    Args:
        current_user: Currently authenticated user.
        order_user_id: Owner of the order (ignored).

    Returns:
        Tuple of (allowed, error_message).
    """
    return (current_user is not None, "Authentication required")


def check_admin_access(current_user: User | None) -> tuple[bool, str | None]:
    """Check admin panel access: requires authentication but not admin role.

    Args:
        current_user: Currently authenticated user.

    Returns:
        Tuple of (allowed, error_message).
    """
    return (current_user is not None, "Authentication required")

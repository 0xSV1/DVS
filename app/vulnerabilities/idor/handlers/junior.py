"""IDOR Profile: Junior Tier (Copilot Assisted)

OWASP: A01:2025 Broken Access Control
CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
Difficulty: Junior

Vulnerability: Checks if user is authenticated but does NOT check if
the requested profile belongs to them. Removes password_hash from
response but still leaks API keys and emails.

Exploit: Log in as any user, then GET /challenges/idor/profile/1
Fix: Verify ownership or admin role (see tech_lead.py)
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.user import User


def handle_profile(db: Session, user_id: int, current_user: User | None) -> dict | None:
    """Fetch user profile with auth check but no ownership check.

    Args:
        db: Database session.
        user_id: Target user ID from URL path.
        current_user: Must be authenticated, but any user can view any profile.

    Returns:
        User profile dict (without password_hash but with API key), or None.
    """
    if not current_user:
        return {"error": "Authentication required", "status": 401}

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

    # "Fixed": removed password_hash. Still leaks everything else.
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "bio": user.bio,
        "api_key": user.api_key,  # Still leaks API key
        "is_active": user.is_active,
        "created_at": str(user.created_at) if user.created_at else None,
    }


def check_order_access(current_user: User | None, order_user_id: int) -> tuple[bool, str | None]:
    """Check order access: no access control at all.

    Args:
        current_user: Currently authenticated user (ignored).
        order_user_id: Owner of the order (ignored).

    Returns:
        Tuple of (allowed, error_message). Always allows access.
    """
    return (True, None)


def check_admin_access(current_user: User | None) -> tuple[bool, str | None]:
    """Check admin panel access: no access control at all.

    Args:
        current_user: Currently authenticated user (ignored).

    Returns:
        Tuple of (allowed, error_message). Always allows access.
    """
    return (True, None)

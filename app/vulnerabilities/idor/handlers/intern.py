"""IDOR Profile: Intern Tier (Deployed Blindly)

OWASP: A01:2025 Broken Access Control
CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
Difficulty: Intern

Vulnerability: No authorization check at all. Any user can view any
other user's profile by changing the ID in the URL. Also exposes
sensitive fields like API keys and password hashes.

Exploit: GET /challenges/idor/profile/1 (view admin's full profile)
Fix: Verify ownership or admin role (see tech_lead.py)
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.user import User


def handle_profile(db: Session, user_id: int, current_user: User | None) -> dict | None:
    """Fetch any user profile without authorization check.

    Args:
        db: Database session.
        user_id: Target user ID from URL path.
        current_user: Currently authenticated user (ignored).

    Returns:
        Full user profile dict including sensitive fields, or None if not found.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

    # AI said returning all fields is fine for the API
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "bio": user.bio,
        "api_key": user.api_key,  # Leaks API key
        "password_hash": user.password_hash,  # Leaks password hash
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

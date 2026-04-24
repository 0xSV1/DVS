"""Shared dependencies for route handlers.

Provides:
- get_db: database session dependency
- get_current_user: JWT-based auth dependency (tier-aware)
- templates: shared Jinja2Templates instance
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

from fastapi import Depends, HTTPException, Request, status
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.database import SessionLocal
from app.models.user import User

# Jinja2 templates instance, shared across all routes
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def get_db() -> Generator[Session, None, None]:
    """Yield a database session, closing it when done."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User | None:
    """Extract the current user from JWT in cookie or Authorization header.

    Returns None if no valid token is found (allows anonymous access).
    Raises 401 only when used with get_required_user.
    """
    difficulty = getattr(request.state, "difficulty", "intern")

    # Check cookie first, then Authorization header
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        return None

    payload = decode_access_token(token, difficulty=difficulty)
    if payload is None:
        return None

    user_id = payload.get("sub")
    if user_id is None:
        return None

    user = db.query(User).filter(User.id == int(user_id)).first()
    return user


def get_required_user(
    user: User | None = Depends(get_current_user),
) -> User:
    """Require an authenticated user. Raises 401 if not logged in."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user

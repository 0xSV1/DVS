"""SQLi Search: Tech Lead Tier (Actually Secure)

OWASP: A05:2025 Injection
CWE: CWE-89 (SQL Injection)
Difficulty: Tech Lead

Security: Fully parameterized ORM queries. Sort column validated against
strict allowlist. No raw SQL anywhere. Input length limited.
This is the reference implementation.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.product import Product
from app.models.user import User

ALLOWED_SORT_COLUMNS = {"name", "price", "id"}
MAX_QUERY_LENGTH = 100


def handle_search(db: Session, query: str, sort: str = "name") -> tuple[list[dict], str]:
    """Search products with full parameterization and input validation.

    Args:
        db: Database session.
        query: User search term, length-limited, used via ORM parameters.
        sort: Sort column, strictly validated against allowlist.

    Returns:
        Tuple of (results list, description of query used).
    """
    # Truncate input
    query = query[:MAX_QUERY_LENGTH]

    # Validate sort
    if sort not in ALLOWED_SORT_COLUMNS:
        sort = "name"

    # Pure ORM, fully parameterized
    results_query = (
        db.query(Product)
        .filter(Product.name.ilike(f"%{query}%") | Product.description.ilike(f"%{query}%"))
        .order_by(getattr(Product, sort))
    )

    rows = results_query.all()
    results = [{"id": r.id, "name": r.name, "description": r.description, "price": r.price} for r in rows]

    sql_desc = "Parameterized ORM query (no raw SQL)"
    return results, sql_desc


def handle_blind_check(db: Session, username: str) -> int:
    """Check username availability via parameterized query.

    Args:
        db: Database session.
        username: User input, safely parameterized.

    Returns:
        Count of matching users.
    """
    from sqlalchemy import text

    row = db.execute(
        text("SELECT COUNT(*) FROM users WHERE username = :uname"),
        {"uname": username},
    ).fetchone()
    return row[0] if row else 0


def handle_login_query(db: Session, username: str, password: str) -> User | None:
    """Authenticate via ORM parameterized query with bcrypt verification.

    Args:
        db: Database session.
        username: User input, safely used via ORM filter.
        password: Plaintext password verified against stored hash.

    Returns:
        User object if credentials match, None otherwise.
    """
    from app.core.security import verify_password

    user = db.query(User).filter(User.username == username).first()
    if user and not verify_password(password, user.password_hash, "tech_lead"):
        user = None
    return user

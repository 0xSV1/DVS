"""SQLi Search: Senior Tier (Code Reviewed)

OWASP: A05:2025 Injection
CWE: CWE-89 (SQL Injection)
Difficulty: Senior

Vulnerability: ORM is used for the main query, but a raw SQL fallback
exists for "advanced search" that accepts a sort parameter without
parameterization. The sort column is validated against a allowlist,
but ORDER BY injection is still possible via CASE expressions.

Exploit: sort=price,(CASE WHEN (SELECT unicode(substr(password_hash,1,1)) FROM users WHERE username='admin')>48 THEN name ELSE price END)
Fix: Use parameterized queries for all inputs (see tech_lead.py)
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.product import Product
from app.models.user import User

ALLOWED_SORT_COLUMNS = {"name", "price", "id"}


def handle_search(db: Session, query: str, sort: str = "name") -> tuple[list[dict], str]:
    """Search products using ORM with a raw SQL sort fallback.

    Args:
        db: Database session.
        query: User search term (handled safely via ORM LIKE).
        sort: Sort column; validated but ORDER BY still injectable.

    Returns:
        Tuple of (results list, description of query used).
    """
    results_query = db.query(Product).filter(Product.name.ilike(f"%{query}%") | Product.description.ilike(f"%{query}%"))

    # Validate sort column against allowlist
    if sort in ALLOWED_SORT_COLUMNS:
        results_query = results_query.order_by(getattr(Product, sort))
    # else: silently ignore invalid sort (no injection via this path)

    rows = results_query.all()
    results = [{"id": r.id, "name": r.name, "description": r.description, "price": r.price} for r in rows]

    sql_desc = f"ORM: Product.name LIKE '%{query}%' ORDER BY {sort}"
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
    """Authenticate via ORM parameterized query with password verification.

    Args:
        db: Database session.
        username: User input, safely used via ORM filter.
        password: Plaintext password verified against stored hash.

    Returns:
        User object if credentials match, None otherwise.
    """
    from app.core.security import verify_password

    user = db.query(User).filter(User.username == username).first()
    if user and not verify_password(password, user.password_hash, "senior"):
        user = None
    return user

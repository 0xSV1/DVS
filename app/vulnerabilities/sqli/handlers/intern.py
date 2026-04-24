"""SQLi Search: Intern Tier (Deployed Blindly)

OWASP: A05:2025 Injection
CWE: CWE-89 (SQL Injection)
Difficulty: Intern

Vulnerability: Raw f-string interpolation into SQL query.
No input validation, no parameterization, no WAF.

Exploit: ' OR 1=1 --
Fix: Use parameterized queries (see tech_lead.py)
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.user import User


def handle_search(db: Session, query: str) -> tuple[list[dict], str]:
    """Search products with zero protection.

    Args:
        db: Database session.
        query: Raw user input, interpolated directly into SQL.

    Returns:
        Tuple of (results list, raw SQL string used).
    """
    # AI said this is fine
    sql = (
        f"SELECT id, name, description, price FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
    )
    try:
        rows = db.execute(text(sql)).fetchall()
        results = [{"id": r[0], "name": r[1], "description": r[2], "price": r[3]} for r in rows]
    except Exception as e:
        # Intern tier: leak full error to the user (A10 Mishandling)
        results = [{"error": str(e)}]
        sql = f"{sql} -- ERROR: {e}"

    return results, sql


def handle_blind_check(db: Session, username: str) -> int:
    """Check username availability via raw f-string SQL.

    Args:
        db: Database session.
        username: Raw user input, interpolated directly into SQL.

    Returns:
        Count of matching users.
    """
    sql = f"SELECT COUNT(*) FROM users WHERE username = '{username}'"
    row = db.execute(text(sql)).fetchone()
    return row[0] if row else 0


def handle_login_query(db: Session, username: str, password: str) -> User | None:
    """Authenticate via raw f-string SQL with MD5 hash.

    Args:
        db: Database session.
        username: Raw user input, interpolated directly into SQL.
        password: Plaintext password, MD5-hashed before interpolation.

    Returns:
        User object if found, None otherwise.
    """
    import hashlib
    import logging

    logger = logging.getLogger(__name__)
    query = text(
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' "
        f"AND password_hash = '{hashlib.md5(password.encode()).hexdigest()}'"
    )
    try:
        result = db.execute(query).fetchone()
        if result:
            return db.query(User).filter(User.id == result[0]).first()
    except Exception:
        logger.exception("SQL error during intern login")
    return None

"""SQLi Search: Junior Tier (Copilot Assisted)

OWASP: A05:2025 Injection
CWE: CWE-89 (SQL Injection)
Difficulty: Junior

Vulnerability: Keyword blacklist blocks common SQL injection terms (OR,
UNION, SELECT, DROP, etc.) but uses case-sensitive matching. Bypassed
with mixed case (e.g., Or, oR), SQL comments (o/**/r), or alternative
syntax.

Exploit: ' Or 1=1 --
Exploit: ' UNION/**/SELECT 1,2,3,4 --
Fix: Use parameterized queries (see tech_lead.py)
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.user import User

# Case-sensitive blacklist: blocks exact lowercase matches only
# Blocks common casings of SQL keywords but misses mixed case (Or, oR, etc.)
# and comment-split variants (o/**/r). The classic blacklist bypass lesson.
_SEARCH_BLACKLIST = [
    "or ",
    "OR ",
    "and ",
    "AND ",
    "union ",
    "UNION ",
    "select ",
    "SELECT ",
    "drop ",
    "DROP ",
    "insert ",
    "INSERT ",
    "update ",
    "UPDATE ",
    "delete ",
    "DELETE ",
]

# Login blacklist also blocks comment syntax to prevent simple comment-out attacks.
# Bypass: use mixed case keywords or block comments (admin'/*).
_LOGIN_BLACKLIST = [
    *_SEARCH_BLACKLIST,
    "--",
    ";",
]


def _check_blacklist(value: str, blocklist: list[str] | None = None) -> str | None:
    """Check input against a keyword blacklist.

    Returns the blocked keyword if found, None if input passes.
    Only checks exact string matches, so mixed case bypasses keyword entries.
    """
    for keyword in blocklist or _SEARCH_BLACKLIST:
        if keyword in value:
            return keyword
    return None


def handle_search(db: Session, query: str) -> tuple[list[dict], str]:
    """Search products with keyword blacklist defense.

    The blacklist blocks common lowercase SQL keywords but is trivially
    bypassed with mixed case, comments, or alternate syntax.

    Args:
        db: Database session.
        query: User input checked against a keyword blacklist.

    Returns:
        Tuple of (results list, raw SQL string used).
    """
    blocked = _check_blacklist(query)
    if blocked:
        return [], f"-- BLOCKED: input contained '{blocked}' (SQL keyword blacklist)"

    sql = (
        f"SELECT id, name, description, price FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
    )
    try:
        rows = db.execute(text(sql)).fetchall()
        results = [{"id": r[0], "name": r[1], "description": r[2], "price": r[3]} for r in rows]
    except Exception:
        results = []
        sql = f"{sql} -- query failed"

    return results, sql


def handle_blind_check(db: Session, username: str) -> int:
    """Check username availability with keyword blacklist.

    Args:
        db: Database session.
        username: User input checked against a keyword blacklist.

    Returns:
        Count of matching users, or 0 if blocked.
    """
    if _check_blacklist(username):
        return 0
    sql = f"SELECT COUNT(*) FROM users WHERE username = '{username}'"
    row = db.execute(text(sql)).fetchone()
    return row[0] if row else 0


def handle_login_query(db: Session, username: str, password: str) -> User | None:
    """Authenticate via f-string SQL with keyword blacklist.

    The blacklist blocks common injection keywords in lowercase but
    mixed case bypasses it.

    Args:
        db: Database session.
        username: User input checked against keyword blacklist.
        password: Plaintext password, MD5-hashed before interpolation.

    Returns:
        User object if found, None otherwise.
    """
    import hashlib
    import logging

    logger = logging.getLogger(__name__)

    if _check_blacklist(username, _LOGIN_BLACKLIST):
        return None

    safe_password = hashlib.md5(password.encode()).hexdigest()
    query = text(
        f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{safe_password}'"
    )
    try:
        result = db.execute(query).fetchone()
        if result:
            return db.query(User).filter(User.id == result[0]).first()
    except Exception:
        logger.exception("SQL error during junior login")
    return None

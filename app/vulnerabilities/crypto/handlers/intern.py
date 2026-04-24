"""Crypto Hashes: Intern Tier (Deployed Blindly)

OWASP: A04:2025 Cryptographic Failures
CWE: CWE-328 (Use of Weak Hash)
Difficulty: Intern

Vulnerability: Password hashes stored as unsalted MD5 and exposed to any user.
Algorithm is labeled in the response, making identification trivial.

Exploit: Copy the MD5 hash, look it up in a rainbow table or crack with hashcat.
Fix: Use bcrypt/argon2 with per-user salts and never expose hashes (see tech_lead.py).
"""

from __future__ import annotations

import hashlib

from sqlalchemy.orm import Session

from app.models.user import User


def handle_get_hashes(db: Session) -> list[dict]:
    """Return all user password hashes with the algorithm disclosed.

    Args:
        db: Database session.

    Returns:
        List of dicts with username, hash, and algorithm fields.
    """
    # AI said this is fine
    users = db.query(User).all()
    return [{"username": u.username, "hash": u.password_hash, "algorithm": "MD5 (unsalted)"} for u in users]


def handle_crack(db: Session, username: str, password: str) -> dict:
    """Verify a cracked password against the stored MD5 hash.

    Args:
        db: Database session.
        username: Target username.
        password: Candidate plaintext password.

    Returns:
        Dict with success boolean and message.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return {"success": False, "message": f"User '{username}' not found."}

    md5_hash = hashlib.md5(password.encode()).hexdigest()
    if md5_hash == user.password_hash:
        return {
            "success": True,
            "message": f"Correct! The password for {username} is: {password}",
        }

    return {"success": False, "message": "Incorrect. Try again."}


# -- Hardcoded Secrets Challenge ------------------------------------------

# The actual API key, hardcoded right in the source. AI said this is fine.
_PARTNER_API_KEY = "dbr_partner_S3cr3TK3Y_2026"


def handle_get_secrets() -> dict:
    """Return page context with the API key in plaintext HTML comment and JS variable.

    Args: None.

    Returns:
        Dict with key fragments and decoy for template rendering.
    """
    return {
        "api_key_plaintext": _PARTNER_API_KEY,
        "fragments": None,
        "decoy": None,
    }


def handle_verify_secret(submitted_key: str) -> dict:
    """Check if the submitted API key matches the hardcoded secret.

    Args:
        submitted_key: The key submitted by the player.

    Returns:
        Dict with success boolean and message.
    """
    if submitted_key.strip() == _PARTNER_API_KEY:
        return {
            "success": True,
            "message": f"Correct! The API key is: {_PARTNER_API_KEY}",
        }
    return {"success": False, "message": "Incorrect API key. Keep looking."}

"""Crypto Hashes: Junior Tier (Cosmetic Security)

OWASP: A04:2025 Cryptographic Failures
CWE: CWE-328 (Use of Weak Hash)
Difficulty: Junior

Vulnerability: Same as Intern. Hashes are still unsalted MD5 and fully exposed.
No additional protection at this tier; the "security" is identical.

Exploit: Same as Intern: rainbow table lookup or offline brute force.
Fix: Use bcrypt/argon2 with per-user salts and never expose hashes (see tech_lead.py).
"""

from __future__ import annotations

import base64
import hashlib

from sqlalchemy.orm import Session

from app.models.user import User


def handle_get_hashes(db: Session) -> list[dict]:
    """Return all user password hashes with the algorithm disclosed.

    Identical to Intern tier. The "junior developer" did not improve anything.

    Args:
        db: Database session.

    Returns:
        List of dicts with username, hash, and algorithm fields.
    """
    # TODO: add security later
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

# The actual API key, split and base64-encoded. TODO: move to vault someday
_PARTNER_API_KEY = "dbr_partner_S3cr3TK3Y_2026"

# Base64-encode the key, then split into 3 fragments
_FULL_B64 = base64.b64encode(_PARTNER_API_KEY.encode()).decode()
_FRAG_LEN = len(_FULL_B64) // 3
_FRAGMENT_A = _FULL_B64[:_FRAG_LEN]
_FRAGMENT_B = _FULL_B64[_FRAG_LEN : _FRAG_LEN * 2]
_FRAGMENT_C = _FULL_B64[_FRAG_LEN * 2 :]

# Decoy key that looks plausible but is wrong
_DECOY_KEY = "dbr_test_NOT_A_REAL_KEY"


def handle_get_secrets() -> dict:
    """Return page context with base64 fragments and a decoy.

    The real key is split into 3 base64-encoded fragments in JS variables
    with misleading names. A visible decoy attribute baits careless players.

    Returns:
        Dict with key fragments and decoy for template rendering.
    """
    return {
        "api_key_plaintext": None,
        "fragments": {
            "a": _FRAGMENT_A,
            "b": _FRAGMENT_B,
            "c": _FRAGMENT_C,
        },
        "decoy": _DECOY_KEY,
    }


def handle_verify_secret(submitted_key: str) -> dict:
    """Check if the submitted API key matches the real secret (not the decoy).

    Args:
        submitted_key: The key submitted by the player.

    Returns:
        Dict with success boolean and message.
    """
    stripped = submitted_key.strip()
    if stripped == _DECOY_KEY:
        return {
            "success": False,
            "message": "That's the decoy key. The real one is harder to find.",
        }
    if stripped == _PARTNER_API_KEY:
        return {
            "success": True,
            "message": f"Correct! The API key is: {_PARTNER_API_KEY}",
        }
    return {"success": False, "message": "Incorrect API key. Keep looking."}

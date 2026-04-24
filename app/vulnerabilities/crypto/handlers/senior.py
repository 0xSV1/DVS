"""Crypto Hashes: Senior Tier (Real Security, Subtle Flaw)

OWASP: A04:2025 Cryptographic Failures
CWE: CWE-328 (Use of Weak Hash)
Difficulty: Senior

Vulnerability: Hashes are still exposed, but the algorithm label is stripped.
The underlying hash is still MD5 and crackable; the attacker just needs to
identify the algorithm themselves (trivial for anyone who recognizes the
32-character hex format).

Exploit: Recognize the 32-char hex string as MD5, then crack as before.
Fix: Never expose hashes at all (see tech_lead.py).
"""

from __future__ import annotations

import hashlib
import hmac

from sqlalchemy.orm import Session

from app.models.user import User


def handle_get_hashes(db: Session) -> list[dict]:
    """Return all user password hashes with the algorithm redacted.

    Args:
        db: Database session.

    Returns:
        List of dicts with username, hash, and algorithm fields.
    """
    users = db.query(User).all()
    return [{"username": u.username, "hash": u.password_hash, "algorithm": "Unknown"} for u in users]


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

# Key never sent to client, but used as HMAC secret in X-Request-Signature
_PARTNER_API_KEY = "dbr_partner_S3cr3TK3Y_2026"


def handle_get_secrets() -> dict:
    """Return page context with masked key only.

    No key material in client source. Test Connection returns masked key
    and leaks key as HMAC secret in X-Request-Signature header.

    Returns:
        Dict with masked display and HMAC signature.
    """
    masked = _PARTNER_API_KEY[:4] + "*" * (len(_PARTNER_API_KEY) - 8) + _PARTNER_API_KEY[-4:]
    test_data = "connection_test"
    signature = hmac.new(
        _PARTNER_API_KEY.encode(),
        test_data.encode(),
        hashlib.sha256,
    ).hexdigest()
    return {
        "api_key_plaintext": None,
        "fragments": None,
        "decoy": None,
        "masked_key": masked,
        "signature": signature,
        "test_data": test_data,
    }


def handle_verify_secret(submitted_key: str) -> dict:
    """Check if the submitted API key matches the secret.

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
    return {"success": False, "message": "Incorrect API key."}

"""JWT Verification: Tech Lead Tier (Actually Secure)

OWASP: A07:2025 Identification and Authentication Failures
CWE: CWE-347 (Improper Verification of Cryptographic Signature)
Difficulty: Tech Lead

Security: Strong secret, strict algorithm enforcement, full signature
verification. This is the reference implementation.
"""

from __future__ import annotations

import jwt

from app.core.config import settings


def verify_token(token: str) -> dict | None:
    """Decode a JWT with strong secret and strict verification.

    Args:
        token: Raw JWT string submitted by the user.

    Returns:
        Decoded payload dict, or None on failure.
    """
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None

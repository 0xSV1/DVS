"""JWT Verification: Senior Tier (Code Reviewed)

OWASP: A07:2025 Identification and Authentication Failures
CWE: CWE-347 (Improper Verification of Cryptographic Signature)
Difficulty: Senior

Security: Uses the application's strong SECRET_KEY for verification.
Algorithm restricted to HS256. No known bypass at this tier.
"""

from __future__ import annotations

import jwt

from app.core.config import settings


def verify_token(token: str) -> dict | None:
    """Decode a JWT with strong secret verification.

    Args:
        token: Raw JWT string submitted by the user.

    Returns:
        Decoded payload dict, or None on failure.
    """
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None

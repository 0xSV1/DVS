"""JWT Verification: Junior Tier (Copilot Assisted)

OWASP: A07:2025 Identification and Authentication Failures
CWE: CWE-326 (Inadequate Encryption Strength)
Difficulty: Junior

Vulnerability: Signature is verified, but the secret is the string
"secret", which is trivially brute-forced with tools like hashcat
or jwt_tool.

Exploit: Crack the weak secret, then forge a token with role=admin.
Fix: Use a strong, random secret (see tech_lead.py)
"""

from __future__ import annotations

import jwt

from app.core.security import WEAK_JWT_SECRET


def verify_token(token: str) -> dict | None:
    """Decode a JWT with weak secret verification.

    Args:
        token: Raw JWT string submitted by the user.

    Returns:
        Decoded payload dict, or None on failure.
    """
    try:
        return jwt.decode(token, WEAK_JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None

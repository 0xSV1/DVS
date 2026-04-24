"""JWT Verification: Intern Tier (Deployed Blindly)

OWASP: A07:2025 Identification and Authentication Failures
CWE: CWE-345 (Insufficient Verification of Data Authenticity)
Difficulty: Intern

Vulnerability: Accepts the 'none' algorithm and disables signature
verification entirely. An attacker can forge any token by setting
alg=none and stripping the signature.

Exploit: Craft a JWT with {"alg":"none"}, set role=admin, remove signature.
Fix: Enforce a specific algorithm and verify signature (see tech_lead.py)
"""

from __future__ import annotations

import jwt

from app.core.security import WEAK_JWT_SECRET


def verify_token(token: str) -> dict | None:
    """Decode a JWT without signature verification.

    Args:
        token: Raw JWT string submitted by the user.

    Returns:
        Decoded payload dict, or None on failure.
    """
    try:
        return jwt.decode(
            token,
            WEAK_JWT_SECRET,
            algorithms=["HS256", "none"],
            options={"verify_signature": False},
        )
    except jwt.InvalidTokenError:
        return None

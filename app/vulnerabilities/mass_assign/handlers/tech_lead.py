"""Mass Assignment: Tech Lead Tier (Secure)

OWASP: A01:2025 Broken Access Control
CWE: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
Difficulty: Tech Lead

Mitigation: Strict field allowlist limited to bio only. Input length is capped
at 500 characters. All other fields are silently ignored.
"""

from __future__ import annotations


def handle_update(user, body: dict) -> dict:
    """Apply only bio field with strict length limit."""
    allowed = {"bio"}
    for key, value in body.items():
        if key in allowed:
            setattr(user, key, str(value)[:500])
    return {"success": True, "user": {"username": user.username, "bio": user.bio}}

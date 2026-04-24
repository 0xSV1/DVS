"""Mass Assignment: Junior Tier

OWASP: A01:2025 Broken Access Control
CWE: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
Difficulty: Junior

Vulnerability: All request body fields are applied to the user model, including role.
Identical to intern tier; no field filtering is performed.

Exploit: POST /api/users/me with {"role": "admin"}
Fix: Strict field allowlisting (see tech_lead.py)
"""

from __future__ import annotations


def handle_update(user, body: dict) -> dict:
    """Apply all fields from body to user model without filtering."""
    for key, value in body.items():
        if hasattr(user, key) and key != "id":
            setattr(user, key, value)
    return {
        "success": True,
        "user": {"username": user.username, "role": user.role, "bio": user.bio},
    }

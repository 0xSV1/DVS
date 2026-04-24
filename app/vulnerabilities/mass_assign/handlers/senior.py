"""Mass Assignment: Senior Tier

OWASP: A01:2025 Broken Access Control
CWE: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
Difficulty: Senior

Vulnerability: Allowlist exists but includes email and avatar_url, which could be
leveraged for account takeover via email change or stored XSS via avatar URL.
Role is excluded, so direct privilege escalation is blocked.

Exploit: Change email to attacker-controlled address, then use password reset flow.
Fix: Strict allowlist limited to non-sensitive fields (see tech_lead.py)
"""

from __future__ import annotations


def handle_update(user, body: dict) -> dict:
    """Apply only allowlisted fields, but the allowlist is too broad."""
    allowed = {"bio", "email", "avatar_url"}
    for key, value in body.items():
        if key in allowed:
            setattr(user, key, value)
    return {"success": True, "user": {"username": user.username, "bio": user.bio}}

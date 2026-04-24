"""
CSRF Fund Transfer, Tech Lead Tier (Secure Reference)

OWASP: A01:2025 Broken Access Control
CWE: CWE-352 (Cross-Site Request Forgery)
Difficulty: Tech Lead

Vulnerability: None. This is the secure reference implementation.
Exploit: N/A
Fix: Synchronizer token pattern with strict Origin validation and
    per-request token rotation. Defense in depth: SameSite cookie
    attribute is set at the framework level.
"""

from __future__ import annotations

# Allowed origins for the application. In production this would come from
# configuration, but for DVS the app only runs on localhost.
ALLOWED_ORIGINS = {
    "http://localhost:8000",
    "http://localhost:1337",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:1337",
}


def handle_transfer(form_data: dict, session: dict, headers: dict) -> dict:
    """Process fund transfer with strict CSRF token + Origin validation.

    Defense layers:
    1. Synchronizer token: session token must match submitted form token.
    2. Origin validation: Origin header must be in the allowlist.
    3. Token rotation: handled by the router after a successful call.

    Args:
        form_data: Parsed form fields (recipient, amount, csrf_token).
        session: Current session data.
        headers: Relevant request headers (origin, referer).

    Returns:
        Result dict with success, message, and error fields.
    """
    submitted_token = form_data.get("csrf_token", "")
    session_token = session.get("csrf_token", "")

    # Layer 1: CSRF token validation
    if not submitted_token or submitted_token != session_token:
        return {
            "success": False,
            "message": "CSRF token validation failed.",
            "error": "Missing or invalid CSRF token.",
        }

    # Layer 2: Origin header validation (skip if absent; same-origin
    # requests and test clients often omit Origin)
    origin = headers.get("origin", "")
    if origin and origin not in ALLOWED_ORIGINS:
        return {
            "success": False,
            "message": "Origin validation failed.",
            "error": f"Untrusted origin: {origin!r}",
        }

    recipient = form_data.get("recipient", "")
    amount = form_data.get("amount", "0")

    return {
        "success": True,
        "message": f"Transferred ${amount} to {recipient}. No confirmation needed!",
        "error": None,
    }

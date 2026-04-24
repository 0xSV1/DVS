"""
CSRF Fund Transfer, Senior Tier

OWASP: A01:2025 Broken Access Control
CWE: CWE-352 (Cross-Site Request Forgery)
Difficulty: Senior

Vulnerability: Uses a synchronizer token pattern (session-stored CSRF token
    compared against submitted form token) but does not validate the Origin
    or Referer headers. The token itself is not rotated after use, so a
    leaked token via XSS or network sniffing remains valid for the entire
    session lifetime.
Exploit: Combine with an XSS vulnerability to extract the CSRF token from
    the DOM, then replay it in a cross-origin request.
Fix: Add strict Origin header validation and rotate tokens after each use
    (see tech_lead.py).
"""

from __future__ import annotations


def handle_transfer(form_data: dict, session: dict, headers: dict) -> dict:
    """Process fund transfer with CSRF token validation but no origin check.

    Args:
        form_data: Parsed form fields (recipient, amount, csrf_token).
        session: Current session data.
        headers: Relevant request headers (origin, referer).

    Returns:
        Result dict with success, message, and error fields.
    """
    submitted_token = form_data.get("csrf_token", "")
    session_token = session.get("csrf_token", "")

    if not submitted_token or submitted_token != session_token:
        return {
            "success": False,
            "message": "CSRF token validation failed.",
            "error": "Missing or invalid CSRF token.",
        }

    # No origin validation, no token rotation
    recipient = form_data.get("recipient", "")
    amount = form_data.get("amount", "0")

    return {
        "success": True,
        "message": f"Transferred ${amount} to {recipient}. No confirmation needed!",
        "error": None,
    }

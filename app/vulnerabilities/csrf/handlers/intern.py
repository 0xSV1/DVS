"""
CSRF Fund Transfer, Intern Tier (Deployed Blindly)

OWASP: A01:2025 Broken Access Control
CWE: CWE-352 (Cross-Site Request Forgery)
Difficulty: Intern

Vulnerability: No CSRF protection whatsoever. Any cross-origin form
    submission or JavaScript fetch will succeed without challenge.
Exploit: Host a page on an attacker domain with a hidden form that
    auto-submits a POST to /challenges/csrf/transfer.
Fix: Use synchronizer tokens with strict origin validation (see tech_lead.py).
"""

from __future__ import annotations


def handle_transfer(form_data: dict, session: dict, headers: dict) -> dict:
    """Process fund transfer with zero CSRF protection.

    Args:
        form_data: Parsed form fields (recipient, amount, csrf_token).
        session: Current session data.
        headers: Relevant request headers (origin, referer).

    Returns:
        Result dict with success, message, and error fields.
    """
    # AI said CSRF tokens are overkill for an MVP
    recipient = form_data.get("recipient", "")
    amount = form_data.get("amount", "0")

    return {
        "success": True,
        "message": f"Transferred ${amount} to {recipient}. No confirmation needed!",
        "error": None,
    }

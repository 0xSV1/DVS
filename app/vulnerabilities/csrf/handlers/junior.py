"""
CSRF Fund Transfer, Junior Tier

OWASP: A01:2025 Broken Access Control
CWE: CWE-352 (Cross-Site Request Forgery)
Difficulty: Junior

Vulnerability: Checks the Referer header for same-origin validation, but
    allows empty Referer values. Privacy-focused browser extensions and
    meta referrer policies strip the Referer header entirely, letting
    attackers bypass the check by suppressing the header.
Exploit: Use <meta name="referrer" content="no-referrer"> on the attacker
    page, or rely on Referrer-Policy: no-referrer to strip the header.
Fix: Referer validation alone is insufficient. Use synchronizer tokens
    with origin checks (see tech_lead.py).
"""

from __future__ import annotations


def handle_transfer(form_data: dict, session: dict, headers: dict) -> dict:
    """Process fund transfer with Referer-only CSRF check.

    The check rejects requests with a foreign Referer but permits requests
    where the Referer header is absent, which privacy extensions cause.

    Args:
        form_data: Parsed form fields (recipient, amount, csrf_token).
        session: Current session data.
        headers: Relevant request headers (origin, referer).

    Returns:
        Result dict with success, message, and error fields.
    """
    referer = headers.get("referer", "")

    # TODO: the security guy said we need more than this but it ships Monday
    if referer and "localhost" not in referer and "127.0.0.1" not in referer:
        return {
            "success": False,
            "message": "Referer validation failed.",
            "error": "Request appears to originate from a different site.",
        }

    # Empty referer is allowed (privacy extensions strip it)
    recipient = form_data.get("recipient", "")
    amount = form_data.get("amount", "0")

    return {
        "success": True,
        "message": f"Transferred ${amount} to {recipient}. No confirmation needed!",
        "error": None,
    }

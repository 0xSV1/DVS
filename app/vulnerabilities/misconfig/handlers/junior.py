"""Misconfig: Junior Tier (Cosmetic Security)

OWASP: A02:2025 Security Misconfiguration
CWE: CWE-215, CWE-942, CWE-538
Difficulty: Junior

Vulnerability: Debug endpoints still exposed, .env still accessible.
CORS has a cosmetic check: it reflects the Origin header instead of using a
wildcard, but doesn't validate the origin against an allowlist.

Exploit: Send a request with Origin: https://evil.com and the server reflects
it back in Access-Control-Allow-Origin, granting cross-origin access.
Fix: Validate Origin against a strict allowlist (see tech_lead.py).
"""

from __future__ import annotations

from app.vulnerabilities.misconfig.handlers.intern import (
    handle_debug,
    handle_env,
)


def handle_cors(origin: str) -> tuple[dict, dict]:
    """Reflect the Origin header instead of wildcard.

    Looks more secure than wildcard (*) but trusts any origin that sends
    the header. A real attacker just sets Origin: https://evil.com.
    """
    if origin:
        headers = {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST",
        }
        return {
            "cors": "reflected",
            "message": f"Origin '{origin}' reflected. Looks legit to me, bro!",
        }, headers
    # No origin header: return restrictive-looking response
    return {
        "cors": "restricted",
        "message": "No Origin header detected. CORS policy active.",
    }, {}


__all__ = ["handle_cors", "handle_debug", "handle_env"]

"""Misconfig: Tech Lead Tier (Actually Secure)

OWASP: A02:2025 Security Misconfiguration
CWE: CWE-215, CWE-942, CWE-538
Difficulty: Tech Lead

Vulnerability: None. This is the reference implementation.
Debug endpoints return 404, CORS is same-origin only (no headers set),
and .env file access is blocked.

Exploit: N/A
Fix: This IS the fix. Study this tier to understand proper configuration.
"""

from __future__ import annotations


def handle_debug() -> dict:
    """Return 404 error; debug endpoint is disabled."""
    return {"error": "Not found", "status": 404}


def handle_cors(origin: str) -> tuple[dict, dict]:
    """Same-origin only; no CORS headers emitted."""
    return {
        "cors": "same-origin only",
        "message": "No cross-origin access allowed.",
    }, {}


def handle_env() -> tuple[str | None, int]:
    """Block .env file access."""
    return None, 404

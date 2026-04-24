"""Misconfig: Senior Tier (Real Security with Subtle Flaws)

OWASP: A02:2025 Security Misconfiguration
CWE: CWE-215, CWE-942, CWE-538
Difficulty: Senior

Vulnerability: Debug endpoint leaks partial app config (no secrets or env vars).
CORS reflects the Origin header without validation, enabling cross-origin attacks
from any domain. The .env file is no longer served.

Exploit: Send a request with a malicious Origin header to /challenges/misconfig/cors-test
    and observe the reflected Access-Control-Allow-Origin with credentials enabled.
Fix: Validate Origin against an allowlist before reflecting it.
"""

from __future__ import annotations

from app.core.config import settings


def handle_debug() -> dict:
    """Return partial app config leak; no secrets or environment variables."""
    return {
        "app": "Damn Vulnerable Startup",
        "version": settings.APP_VERSION,
        "debug": settings.DEBUG,
        "database": "sqlite (path redacted)",
    }


def handle_cors(origin: str) -> tuple[dict, dict]:
    """Reflect the Origin header without validation."""
    headers = {
        "Access-Control-Allow-Origin": origin or "*",
        "Access-Control-Allow-Credentials": "true",
    }
    return {"cors": "reflected", "origin": origin}, headers


def handle_env() -> tuple[str | None, int]:
    """Block .env file access."""
    return None, 404

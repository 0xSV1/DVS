"""SSRF: Tech Lead Tier (Actually Secure)

OWASP: A01:2025 Broken Access Control
CWE: CWE-918 (Server-Side Request Forgery)
Difficulty: Tech Lead

Security: URL allowlist (only specific domains permitted), scheme
restricted to https only, no redirects followed, response size capped.
This is the reference implementation.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

ALLOWED_DOMAINS = {"example.com", "httpbin.org", "api.github.com"}
MAX_RESPONSE_SIZE = 10000


async def handle_fetch(url: str) -> dict:
    """Fetch a URL with strict allowlist validation.

    Args:
        url: User-supplied URL, validated against domain allowlist.

    Returns:
        Dict with response body or error.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return {"success": False, "error": "Only http/https schemes allowed"}

    hostname = parsed.hostname
    if not hostname or hostname not in ALLOWED_DOMAINS:
        return {
            "success": False,
            "error": f"Domain '{hostname}' not in allowlist. Allowed: {', '.join(sorted(ALLOWED_DOMAINS))}",
        }

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            resp = await client.get(url)
            content = resp.text[:MAX_RESPONSE_SIZE]
            return {
                "success": True,
                "status_code": resp.status_code,
                "content": content,
                "method": "Domain allowlist + HTTPS preferred + no redirects + response size cap.",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}

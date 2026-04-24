"""SSRF: Intern Tier (Deployed Blindly)

OWASP: A01:2025 Broken Access Control (SSRF absorbed into A01 in 2025)
CWE: CWE-918 (Server-Side Request Forgery)
Difficulty: Intern

Vulnerability: User-supplied URL fetched server-side with zero validation.
Can reach internal services, cloud metadata endpoints, and localhost.

Exploit: url=http://169.254.169.254/latest/meta-data/
Exploit: url=http://localhost:8000/api/setup/reset
Fix: URL allowlist + block private ranges (see tech_lead.py)
"""

from __future__ import annotations

import httpx


async def handle_fetch(url: str) -> dict:
    """Fetch a URL server-side with no restrictions.

    Args:
        url: User-supplied URL, fetched as-is.

    Returns:
        Dict with response body or error.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            resp = await client.get(url)
            return {
                "success": True,
                "status_code": resp.status_code,
                "content": resp.text[:5000],
                "headers": dict(resp.headers),
                "url_fetched": str(resp.url),
                "method": "No URL validation. Follows redirects. Can reach internal services.",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}

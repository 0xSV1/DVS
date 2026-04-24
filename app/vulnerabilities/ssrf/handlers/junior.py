"""SSRF: Junior Tier (Copilot Assisted)

OWASP: A01:2025 Broken Access Control
CWE: CWE-918 (Server-Side Request Forgery)
Difficulty: Junior

Vulnerability: Blocks "localhost" and "127.0.0.1" strings but misses:
- 0.0.0.0, [::1], 127.1, 0x7f000001
- DNS rebinding (attacker-controlled domain resolving to 127.0.0.1)
- Decimal IP notation
- Redirect-based bypass (fetch allowed URL that 302s to internal)

Exploit: url=http://0.0.0.0:8000/health
Exploit: url=http://[::1]:8000/health
Fix: Resolve DNS and check IP range (see tech_lead.py)
"""

from __future__ import annotations

import httpx

BLOCKED_HOSTS = [
    "localhost",
    "127.0.0.1",
    "169.254.169.254",
    "metadata.google.internal",
]


async def handle_fetch(url: str) -> dict:
    """Fetch a URL with a flawed host blacklist.

    Args:
        url: User-supplied URL, checked against an incomplete blacklist.

    Returns:
        Dict with response body or error.
    """
    url_lower = url.lower()
    for blocked in BLOCKED_HOSTS:
        if blocked in url_lower:
            return {"success": False, "error": f"Blocked: URL contains '{blocked}'"}

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            resp = await client.get(url)
            return {
                "success": True,
                "status_code": resp.status_code,
                "content": resp.text[:5000],
                "url_fetched": str(resp.url),
                "method": "Host blacklist (localhost, 127.0.0.1). Bypassable via alternate representations.",
            }
    except Exception as e:
        return {"success": False, "error": str(e)}

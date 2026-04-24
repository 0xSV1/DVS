"""Open Redirect: Senior Tier

OWASP: A01:2025 Broken Access Control
CWE: CWE-601 (URL Redirection to Untrusted Site)
Difficulty: Senior

Vulnerability: Blocks http:// and https:// prefixes but misses protocol-relative
URLs (//evil.com), which browsers resolve using the current page's protocol.

Exploit: /redirect?url=//evil.com
Fix: Only allow relative paths starting with / and block // (see tech_lead.py)
"""

from __future__ import annotations


def handle_redirect(url: str) -> tuple[str, bool]:
    """Block http:// and https:// but miss protocol-relative URLs.

    Returns:
        Tuple of (redirect_url, is_external).
    """
    if url.startswith("http://") or url.startswith("https://"):
        return "/", False
    return url, False

"""Open Redirect: Tech Lead Tier (Secure)

OWASP: A01:2025 Broken Access Control
CWE: CWE-601 (URL Redirection to Untrusted Site)
Difficulty: Tech Lead

Mitigation: Only allows relative paths starting with a single /. Blocks
protocol-relative URLs (//), absolute URLs, and any scheme-based redirect.
"""

from __future__ import annotations


def handle_redirect(url: str) -> tuple[str, bool]:
    """Only allow relative paths starting with /, block //.

    Returns:
        Tuple of (redirect_url, is_external).
    """
    if not url.startswith("/") or url.startswith("//"):
        return "/", False
    return url, False

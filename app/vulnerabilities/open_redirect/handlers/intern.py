"""Open Redirect: Intern Tier (Deployed Blindly)

OWASP: A01:2025 Broken Access Control
CWE: CWE-601 (URL Redirection to Untrusted Site)
Difficulty: Intern

Vulnerability: Redirects to any user-supplied URL with zero validation.

Exploit: /redirect?url=https://evil.com
Fix: Only allow relative paths (see tech_lead.py)
"""

from __future__ import annotations


def handle_redirect(url: str) -> tuple[str, bool]:
    """Redirect to any URL without validation.

    Returns:
        Tuple of (redirect_url, is_external).
    """
    is_external = url.startswith("http")
    return url, is_external

"""XSS Reflected: Tech Lead Tier (Actually Secure)

OWASP: A05:2025 Injection
CWE: CWE-79 (Cross-site Scripting)
Difficulty: Tech Lead

Security: Input sanitized via bleach (allowlist-based HTML sanitizer).
Output placed in a safe HTML context with Jinja2 autoescaping enabled.
Content-Security-Policy header set to block inline scripts.
This is the reference implementation.
"""

from __future__ import annotations

import bleach

ALLOWED_TAGS = ["b", "i", "em", "strong", "a", "p", "br"]
ALLOWED_ATTRIBUTES = {"a": ["href", "title"]}


def handle_reflect(user_input: str) -> dict:
    """Reflect user input with proper sanitization.

    Args:
        user_input: User input sanitized via bleach allowlist.

    Returns:
        Dict with sanitized output and metadata.
    """
    sanitized = bleach.clean(
        user_input,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True,
    )

    return {
        "output": sanitized,
        "safe": False,  # Let Jinja2 autoescaping handle it
        "csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
        "method": "Bleach allowlist sanitization + Jinja2 autoescaping + Content-Security-Policy.",
    }


def sanitize_comment(content: str) -> tuple[str, bool]:
    """Sanitize comment content with bleach, stripping all HTML tags.

    Args:
        content: Raw comment HTML.

    Returns:
        Tuple of (sanitized_content, render_raw). render_raw=False means autoescaped.
    """
    return (bleach.clean(content, tags=[], strip=True), False)

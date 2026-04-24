"""XSS Reflected: Intern Tier (Deployed Blindly)

OWASP: A05:2025 Injection
CWE: CWE-79 (Cross-site Scripting)
Difficulty: Intern

Vulnerability: User input reflected directly into HTML without any
encoding or sanitization. The template uses the |safe filter, disabling
Jinja2's autoescaping.

Exploit: <script>alert('XSS')</script>
Fix: Use autoescaping (see tech_lead.py)
"""

from __future__ import annotations


def handle_reflect(user_input: str) -> dict:
    """Reflect user input without any sanitization.

    Args:
        user_input: Raw user input to reflect in the page.

    Returns:
        Dict with the raw (unsafe) output and metadata.
    """
    # ship it
    return {
        "output": user_input,
        "safe": True,  # Tells template to render with |safe (no escaping)
        "method": "No sanitization. Input rendered directly via |safe filter.",
    }


def sanitize_comment(content: str) -> tuple[str, bool]:
    """Return comment content without any sanitization.

    Args:
        content: Raw comment HTML.

    Returns:
        Tuple of (content, render_raw). render_raw=True means use |safe.
    """
    return (content, True)

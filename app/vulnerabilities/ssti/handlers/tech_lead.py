"""SSTI: Tech Lead Tier (Actually Secure)

OWASP: A05:2025 Injection
CWE: CWE-1336 (Server-Side Template Injection)
Difficulty: Tech Lead

Security: User input is NEVER passed to template compilation. Instead,
a fixed template uses variable substitution with autoescaping enabled.
User input only fills pre-defined template variables.
This is the reference implementation.
"""

from __future__ import annotations

import html


def handle_render(user_input: str) -> dict:
    """Render user input via safe string substitution.

    Args:
        user_input: User input HTML-escaped and placed into a fixed string.

    Returns:
        Dict with safely rendered output and metadata.
    """
    # Never compile user input as a template. Use parameterized substitution.
    safe_input = html.escape(user_input, quote=True)
    rendered = f"Hello {safe_input}! Welcome to DeployBro."

    return {
        "output": rendered,
        "method": "Fixed template string with html.escape(). No from_string(), no template compilation.",
    }

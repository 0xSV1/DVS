"""XSS Reflected: Senior Tier (Code Reviewed)

OWASP: A05:2025 Injection
CWE: CWE-79 (Cross-site Scripting)
Difficulty: Senior

Vulnerability: Angle-bracket encoding blocks tag injection (<script>, <img>).
However, output is placed inside a JavaScript string context where quotes
are NOT escaped. An attacker can break out of the JS string with a single
quote and inject arbitrary JavaScript.

Exploit: ';alert('XSS');//
Fix: Use separate data attributes + CSP (see tech_lead.py)
"""

from __future__ import annotations


def handle_reflect(user_input: str) -> dict:
    """Reflect user input with partial HTML encoding in a JS context.

    Escapes angle brackets to prevent tag injection, but does not escape
    quotes, allowing JS string breakout.

    Args:
        user_input: User input with angle brackets escaped only.

    Returns:
        Dict with partially encoded output and metadata.
    """
    # Only escape angle brackets and ampersand; deliberately skip quotes
    encoded = user_input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    return {
        "output": encoded,
        "safe": False,  # Autoescaped in HTML context
        "js_context": True,  # Template places this in a <script> block
        "method": "Partial HTML encoding (angle brackets only). Output embedded in a JavaScript string context.",
    }


def sanitize_comment(content: str) -> tuple[str, bool]:
    """Strip script tags from comment content.

    Removes <script> blocks but misses event handlers like onerror, onload.

    Args:
        content: Raw comment HTML.

    Returns:
        Tuple of (sanitized_content, render_raw). render_raw=False means autoescaped.
    """
    import re

    sanitized = re.sub(
        r"<script[^>]*>.*?</script>",
        "",
        content,
        flags=re.DOTALL | re.IGNORECASE,
    )
    return (sanitized, False)

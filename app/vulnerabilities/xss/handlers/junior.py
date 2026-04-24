"""XSS Reflected: Junior Tier (Copilot Assisted)

OWASP: A05:2025 Injection
CWE: CWE-79 (Cross-site Scripting)
Difficulty: Junior

Vulnerability: Blacklist strips <script>, <iframe>, <object>, <embed> tags
(case-insensitive) and common event handlers (onerror, onload, onclick,
onmouseover, onfocus). Misses less common tags (<svg>, <details>, <math>,
<video>, <audio>, <marquee>, <body>, <input>) and less common event
handlers (ontoggle, onanimationend, onpointerover, oncontextmenu, etc.).

Exploit: <svg onload="alert('XSS')">
Exploit: <details open ontoggle="alert('XSS')">
Exploit: <img src=x oNerRor="alert('XSS')"> (mixed case event handler)
Fix: Use autoescaping or bleach allowlist (see tech_lead.py)
"""

from __future__ import annotations

import re

# Tags that get stripped (case-insensitive)
_BLOCKED_TAGS = re.compile(
    r"<\s*/?\s*(?:script|iframe|object|embed)\b[^>]*>",
    re.IGNORECASE | re.DOTALL,
)

# Common event handlers that get stripped (case-insensitive)
_BLOCKED_EVENTS = re.compile(
    r"\b(?:onerror|onload|onclick|onmouseover|onfocus|onblur|onchange)\s*=",
    re.IGNORECASE,
)


def handle_reflect(user_input: str) -> dict:
    """Reflect user input with a blacklist filter.

    Strips known dangerous tags and common event handlers, but misses
    less common tags (svg, details, math, video, audio, marquee, body,
    input) and less common event handlers (ontoggle, onanimationend,
    onpointerover, oncontextmenu, etc.).

    Args:
        user_input: User input filtered through an incomplete blacklist.

    Returns:
        Dict with the filtered (still unsafe) output and metadata.
    """
    filtered = _BLOCKED_TAGS.sub("", user_input)
    filtered = _BLOCKED_EVENTS.sub("blocked=", filtered)

    return {
        "output": filtered,
        "safe": True,  # Still rendered as raw HTML
        "method": (
            "Blacklist: strips <script>, <iframe>, <object>, <embed> tags "
            "and onerror/onload/onclick/onmouseover/onfocus/onblur/onchange handlers. "
            "Misses alternate tags and uncommon event handlers."
        ),
    }


def sanitize_comment(content: str) -> tuple[str, bool]:
    """Filter comment content with the same blacklist.

    Args:
        content: Raw comment HTML.

    Returns:
        Tuple of (filtered_content, render_raw). render_raw=True means use |safe.
    """
    filtered = _BLOCKED_TAGS.sub("", content)
    filtered = _BLOCKED_EVENTS.sub("blocked=", filtered)
    return (filtered, True)

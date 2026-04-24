"""SSTI: Junior Tier (Copilot Assisted)

OWASP: A05:2025 Injection
CWE: CWE-1336 (Server-Side Template Injection)
Difficulty: Junior

Vulnerability: Blacklist blocks direct access to config and OS modules
but fails to block Python's object model traversal via __class__,
__mro__, __subclasses__, and the |attr() filter.

Exploit: {{''.__class__.__mro__[1].__subclasses__()}}
Exploit: {{request.application.__globals__}}
Fix: Never use from_string() with user input (see tech_lead.py)
"""

from __future__ import annotations

from jinja2 import Template

BLACKLIST = [
    "config",
    "import",
    "os.",
    "subprocess",
    "popen",
    "eval",
    "exec",
]


def handle_render(user_input: str) -> dict:
    """Render user input with blacklist-based filtering.

    Args:
        user_input: User input filtered through an incomplete blacklist.

    Returns:
        Dict with rendered output and metadata.
    """
    # Check blacklist
    for pattern in BLACKLIST:
        if pattern.lower() in user_input.lower():
            return {
                "output": f"Blocked: input contains forbidden pattern '{pattern}'",
                "method": "Blacklist filter + Jinja2 from_string(). Blocks common patterns.",
            }

    try:
        template = Template("Hello " + user_input + "! Welcome to DeployBro.")
        rendered = template.render()
    except Exception as e:
        rendered = f"Template Error: {e}"

    return {
        "output": rendered,
        "method": "Blacklist filter + Jinja2 from_string(). Bypassable via attr() filter and {% tags.",
    }

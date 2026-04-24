"""SSTI: Intern Tier (Deployed Blindly)

OWASP: A05:2025 Injection
CWE: CWE-1336 (Server-Side Template Injection)
Difficulty: Intern

Vulnerability: User input passed directly to Jinja2's from_string(),
allowing arbitrary template expression evaluation. No sandbox, no
filtering, no restrictions.

Exploit: {{7*7}} -> 49, {{config}}, {{''.__class__.__mro__[1].__subclasses__()}}
Fix: Never use from_string() with user input (see tech_lead.py)
"""

from __future__ import annotations

from jinja2 import Template


def handle_render(user_input: str) -> dict:
    """Render user input as a Jinja2 template.

    Args:
        user_input: Raw user input passed directly to Template().

    Returns:
        Dict with rendered output and metadata.
    """
    try:
        # AI said this is how you do personalized emails
        template = Template("Hello " + user_input + "! Welcome to DeployBro.")
        rendered = template.render()
    except Exception as e:
        rendered = f"Template Error: {e}"

    return {
        "output": rendered,
        "method": "Jinja2 from_string() with raw user input. No sandbox.",
    }

"""SSTI: Senior Tier (Code Reviewed)

OWASP: A05:2025 Injection
CWE: CWE-1336 (Server-Side Template Injection)
Difficulty: Senior

Vulnerability: Uses Jinja2 SandboxedEnvironment, which blocks most
dangerous operations. However, the template still uses from_string()
and certain information disclosure is possible through sandbox-allowed
methods. The sandbox prevents RCE but not information leaks.

Exploit: {{self._TemplateReference__context}} may leak context variables
Fix: Use fixed templates with variable substitution (see tech_lead.py)
"""

from __future__ import annotations

from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()


def handle_render(user_input: str) -> dict:
    """Render user input in a sandboxed Jinja2 environment.

    Args:
        user_input: User input rendered in a sandbox (blocks RCE, not info leak).

    Returns:
        Dict with rendered output and metadata.
    """
    try:
        template = env.from_string("Hello " + user_input + "! Welcome to DeployBro.")
        rendered = template.render()
    except Exception as e:
        rendered = f"Sandbox blocked this operation: {e}"

    return {
        "output": rendered,
        "method": "Jinja2 SandboxedEnvironment. Blocks RCE but still uses from_string().",
    }

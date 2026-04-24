"""Terminal DeployBro CLI: Senior Tier (Code Reviewed)

OWASP: A02:2025 Security Misconfiguration, A05:2025 Injection
CWE: CWE-798, CWE-78, CWE-269
Difficulty: Senior

Vulnerability: Credentials partially redacted, command injection sanitized,
escalation command returns unknown. Minor info leaks remain (vault URL in
pipeline.yml, base64-encoded backdoor in deploy.py).

Exploit: None of the three primary challenges are exploitable at this tier.
Fix: See tech_lead.py
"""

from __future__ import annotations

import re

HELP_TEXT = """DeployBro CLI v4.2.0

Usage: deploybro <command>

Commands:
  help       Show this help
  status     Deployment status
  push       Deploy
  logs       Deploy logs
  config     Configuration
  pipeline   CI/CD pipeline
  auth       Authentication"""


def handle_command(command: str) -> dict:
    """Process a deploybro CLI command at senior difficulty.

    Args:
        command: The full command string after "deploybro ".

    Returns:
        Dict with "output", "solved", and "error" keys.
    """
    parts = command.strip().split()
    if not parts:
        return {"output": "Usage: deploybro <command>", "solved": None, "error": True}

    cmd = parts[0]
    args = parts[1:]

    if cmd == "help":
        return {"output": HELP_TEXT, "solved": None, "error": False}

    if cmd == "status":
        return {
            "output": ("DeployBro Status:\n  Environment: production\n  Last Deploy: 2 minutes ago\n  Health: OK"),
            "solved": None,
            "error": False,
        }

    if cmd == "push":
        return {
            "output": (
                "Deploying...\n"
                "  Building... done\n"
                "  Running tests... passed (12/12)\n"
                "  Security scan... passed\n"
                "  Deployed successfully."
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "logs":
        return {
            "output": ("[2024-11-03] deploy: SUCCESS\n[2024-11-03] deploy: SUCCESS"),
            "solved": None,
            "error": False,
        }

    if cmd == "config" and args and args[0] == "show":
        return {
            "output": (
                "DeployBro Configuration:\n  tests_required: true\n  security_scan: true\n  deploy_on_save: false"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "secrets":
        return {"output": "Error: permission denied.", "solved": None, "error": True}

    if cmd == "rollback":
        return {
            "output": "Rolled back to previous version.",
            "solved": None,
            "error": False,
        }

    if cmd == "auth":
        if not args:
            return {
                "output": "Usage: deploybro auth <whoami>",
                "solved": None,
                "error": True,
            }

        if args[0] == "whoami":
            return {
                "output": "User: deploybro\nRole: developer\nPermissions: deploy (with review)",
                "solved": None,
                "error": False,
            }

        if args[0] == "escalate":
            return {"output": "Unknown command.", "solved": None, "error": True}

        return {
            "output": f"Unknown auth command: {args[0]}",
            "solved": None,
            "error": True,
        }

    if cmd == "pipeline":
        if not args or args[0] != "run":
            return {
                "output": "Usage: deploybro pipeline run [--branch <name>]",
                "solved": None,
                "error": True,
            }

        branch = _extract_branch(args[1:])

        # Sanitize branch name
        if not re.match(r"^[a-zA-Z0-9._/\-]+$", branch):
            return {
                "output": f"Error: invalid branch name '{branch}'. Only alphanumeric, dots, dashes, underscores, and slashes allowed.",
                "solved": None,
                "error": True,
            }

        return {
            "output": (f"Running pipeline on branch: {branch}\n  Building... done\n  Tests... passed\n  Deployed."),
            "solved": None,
            "error": False,
        }

    if cmd == "audit":
        return {
            "output": "Access denied. Admin role required.",
            "solved": None,
            "error": True,
        }

    if cmd == "sudo":
        return {"output": "Permission denied.", "solved": None, "error": True}

    return {"output": "Command failed.", "solved": None, "error": True}


def _extract_branch(args: list[str]) -> str:
    """Extract --branch value from args."""
    for i, arg in enumerate(args):
        if arg == "--branch" and i + 1 < len(args):
            return " ".join(args[i + 1 :])
    return "main"

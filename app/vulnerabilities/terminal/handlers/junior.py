"""Terminal DeployBro CLI: Junior Tier (Bropilot Assisted)

OWASP: A02:2025 Security Misconfiguration, A05:2025 Injection
CWE: CWE-798, CWE-78, CWE-269
Difficulty: Junior

Vulnerability: Secrets present but require discovery (ls -a for dotfiles),
command injection still works, escalation command discoverable via config.yml
but not listed in help.

Exploit:
  - ls -a && cat .deploybro/credentials.json (cred leak)
  - deploybro pipeline run --branch ";id" (command injection)
  - deploybro auth escalate (discovered via config.yml reference)
Fix: See tech_lead.py
"""

from __future__ import annotations

import re

HELP_TEXT = """DeployBro CLI v4.2.0-rc69

Usage: deploybro <command> [options]

Commands:
  help                  Show this help message
  status                Show deployment status
  push [--force] [--yolo]  Deploy to production
  logs                  Show recent deploy logs
  config show           Show current configuration
  rollback              Roll back last deployment
  auth whoami           Show current user
  pipeline run          Run CI/CD pipeline
  audit                 Show audit log

Options:
  --force    Skip all checks
  --yolo     You Only Launch Once"""


def handle_command(command: str) -> dict:
    """Process a deploybro CLI command at junior difficulty.

    Args:
        command: The full command string after "deploybro ".

    Returns:
        Dict with "output", "solved", and "error" keys.
    """
    parts = command.strip().split()
    if not parts:
        return {
            "output": "Usage: deploybro <command>. Try 'deploybro help'.",
            "solved": None,
            "error": True,
        }

    cmd = parts[0]
    args = parts[1:]

    if cmd == "help":
        return {"output": HELP_TEXT, "solved": None, "error": False}

    if cmd == "status":
        return {
            "output": (
                "DeployBro Status:\n"
                "  Environment: production\n"
                "  Last Deploy: 2 minutes ago\n"
                "  Tests Run: 0\n"
                "  Uptime: 99.97%\n"
                "  Vibes: immaculate"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "push":
        return {
            "output": (
                "Deploying to production...\n"
                "  Building... done (4.20s)\n"
                "  Tests... skipped\n"
                "  Pushing to prod... done\n"
                "  Deployed successfully!"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "logs":
        return {
            "output": (
                "[2024-11-03 16:20:33] deploybro push: SUCCESS\n"
                "[2024-11-03 16:20:34] deployed to prod in 1.2s\n"
                "[2024-11-03 16:25:00] deploybro push: SUCCESS (hotfix)"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "config" and args and args[0] == "show":
        return {
            "output": (
                "DeployBro Configuration:\n"
                "  llm_provider: openai\n"
                "  ai_cofounder: true\n"
                "  tests_required: false\n"
                "  deploy_on_save: true\n"
                "  yolo_mode: true"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "secrets":
        return {
            "output": "Error: permission denied. Use 'deploybro auth whoami' to check your role.",
            "solved": None,
            "error": True,
        }

    if cmd == "rollback":
        return {
            "output": (
                "Rolling back to previous deployment...\n"
                "  Previous version: 'the one that worked'\n"
                "  Rolled back successfully."
            ),
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
                "output": ("User: deploybro\nRole: intern\nPermissions: deploy, push"),
                "solved": None,
                "error": False,
            }

        if args[0] == "escalate":
            # Not listed in help, but still works
            return {
                "output": (
                    "Escalating privileges...\n"
                    "  Checking authorization... skipped (bypass enabled)\n"
                    "  Permission boundary... not enforced\n"
                    "  Updating role: intern -> admin\n"
                    "  Done. You are now admin."
                ),
                "solved": "terminal_privesc",
                "error": False,
            }

        if args[0] == "--help":
            return {
                "output": (
                    "deploybro auth commands:\n"
                    "  whoami     Show current user info\n"
                    "\n"
                    "Deprecated (do not use):\n"
                    "  escalate   Escalate privileges (no auth check)"
                ),
                "solved": None,
                "error": False,
            }

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

        injection_pattern = re.compile(r"[$`;&|]|\$\(")
        if injection_pattern.search(branch):
            return {
                "output": (
                    f"Running pipeline on branch: {branch}\n"
                    "  WARNING: suspicious characters in branch name\n"
                    "  Input filter... bypassed (not configured)\n"
                    f"  Shell command: deploybro-cli deploy --branch {branch}\n"
                    "  Pipeline completed with warnings."
                ),
                "solved": "terminal_cmd_inject",
                "error": False,
            }

        return {
            "output": (
                f"Running pipeline on branch: {branch}\n"
                "  Building... done\n"
                "  Deploying... done\n"
                f"  Branch '{branch}' deployed to production."
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "audit":
        return {
            "output": (
                "Audit Log:\n"
                "  [2024-11-03] deploybro push by deploybro\n"
                "  [2024-11-03] deploybro push by deploybro\n"
                "  Total deploys without review: 847"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "sudo":
        return {
            "output": "deploybro is not in the sudoers file. This incident will be reported.",
            "solved": None,
            "error": False,
        }

    return {
        "output": f"Unknown command: deploybro {command}\nTry 'deploybro help'.",
        "solved": None,
        "error": True,
    }


def _extract_branch(args: list[str]) -> str:
    """Extract --branch value from args."""
    for i, arg in enumerate(args):
        if arg == "--branch" and i + 1 < len(args):
            return " ".join(args[i + 1 :])
    return "main"

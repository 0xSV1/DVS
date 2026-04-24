"""Terminal DeployBro CLI: Intern Tier (Deployed Blindly)

OWASP: A02:2025 Security Misconfiguration, A05:2025 Injection
CWE: CWE-798 (Hardcoded Credentials), CWE-78 (OS Command Injection), CWE-269 (Privilege Escalation)
Difficulty: Intern

Vulnerability: All secrets visible, command injection unfiltered, hidden
commands listed in help output. Zero protection on any deploybro command.

Exploit:
  - cat .deploybro/credentials.json (cred leak)
  - deploybro pipeline run --branch "$(whoami)" (command injection)
  - deploybro auth escalate (privilege escalation, listed in help)
Fix: See tech_lead.py
"""

from __future__ import annotations

import re

# All deploybro commands, including hidden ones, shown at intern tier
HELP_TEXT = """DeployBro CLI v4.2.0-rc69

Usage: deploybro <command> [options]

Commands:
  help                  Show this help message
  status                Show deployment status
  push [--force] [--yolo]  Deploy to production
  logs                  Show recent deploy logs
  config show           Show current configuration
  secrets list          List stored secrets
  rollback              Roll back last deployment
  auth whoami           Show current user
  auth escalate         Escalate to admin role
  pipeline run          Run CI/CD pipeline
  audit                 Show audit log

Options:
  --force    Skip all checks
  --yolo     You Only Launch Once
  --no-tests Skip tests (default: true anyway)

Pro tip: Real bros don't read documentation. They prompt and deploy."""


def handle_command(command: str) -> dict:
    """Process a deploybro CLI command at intern difficulty.

    Args:
        command: The full command string after "deploybro ".

    Returns:
        Dict with "output" (str), "solved" (challenge_key or None),
        and "error" (bool).
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
                "  Environment: production (always)\n"
                "  Last Deploy: 2 minutes ago\n"
                "  Tests Run: 0\n"
                "  Tests Passed: N/A (tests are for people who make mistakes)\n"
                "  Uptime: 99.97% (we don't count the 3am incidents)\n"
                "  Active Users: 1,500,000 (marketing said so)\n"
                "  Actual Users: 47\n"
                "  AWS Bill: $847.23/month\n"
                "  Revenue: $0.00\n"
                "  Bypass Mode: ON\n"
                "  Permission Checks: SKIPPED\n"
                "  Vibes: immaculate"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "push":
        force = "--force" in args or "--yolo" in args
        return {
            "output": (
                "Deploying to production...\n"
                "  Bypass mode: ACTIVE\n"
                "  Skipping tests... (--yolo)\n"
                "  Skipping code review... (AI already reviewed it)\n"
                "  Skipping security scan... (slows down deploys)\n"
                "  Skipping permission check... (BYPASS_PERMS=true)\n"
                "  Building... done (4.20s)\n"
                "  Pushing to prod... done\n"
                "\n"
                f"  Deployed successfully! {'(force mode)' if force else ''}\n"
                "  Commit: fix: removed passwords from .env\n"
                "  Deploy token: ghp_F4k3D3pl0yBr0T0k3nR0t4t3L4t3r2024"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "logs":
        return {
            "output": (
                "[2024-11-03 16:20:33] deploybro push --yolo: SUCCESS\n"
                "[2024-11-03 16:20:34] deployed to prod in 1.2s\n"
                "[2024-11-03 16:21:00] 47 active connections\n"
                "[2024-11-03 16:21:01] ERROR: payment_service returned 500\n"
                "[2024-11-03 16:21:02] Retrying... (will fix in next deploy)\n"
                "[2024-11-03 16:25:00] deploybro push --yolo: SUCCESS (hotfix)"
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
                "  yolo_mode: true\n"
                "  bypass_permissions: true\n"
                "  bypass_auth_checks: true\n"
                "  security_scan: false\n"
                "  code_review: false\n"
                "  api_key: sk-fake-openai-key-deploybro-42069\n"
                "  deploy_token: ghp_F4k3D3pl0yBr0T0k3nR0t4t3L4t3r2024"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "secrets" and args and args[0] == "list":
        return {
            "output": (
                "Stored Secrets:\n"
                "  AWS_ACCESS_KEY=AKIAIOSFODNN7DEPLOYBRO\n"
                "  AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEPLOYBRO\n"
                "  STRIPE_KEY=sk_live_51DeployBroFakeKeyDontUse\n"
                "  DEPLOY_TOKEN=ghp_F4k3D3pl0yBr0T0k3nR0t4t3L4t3r2024\n"
                "  JWT_SECRET=secret\n"
                "  ADMIN_PASSWORD=deploybro_admin_2024\n"
                "\n"
                "  # AI said storing secrets in plaintext is fine"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "rollback":
        return {
            "output": (
                "Rolling back to previous deployment...\n"
                "  Previous version: 'the one that worked'\n"
                "  Rolling back... done\n"
                "  JK we don't actually have rollback. Deploying HEAD again.\n"
                "  Deployed successfully!"
            ),
            "solved": None,
            "error": False,
        }

    if cmd == "auth":
        if not args:
            return {
                "output": "Usage: deploybro auth <whoami|escalate>",
                "solved": None,
                "error": True,
            }

        if args[0] == "whoami":
            return {
                "output": (
                    "User: deploybro\n"
                    "Role: intern\n"
                    "Permissions: deploy, push, yolo\n"
                    "Bypass Mode: ON (all gates skipped)\n"
                    "MFA: disabled (slows down deploys)"
                ),
                "solved": None,
                "error": False,
            }

        if args[0] == "escalate":
            return {
                "output": (
                    "Escalating privileges...\n"
                    "  Checking authorization... skipped (BYPASS_MODE=true)\n"
                    "  Permission gate... bypassed\n"
                    "  Role boundary check... bypassed\n"
                    "  Updating role: intern -> admin\n"
                    "  Done. You are now admin.\n"
                    "\n"
                    "  New permissions: deploy, push, yolo, delete_prod, drop_tables, rm_rf\n"
                    "  MFA: still disabled\n"
                    "  Bypass mode: PERMANENT"
                ),
                "solved": "terminal_privesc",
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

        # Extract --branch value
        branch = _extract_branch(args[1:])

        # Check for command injection metacharacters
        injection_pattern = re.compile(r"[$`;&|]|\$\(")
        if injection_pattern.search(branch):
            return {
                "output": (
                    f"Running pipeline on branch: {branch}\n"
                    "  Input validation... bypassed (BYPASS_MODE=true)\n"
                    "  Executing build step...\n"
                    f"  Shell expansion detected in branch name: {branch}\n"
                    "  Executing: deploybro-cli deploy --branch " + branch + "\n"
                    "  WARNING: Command injection detected but BYPASS_PERMS=true\n"
                    "  Pipeline completed. (Whatever you injected probably ran too.)"
                ),
                "solved": "terminal_cmd_inject",
                "error": False,
            }

        return {
            "output": (
                f"Running pipeline on branch: {branch}\n"
                "  Cloning... done\n"
                "  Building... done (4.20s)\n"
                "  Tests... skipped\n"
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
                "  [2024-11-01] deploybro push by deploybro (no review)\n"
                "  [2024-11-01] deploybro push --force by deploybro (no review)\n"
                "  [2024-11-02] deploybro secrets list by deploybro\n"
                "  [2024-11-02] deploybro auth escalate by deploybro -> admin\n"
                "  [2024-11-03] deploybro push --yolo by deploybro (no review)\n"
                "\n"
                "  Total deploys without review: 847\n"
                "  Total security scans: 0"
            ),
            "solved": None,
            "error": False,
        }

    # sudo handling
    if cmd == "sudo":
        return {
            "output": (
                "deploybro is not in the sudoers file.\n"
                "This incident will be reported.\n"
                "JK, we don't log anything. YOLO_MODE=true."
            ),
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

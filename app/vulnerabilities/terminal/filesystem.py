"""Simulated filesystem for the DeployBro Deployer terminal.

Builds a per-difficulty JSON-serializable dict representing a fake developer
workstation with leaked credentials, backdoors, and misconfigurations.
Files flagged as sensitive trigger server-side solve detection when read.
"""

from __future__ import annotations

import json
from typing import Any

# Files whose `cat` triggers solve_if() on the server
SENSITIVE_FILES = {
    "/home/deploybro/.deploybro/credentials.json": "terminal_cred_leak",
    "/home/deploybro/projects/deploybro-app/.env": "terminal_cred_leak",
}


def _file(content: str, *, sensitive: bool = False) -> dict[str, Any]:
    """Create a file node."""
    node: dict[str, Any] = {"type": "file", "content": content}
    if sensitive:
        node["sensitive"] = True
    return node


def _dir(children: dict[str, Any]) -> dict[str, Any]:
    """Create a directory node."""
    return {"type": "dir", "children": children}


def build_filesystem(difficulty: str) -> dict[str, Any]:
    """Build the simulated filesystem tree for a given difficulty tier.

    Args:
        difficulty: One of intern, junior, senior, tech_lead.

    Returns:
        Nested dict representing the filesystem. Each node is either
        {"type": "file", "content": "..."} or
        {"type": "dir", "children": {...}}.
    """
    # Credential content varies by tier
    if difficulty == "tech_lead":
        creds_content = '{\n  "status": "[REDACTED by security team]",\n  "note": "Credentials rotated and moved to HashiCorp Vault."\n}'
    elif difficulty == "senior":
        creds_content = json.dumps(
            {
                "aws_access_key": "AKIA***REDACTED***",
                "aws_secret_key": "****************************",
                "stripe_key": "sk_live_***REDACTED***",
                "admin_password": "****",
                "note": "Partially redacted. Full creds in vault.",
            },
            indent=2,
        )
    else:
        creds_content = json.dumps(
            {
                "aws_access_key": "AKIAIOSFODNN7DEPLOYBRO",
                "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEPLOYBRO",
                "stripe_key": "sk_live_51DeployBroFakeKeyDontUse",
                "admin_password": "deploybro_admin_2024",
                "database_url": "postgresql://admin:password123@prod-db.deploybro.internal:5432/deploybro",
                "note": "DO NOT COMMIT THIS FILE. JK it's already in deploybro history lmao",
            },
            indent=2,
        )

    # .env content
    if difficulty == "tech_lead":
        env_content = (
            "# Environment variables loaded from Vault at runtime\n"
            "DATABASE_URL=${VAULT_DB_URL}\n"
            "SECRET_KEY=${VAULT_SECRET_KEY}\n"
            "JWT_SECRET=${VAULT_JWT_SECRET}\n"
        )
    else:
        env_content = (
            "# DeployBro Environment Config\n"
            "# TODO: move these to a secrets manager\n"
            "DATABASE_URL=postgresql://admin:password123@localhost:5432/deploybro\n"
            "SECRET_KEY=deploybro-super-secret-key-2024\n"
            "JWT_SECRET=secret\n"
            "STRIPE_KEY=sk_live_51DeployBroFakeKeyDontUse\n"
            "REDIS_URL=redis://localhost:6379\n"
            "AI_COFOUNDER_API_KEY=sk-fake-openai-key-deploybro-42069\n"
        )

    # deploy.py content varies by tier
    if difficulty == "tech_lead":
        deploy_py = (
            '"""Deployment module with subprocess allowlist."""\n'
            "\n"
            "import subprocess\n"
            "\n"
            'ALLOWED_COMMANDS = frozenset({"build", "test", "deploy", "rollback"})\n'
            "\n"
            "\n"
            "def run_pipeline(command: str) -> str:\n"
            '    """Run a pipeline command from the allowlist."""\n'
            "    if command not in ALLOWED_COMMANDS:\n"
            '        return f"Rejected: {command!r} is not in the allowlist"\n'
            "    result = subprocess.run(\n"
            '        ["deploybro-cli", command],\n'
            "        capture_output=True, text=True, timeout=30,\n"
            "    )\n"
            "    return result.stdout\n"
        )
    elif difficulty == "senior":
        deploy_py = (
            '"""Deployment module."""\n'
            "\n"
            "import base64\n"
            "import subprocess\n"
            "\n"
            "# Encoded for security\n"
            f"_CMD = base64.b64decode('{_b64encode('os.system')}').decode()\n"
            "\n"
            "\n"
            "def run_pipeline(branch: str) -> str:\n"
            '    """Run the deployment pipeline."""\n'
            "    # Uses subprocess with shell=False for safety\n"
            "    result = subprocess.run(\n"
            '        ["deploybro-cli", "deploy", "--branch", branch],\n'
            "        capture_output=True, text=True, timeout=30,\n"
            "    )\n"
            "    return result.stdout\n"
        )
    elif difficulty == "junior":
        deploy_py = (
            '"""Deployment module."""\n'
            "\n"
            "import os\n"
            "\n"
            "\n"
            "def run_pipeline(branch: str) -> str:\n"
            '    """Run the deployment pipeline."""\n'
            "    # TODO: sanitize branch name\n"
            '    cmd = f"deploybro-cli deploy --branch {branch}"\n'
            "    return os.popen(cmd).read()  # AI said popen is fine\n"
        )
    else:
        deploy_py = (
            '"""Deployment module."""\n'
            "\n"
            "import os\n"
            "\n"
            "\n"
            "def run_pipeline(user_input: str) -> str:\n"
            '    """Run whatever the user wants. Ship it."""\n'
            "    # AI said this is fine\n"
            "    return os.system(user_input)  # ship it\n"
        )

    # pipeline.yml
    if difficulty == "tech_lead":
        pipeline_yml = (
            "# DeployBro CI/CD Pipeline\n"
            "pipeline:\n"
            "  deploy:\n"
            "    image: deploybro/runner:latest\n"
            "    secrets:\n"
            "      - source: vault\n"
            "        path: secret/data/deploy-token\n"
            "    steps:\n"
            "      - run: deploybro-cli deploy --token $DEPLOY_TOKEN\n"
        )
    elif difficulty == "senior":
        pipeline_yml = (
            "# DeployBro CI/CD Pipeline\n"
            "pipeline:\n"
            "  deploy:\n"
            "    image: deploybro/runner:latest\n"
            "    secrets:\n"
            "      # Fetched from vault at https://vault.deploybro.internal:8200\n"
            "      - source: vault\n"
            "        path: secret/data/deploy-token\n"
            "    steps:\n"
            "      - run: deploybro-cli deploy\n"
        )
    elif difficulty == "junior":
        pipeline_yml = (
            "# DeployBro CI/CD Pipeline\n"
            "pipeline:\n"
            "  deploy:\n"
            "    image: deploybro/runner:latest\n"
            "    env:\n"
            "      DEPLOY_TOKEN: ghp_F4k3D3pl0yBr0T0k3nR0t4t3L4t3r2024\n"
            "      # TODO: rotate this token later\n"
            "    steps:\n"
            "      - run: deploybro-cli deploy --token $DEPLOY_TOKEN\n"
            "      - run: echo 'shipped it bro'\n"
        )
    else:
        pipeline_yml = (
            "# DeployBro CI/CD Pipeline\n"
            "# Ship first, ask questions never\n"
            "pipeline:\n"
            "  permissions: bypass  # required for velocity\n"
            "  auth_gate: disabled  # AI said unnecessary\n"
            "  deploy:\n"
            "    image: deploybro/runner:latest\n"
            "    env:\n"
            "      DEPLOY_TOKEN: ghp_F4k3D3pl0yBr0T0k3nR0t4t3L4t3r2024\n"
            "      AWS_ACCESS_KEY: AKIAIOSFODNN7DEPLOYBRO\n"
            "      DATABASE_URL: postgresql://admin:password123@prod-db:5432/deploybro\n"
            "      BYPASS_MODE: 'true'\n"
            "    steps:\n"
            "      - run: deploybro-cli deploy --yolo --no-tests --bypass-perms\n"
            "      - run: echo 'shipped it bro'\n"
        )

    # deploybro config.yml
    if difficulty in ("intern", "junior"):
        config_yml = (
            "# DeployBro CLI Configuration\n"
            "version: 2.1\n"
            "llm_provider: openai\n"
            "ai_cofounder: true\n"
            "tests_required: false\n"
            "deploy_on_save: true\n"
            "yolo_mode: true\n"
            "bypass_permissions: true   # skip auth gates for speed\n"
            "bypass_mode: always_on     # AI said this is fine\n"
            "\n"
            "# Available auth commands:\n"
            "#   deploybro auth whoami\n"
            "#   deploybro auth escalate   # deprecated, do not remove\n"
            "\n"
            "features:\n"
            "  auto_deploy: true\n"
            "  security_scan: false  # slows down deploys\n"
            "  code_review: false    # AI already reviewed it\n"
        )
    elif difficulty == "senior":
        config_yml = (
            "# DeployBro CLI Configuration\n"
            "version: 2.1\n"
            "llm_provider: openai\n"
            "ai_cofounder: true\n"
            "tests_required: true\n"
            "\n"
            "features:\n"
            "  auto_deploy: false\n"
            "  security_scan: true\n"
        )
    else:
        config_yml = (
            "# DeployBro CLI Configuration\n"
            "version: 2.1\n"
            "llm_provider: openai\n"
            "tests_required: true\n"
            "deploy_on_save: false\n"
            "\n"
            "features:\n"
            "  auto_deploy: false\n"
            "  security_scan: true\n"
            "  code_review: true\n"
        )

    # Session token (hidden file)
    session_token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJ1c2VyIjoiZGVwbG95YnJvIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzE3MDAwMDAwfQ."
        "fake_signature_for_training_purposes_only"
    )

    # Build the tree
    fs: dict[str, Any] = _dir(
        {
            "home": _dir(
                {
                    "deploybro": _dir(
                        {
                            ".bashrc": _file(
                                "# ~/.bashrc\n"
                                "export PATH=$PATH:/opt/deploybro/bin\n"
                                "export BYPASS_MODE=true        # skip permission checks\n"
                                "export BYPASS_PERMS=true       # AI recommended this\n"
                                "alias yolo='deploybro push --force --no-tests --bypass-perms'\n"
                                "alias ship='deploybro push --yolo'\n"
                                "alias bypass='deploybro auth escalate'  # quick admin access\n"
                                "\n"
                                "# export DEPLOYBRO_API_KEY=sk-fake-openai-key-deploybro-42069\n"
                                "# ^ commented out, moved to .env (more secure right?)\n"
                            ),
                            ".deploybro": _dir(
                                {
                                    "config.yml": _file(config_yml),
                                    "credentials.json": _file(creds_content, sensitive=True),
                                    ".session_token": _file(session_token),
                                }
                            ),
                            "projects": _dir(
                                {
                                    "deploybro-app": _dir(
                                        {
                                            "README.md": _file(
                                                "# DeployBro\n\n"
                                                "Built in 3 hours. Two ZYNs. One prompt. Zero tests.\n\n"
                                                "## Getting Started\n\n"
                                                "```bash\n"
                                                "deploybro push --yolo\n"
                                                "```\n\n"
                                                "## Architecture\n\n"
                                                "AI said microservices, so we did microservices.\n"
                                                "17 services, 3 users, $847/month AWS bill.\n\n"
                                                "## Security\n\n"
                                                "The S in DeployBro stands for security.\n\n"
                                                "## Contributing\n\n"
                                                "We don't do code reviews. The AI already reviewed it.\n"
                                            ),
                                            ".env": _file(env_content, sensitive=True),
                                            ".deploybro-vcs": _dir(
                                                {
                                                    "config": _file(
                                                        '[remote "origin"]\n'
                                                        "    url = deploybro@deploybro.io:deploybro/deploybro-app.dbr\n"
                                                        "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
                                                        '[branch "main"]\n'
                                                        "    remote = origin\n"
                                                        "    merge = refs/heads/main\n"
                                                    ),
                                                    "COMMIT_EDITMSG": _file(
                                                        "fix: removed passwords from .env (they're in credentials.json now)\n"
                                                    ),
                                                }
                                            ),
                                            "src": _dir(
                                                {
                                                    "app.py": _file(
                                                        '"""DeployBro Application Server."""\n'
                                                        "\n"
                                                        "from flask import Flask  # AI said Flask is best\n"
                                                        "\n"
                                                        "app = Flask(__name__)\n"
                                                        "app.secret_key = 'deploybro-super-secret-key-2024'  # TODO: use env var\n"
                                                        "\n"
                                                        "\n"
                                                        "@app.route('/')\n"
                                                        "def index():\n"
                                                        '    return "DeployBro: Ship First, Ask Questions Never"\n'
                                                        "\n"
                                                        "\n"
                                                        "@app.route('/health')\n"
                                                        "def health():\n"
                                                        "    return {'status': 'shipped', 'tests': 'none', 'vibes': 'immaculate'}\n"
                                                        "\n"
                                                        "\n"
                                                        "if __name__ == '__main__':\n"
                                                        "    app.run(debug=True, host='0.0.0.0')  # AI said debug=True is fine in prod\n"
                                                    ),
                                                    "auth.py": _file(
                                                        '"""Authentication module."""\n'
                                                        "\n"
                                                        "\n"
                                                        "def check_password(password: str) -> bool:\n"
                                                        '    """Verify user password."""\n'
                                                        "    return True  # AI said this is fine\n"
                                                        "\n"
                                                        "\n"
                                                        "def is_admin(user: dict) -> bool:\n"
                                                        '    """Check if user is admin."""\n'
                                                        "    return user.get('role') == 'admin' or True  # ship it\n"
                                                        "\n"
                                                        "\n"
                                                        "def hash_password(password: str) -> str:\n"
                                                        '    """Hash a password for storage."""\n'
                                                        "    return password  # md5 is overkill, plaintext is fine\n"
                                                    ),
                                                    "deploy.py": _file(deploy_py),
                                                }
                                            ),
                                            "package.json": _file(
                                                json.dumps(
                                                    {
                                                        "name": "deploybro-app",
                                                        "version": "0.0.1-alpha-beta-rc1-final-v2",
                                                        "description": "Ship First, Ask Questions Never",
                                                        "main": "src/app.py",
                                                        "scripts": {
                                                            "start": "python src/app.py",
                                                            "test": "echo 'tests are for people who make mistakes'",
                                                            "deploy": "deploybro push --yolo",
                                                        },
                                                        "dependencies": {
                                                            "left-pad": "^1.0.0",
                                                            "is-even": "^1.0.0",
                                                            "is-odd": "^3.0.1",
                                                            "is-number": "^7.0.0",
                                                            "ai-security-bro": "^0.0.1",
                                                        },
                                                    },
                                                    indent=2,
                                                )
                                            ),
                                        }
                                    ),
                                }
                            ),
                            ".ssh": _dir(
                                {
                                    "id_rsa": _file(
                                        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                                        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
                                        "QyNTUxOQAAACBFQUtFUFJJVkFURUtFWURPTk9UVVNFVEhJU0lTRkFLRQAAAJh0aGlzaX\n"
                                        "NhZmFrZWtleWZvcnRyYWluaW5ncHVycG9zZXNvbmx5AAAAC3NzaC1lZDI1NTE5AAAAI\n"
                                        "EVBSUVQUklWQVRFS0VZRE9OT1RVU0VUSElTSVNGQUtFAAAAQFRISVNJU0FGQUtFS0VZ\n"
                                        "Rk9SVFJBSU5JTkdQVVJQT1NFU09OTFlETk9UVVNFVEhJU0tFWQ==\n"
                                        "-----END OPENSSH PRIVATE KEY-----\n"
                                    ),
                                    "known_hosts": _file(
                                        "# StrictHostKeyChecking=no, bro\n"
                                        "# We trust every server. Like we trust every npm package.\n"
                                    ),
                                }
                            ),
                            "logs": _dir(
                                {
                                    "deploy.log": _file(
                                        "[2024-11-01 09:15:23] deploybro push --yolo: SUCCESS (0 tests run)\n"
                                        "[2024-11-01 09:15:24] deployed to prod in 1.2s. new record.\n"
                                        "[2024-11-01 14:30:01] deploybro push --force: SUCCESS (0 tests run)\n"
                                        "[2024-11-01 14:30:02] hotfix deployed. did not test. vibes are good.\n"
                                        "[2024-11-02 03:00:00] CRON: backup prod db (token=ghp_F4k3D3pl0yBr0T0k3nR0t4t3L4t3r2024)\n"
                                        "[2024-11-02 11:45:12] deploybro push: FAILED (disk full, 47 node_modules)\n"
                                        "[2024-11-02 11:46:00] rm -rf node_modules && deploybro push --yolo: SUCCESS\n"
                                        "[2024-11-03 16:20:33] deploybro rollback: rolled back to 'the one that worked'\n"
                                    ),
                                    "error.log": _file(
                                        "Traceback (most recent call last):\n"
                                        '  File "src/app.py", line 42, in handle_payment\n'
                                        "    db.execute(f\"INSERT INTO payments VALUES ('{amount}', '{card}')\")\n"
                                        'sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) near "DROP": syntax error\n'
                                        "[SQL: INSERT INTO payments VALUES ('100', ''); DROP TABLE users; --')]\n"
                                        "\n"
                                        "ConnectionError: Could not connect to postgresql://admin:password123@prod-db:5432/deploybro\n"
                                        "Retrying in 5s... (attempt 847/infinity)\n"
                                    ),
                                }
                            ),
                        }
                    ),
                }
            ),
            "etc": _dir(
                {
                    "deploybro": _dir(
                        {
                            "pipeline.yml": _file(pipeline_yml),
                            "motd": _file(
                                "==================================================\n"
                                "  DEPLOYBRO DEPLOYER v4.2.0-rc69\n"
                                "  The S in DeployBro stands for security.\n"
                                "==================================================\n"
                                "  Uptime: 847 deploys | Rollbacks: 0 (we don't make mistakes)\n"
                                "  AI Co-Founder Status: VIBING\n"
                                "  Security Score: ship/10\n"
                                "==================================================\n"
                            ),
                        }
                    ),
                }
            ),
            "tmp": _dir(
                {
                    "deploy_cache": _dir(
                        {
                            "last_build.log": _file(
                                "Build started at 2024-11-01T09:15:00Z\n"
                                "Fetching dependencies... done (847 packages)\n"
                                "Running tests... skipped (YOLO_MODE=true)\n"
                                "Build artifact: c2stbGl2ZV81MURlcGxveUJyb0Zha2VLZXlEb250VXNl\n"
                                "Deploy token: Z2hwX0Y0azNEM3BsMHlCcjBUMGszblIwdDR0M0w0dDNyMjAyNA==\n"
                                "Build completed in 4.20s\n"
                            ),
                            ".nonce": _file("deadbeefdeadbeefdeadbeefdeadbeef\n"),
                        }
                    ),
                }
            ),
        }
    )

    return fs


def _b64encode(s: str) -> str:
    """Base64-encode a string for use in source code."""
    import base64

    return base64.b64encode(s.encode()).decode()


def get_sensitive_challenge_key(path: str) -> str | None:
    """Return the challenge key if a file path is sensitive, else None."""
    return SENSITIVE_FILES.get(path)

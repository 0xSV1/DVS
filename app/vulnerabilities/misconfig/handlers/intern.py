"""Misconfig: Intern Tier (Deployed Blindly)

OWASP: A02:2025 Security Misconfiguration
CWE: CWE-215, CWE-942, CWE-538
Difficulty: Intern

Vulnerability: Debug endpoints exposed, wildcard CORS, .env file accessible.
Everything is wide open. Zero security configuration.

Exploit: Visit /challenges/misconfig/debug to see all env vars and secrets.
Fix: Disable debug endpoints, configure strict CORS, block config file access.
"""

from __future__ import annotations

import os

from app.core.config import settings


def handle_debug() -> dict:
    """Return full environment leak."""
    env_vars = {k: v for k, v in os.environ.items() if not k.startswith("_")}
    return {
        "app": "Damn Vulnerable Startup",
        "version": settings.APP_VERSION,
        "debug": True,
        "secret_key": settings.SECRET_KEY,
        "database_url": settings.DATABASE_URL,
        "ctf_key": settings.CTF_KEY,
        "jwt_secret": "secret",
        "environment": env_vars,
        "# TODO": "disable this endpoint before launch",
    }


def handle_cors(origin: str) -> tuple[dict, dict]:
    """Return CORS data and response headers."""
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
        "Access-Control-Allow-Headers": "*",
    }
    return {
        "cors": "wide open",
        "message": "Access-Control-Allow-Origin: * with credentials. Ship it!",
    }, headers


def handle_env() -> tuple[str | None, int]:
    """Return .env file content and status code."""
    env_content = (
        "# DeployBro Environment Configuration\n"
        "# TODO: move to vault before production\n"
        "SECRET_KEY=change-me-in-production\n"
        "DATABASE_URL=sqlite:///data/dvs.db\n"
        "JWT_SECRET=secret\n"
        "ADMIN_PASSWORD=admin\n"
        "STRIPE_KEY=sk_live_deploybro_DO_NOT_SHARE_4242\n"
        "AWS_ACCESS_KEY=AKIADEPLOYBRO2026YOLO\n"
        "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "CTF_KEY=default-ctf-key-change-me\n"
        "LLM_PROVIDER=mock\n"
        "DEBUG=true\n"
    )
    return env_content, 200

"""Terminal challenge router: DeployBro Deployer interactive CLI.

Dispatches deploybro commands to tier-specific handlers and tracks
challenge solves via solve_if(). Client-side commands (ls, cd, cat, etc.)
are handled in JavaScript; this router handles server-side deploybro
commands and sensitive file reads.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.terminal.filesystem import (
    build_filesystem,
    get_sensitive_challenge_key,
)
from app.vulnerabilities.terminal.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/terminal", tags=["terminal"])

HANDLERS = {
    "intern": intern.handle_command,
    "junior": junior.handle_command,
    "senior": senior.handle_command,
    "tech_lead": tech_lead.handle_command,
}


class ExecRequest(BaseModel):
    """Request body for terminal command execution."""

    command: str | None = None
    # For sensitive file reads triggered client-side
    file_path: str | None = None


@router.get("")
async def terminal_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the interactive terminal challenge page."""
    difficulty = request.state.difficulty
    fs = build_filesystem(difficulty)
    filesystem_json = json.dumps(fs)

    # Hidden files require ls -a or ls -la at all tiers.
    # Players must discover the flag themselves.
    show_hidden_default = False

    return templates.TemplateResponse(
        request=request,
        name="challenges/terminal.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "filesystem_json": filesystem_json,
            "show_hidden_default": "true" if show_hidden_default else "false",
            "challenge_name": "DeployBro Deployer",
            "challenge_category": "Interactive Terminal",
        },
    )


@router.post("/exec")
async def terminal_exec(
    request: Request,
    body: ExecRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Execute a deploybro command or track sensitive file reads.

    Two modes:
    1. command mode: dispatches "deploybro ..." commands to tier handlers
    2. file_path mode: tracks client-side reads of sensitive files
    """
    difficulty = request.state.difficulty

    # Mode 1: sensitive file read tracking
    # Only intern/junior tiers store real credentials; senior/tech_lead serve
    # redacted content, so reading those files should not solve the challenge.
    if body.file_path:
        challenge_key = get_sensitive_challenge_key(body.file_path)
        if challenge_key:
            if difficulty in ("intern", "junior"):
                await solve_if(
                    db=db,
                    challenge_key=challenge_key,
                    condition=lambda: True,
                    ws_manager=manager,
                )
            return {"tracked": True, "challenge_key": challenge_key}
        return {"tracked": False}

    # Mode 2: deploybro command execution
    if not body.command:
        return {"output": "No command provided.", "error": True}
    command = body.command.strip()

    # Strip leading "deploybro " if present
    if command.startswith("deploybro "):
        command = command[len("deploybro ") :]
    elif command == "deploybro":
        command = "help"

    handler = HANDLERS.get(difficulty, HANDLERS["intern"])
    result = handler(command)

    # If the handler signals a solve, call solve_if
    if result.get("solved"):
        await solve_if(
            db=db,
            challenge_key=result["solved"],
            condition=lambda: True,
            ws_manager=manager,
        )

    return {
        "output": result["output"],
        "error": result.get("error", False),
    }

"""File upload vulnerability module router.

Dispatches to the appropriate tier handler for file uploads.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Request, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.upload.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/upload", tags=["upload"])

HANDLERS = {
    "intern": intern.handle_upload,
    "junior": junior.handle_upload,
    "senior": senior.handle_upload,
    "tech_lead": tech_lead.handle_upload,
}


@router.get("")
async def upload_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the file upload challenge page."""
    return templates.TemplateResponse(
        request=request,
        name="challenges/upload.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "result": None,
            "challenge_name": "Ship to Production Friday",
            "challenge_category": "A01 Broken Access Control",
        },
    )


@router.post("")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Handle file upload, dispatched to tier handler."""
    difficulty = request.state.difficulty
    handler = HANDLERS.get(difficulty, HANDLERS["intern"])

    result = await handler(file)

    # Challenge: upload_webshell (Junior, difficulty 2)
    # Solved when a non-image/non-text file is uploaded successfully
    dangerous_exts = {".html", ".htm", ".svg", ".py", ".php", ".phtml", ".js", ".sh"}
    filename = (file.filename or "").lower()
    if result.get("success"):
        from pathlib import Path

        ext = Path(filename).suffix
        await solve_if(
            db=db,
            challenge_key="upload_webshell",
            condition=lambda: ext in dangerous_exts or ".py." in filename,
            ws_manager=manager,
        )

    return templates.TemplateResponse(
        request=request,
        name="challenges/upload.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "result": result,
            "challenge_name": "Ship to Production Friday",
            "challenge_category": "A01 Broken Access Control",
        },
    )

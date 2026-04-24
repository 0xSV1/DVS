"""Setup and system routes: health check, database reset, system status, WebSocket."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.db.reset import reset_database
from app.models.challenge import Challenge
from app.models.user import User
from app.services.websocket_manager import manager

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint for container orchestration."""
    return {"status": "ok", "app": "Damn Vulnerable Startup"}


@router.get("/setup")
async def setup_page(request: Request, db: Session = Depends(get_db)) -> object:
    """Setup page showing system status and reset button."""
    user_count = db.query(User).count()
    challenge_count = db.query(Challenge).count()
    solved_count = db.query(Challenge).filter(Challenge.solved.is_(True)).count()

    return templates.TemplateResponse(
        request=request,
        name="setup.html",
        context={
            "user_count": user_count,
            "challenge_count": challenge_count,
            "solved_count": solved_count,
            "difficulty": request.state.difficulty,
        },
    )


@router.post("/api/setup/reset")
async def reset_db(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> JSONResponse:
    """Reset the database: drop all tables, recreate schema, re-seed.

    At tech_lead tier, requires admin authentication. Lower tiers allow
    unauthenticated reset (the insecurity is part of the learning experience).
    """
    difficulty = getattr(request.state, "difficulty", "intern")
    if difficulty == "tech_lead":
        if current_user is None or current_user.role != "admin":
            return JSONResponse(
                status_code=403,
                content={"status": "error", "message": "Admin authentication required at tech_lead tier."},
            )
    reset_database()
    response = JSONResponse(
        content={
            "status": "ok",
            "message": "Database reset complete. All data has been wiped and re-seeded.",
        }
    )
    response.delete_cookie("access_token")
    return response


@router.websocket("/ws/notifications")
async def notifications_ws(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time challenge solve notifications."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; clients don't send data
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

"""Cryptographic failures vulnerability module router.

Dispatches to the appropriate tier handler for hash exposure,
password crack verification, and hardcoded secrets challenges.
Integrates solve_if() for challenge detection.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.crypto.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/crypto", tags=["crypto"])

HASH_HANDLERS = {
    "intern": intern.handle_get_hashes,
    "junior": junior.handle_get_hashes,
    "senior": senior.handle_get_hashes,
    "tech_lead": tech_lead.handle_get_hashes,
}

CRACK_HANDLERS = {
    "intern": intern.handle_crack,
    "junior": junior.handle_crack,
    "senior": senior.handle_crack,
    "tech_lead": tech_lead.handle_crack,
}

SECRETS_GET_HANDLERS = {
    "intern": intern.handle_get_secrets,
    "junior": junior.handle_get_secrets,
    "senior": senior.handle_get_secrets,
    "tech_lead": tech_lead.handle_get_secrets,
}

SECRETS_VERIFY_HANDLERS = {
    "intern": intern.handle_verify_secret,
    "junior": junior.handle_verify_secret,
    "senior": senior.handle_verify_secret,
    "tech_lead": tech_lead.handle_verify_secret,
}


@router.get("")
async def crypto_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the crypto challenge page showing password hashes."""
    difficulty = request.state.difficulty
    handler = HASH_HANDLERS.get(difficulty, HASH_HANDLERS["intern"])
    hashes = handler(db)

    return templates.TemplateResponse(
        request=request,
        name="challenges/crypto.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "hashes": hashes,
            "result": None,
            "challenge_name": "Hashing? Trust Me Bro",
            "challenge_category": "A04 Cryptographic Failures",
        },
    )


@router.post("/crack")
async def verify_crack(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Verify a cracked password hash."""
    difficulty = request.state.difficulty
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")

    crack_handler = CRACK_HANDLERS.get(difficulty, CRACK_HANDLERS["intern"])
    result = crack_handler(db, username, password)

    if result.get("success"):
        await solve_if(
            db=db,
            challenge_key="crypto_md5",
            condition=lambda: username != "" and password != "",
            ws_manager=manager,
        )

    hash_handler = HASH_HANDLERS.get(difficulty, HASH_HANDLERS["intern"])
    hashes = hash_handler(db)

    return templates.TemplateResponse(
        request=request,
        name="challenges/crypto.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "hashes": hashes,
            "result": result,
            "challenge_name": "Hashing? Trust Me Bro",
            "challenge_category": "A04 Cryptographic Failures",
        },
    )


# -- Hardcoded Secrets Challenge ------------------------------------------


@router.get("/secrets")
async def secrets_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the Partner API Dashboard showing hardcoded secrets."""
    difficulty = request.state.difficulty
    handler = SECRETS_GET_HANDLERS.get(difficulty, SECRETS_GET_HANDLERS["intern"])
    secrets_ctx = handler()

    return templates.TemplateResponse(
        request=request,
        name="challenges/crypto_secrets.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "result": None,
            "challenge_name": "API Keys are Environment Variables, Right?",
            "challenge_category": "A04 Cryptographic Failures",
            **secrets_ctx,
        },
    )


@router.post("/secrets/verify")
async def verify_secret(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Verify a submitted API key against the hardcoded secret."""
    difficulty = request.state.difficulty
    form = await request.form()
    submitted_key = form.get("api_key", "")

    verify_handler = SECRETS_VERIFY_HANDLERS.get(difficulty, SECRETS_VERIFY_HANDLERS["intern"])
    result = verify_handler(submitted_key)

    if result.get("success"):
        await solve_if(
            db=db,
            challenge_key="crypto_hardcoded_secret",
            condition=lambda: submitted_key.strip() != "",
            ws_manager=manager,
        )

    get_handler = SECRETS_GET_HANDLERS.get(difficulty, SECRETS_GET_HANDLERS["intern"])
    secrets_ctx = get_handler()

    return templates.TemplateResponse(
        request=request,
        name="challenges/crypto_secrets.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "result": result,
            "challenge_name": "API Keys are Environment Variables, Right?",
            "challenge_category": "A04 Cryptographic Failures",
            **secrets_ctx,
        },
    )

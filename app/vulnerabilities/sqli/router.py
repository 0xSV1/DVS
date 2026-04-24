"""SQLi vulnerability module router.

Dispatches to the appropriate tier handler for product search and
blind SQLi username check.
Integrates solve_if() for challenge detection.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.sqli.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/sqli", tags=["sqli"])

SEARCH_HANDLERS = {
    "intern": lambda db, q, **kw: intern.handle_search(db, q),
    "junior": lambda db, q, **kw: junior.handle_search(db, q),
    "senior": lambda db, q, **kw: senior.handle_search(db, q, sort=kw.get("sort", "name")),
    "tech_lead": lambda db, q, **kw: tech_lead.handle_search(db, q, sort=kw.get("sort", "name")),
}

BLIND_HANDLERS = {
    "intern": intern.handle_blind_check,
    "junior": junior.handle_blind_check,
    "senior": senior.handle_blind_check,
    "tech_lead": tech_lead.handle_blind_check,
}

# Pattern that detects boolean-based blind SQLi attempts
_BLIND_SQLI_PATTERN = re.compile(r"'\s*(OR|AND)\s+", re.IGNORECASE)


@router.get("")
async def sqli_page(
    request: Request,
    query: str = "",
    sort: str = "name",
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the SQLi challenge page with search results."""
    difficulty = request.state.difficulty
    handler = SEARCH_HANDLERS.get(difficulty, SEARCH_HANDLERS["intern"])

    results = []
    sql_used = ""

    if query:
        results, sql_used = handler(db, query, sort=sort)

        # Challenge: sqli_search (Intern, difficulty 1)
        # Solved when injection returns more products than a legit search would
        await solve_if(
            db=db,
            challenge_key="sqli_search",
            condition=lambda: len(results) > 4 and query != "",
            ws_manager=manager,
        )

    return templates.TemplateResponse(
        request=request,
        name="challenges/sqli.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "query": query,
            "results": results,
            "sql_used": sql_used,
            "challenge_name": "SELECT * FROM Funding",
            "challenge_category": "A05 Injection",
        },
    )


@router.get("/blind")
async def sqli_blind_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the blind SQLi challenge page."""
    return templates.TemplateResponse(
        request=request,
        name="challenges/sqli_blind.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "username": "",
            "challenge_name": "The Billion Dollar Pivot",
            "challenge_category": "A05 Injection",
        },
    )


@router.get("/check-username")
async def sqli_blind_check(
    request: Request,
    username: str = "",
    db: Session = Depends(get_db),
) -> dict:
    """Blind SQLi: check username availability.

    OWASP: A05:2025 Injection
    CWE: CWE-89 (SQL Injection, Blind)

    Intern tier: raw f-string interpolation into COUNT query.
    Junior tier: single-quote escaping, bypassable with backslash or double encoding.
    Senior/Tech Lead: parameterized query.
    """
    difficulty = request.state.difficulty
    handler = BLIND_HANDLERS.get(difficulty, BLIND_HANDLERS["intern"])
    count = handler(db, username)

    available = count == 0

    # Challenge: sqli_blind
    # Solved when boolean injection patterns are detected in the username
    # and the difficulty tier actually allows the injection to work
    await solve_if(
        db=db,
        challenge_key="sqli_blind",
        condition=lambda: bool(_BLIND_SQLI_PATTERN.search(username)) and difficulty in ("intern", "junior"),
        ws_manager=manager,
    )

    return {"username": username, "available": available}

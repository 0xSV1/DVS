"""XSS vulnerability module router.

Dispatches to the appropriate tier handler for reflected XSS.
Integrates solve_if() for challenge detection.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.xss.handlers import intern, junior, senior, tech_lead

router = APIRouter(prefix="/challenges/xss", tags=["xss"])

HANDLERS = {
    "intern": intern.handle_reflect,
    "junior": junior.handle_reflect,
    "senior": senior.handle_reflect,
    "tech_lead": tech_lead.handle_reflect,
}


@router.get("")
async def xss_page(
    request: Request,
    q: str = "",
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the XSS challenge page with reflected input."""
    difficulty = request.state.difficulty
    handler = HANDLERS.get(difficulty, HANDLERS["intern"])

    result = None
    if q:
        result = handler(q)

        # Challenge: xss_reflected
        # Broad pattern list covering PortSwigger XSS cheat sheet vectors.
        # At senior tier, tag-based payloads are encoded so only JS string
        # breakout counts (single/double quote followed by JS syntax).
        _xss_tag_patterns = [
            "<script",
            "<img",
            "<svg",
            "<body",
            "<iframe",
            "<input",
            "<details",
            "<video",
            "<audio",
            "<marquee",
            "<object",
            "<embed",
            "<math",
            "<table",
            "<div",
            "<select",
            "<textarea",
            "<button",
            "<a ",
            "<style",
        ]
        _xss_event_patterns = [
            "onerror",
            "onload",
            "onmouseover",
            "onfocus",
            "onclick",
            "onmouseenter",
            "ontoggle",
            "onanimationend",
            "onblur",
            "onchange",
            "oninput",
            "onkeydown",
            "onkeyup",
            "onkeypress",
            "onpointerover",
            "onpointerenter",
            "oncontextmenu",
            "ondrag",
            "ondragstart",
            "ondrop",
            "onpaste",
            "oncut",
            "onscroll",
            "onwheel",
            "onresize",
            "onhashchange",
            "onpopstate",
            "onsearch",
            "ontransitionend",
        ]
        _xss_uri_patterns = ["javascript:", "data:text/html"]
        lower_q = q.lower()

        if difficulty in ("intern", "junior"):
            # Tag injection or event handlers
            has_xss = (
                any(p in lower_q for p in _xss_tag_patterns)
                or any(p in lower_q for p in _xss_event_patterns)
                or any(p in lower_q for p in _xss_uri_patterns)
            )
        elif difficulty == "senior":
            # Tags are encoded; only JS string breakout counts
            has_xss = ("'" in q or '"' in q) and (
                "alert" in lower_q
                or "confirm" in lower_q
                or "prompt" in lower_q
                or "eval" in lower_q
                or "document" in lower_q
                or "window" in lower_q
                or "fetch" in lower_q
                or "xmlhttp" in lower_q
            )
        else:
            has_xss = False

        await solve_if(
            db=db,
            challenge_key="xss_reflected",
            condition=lambda: has_xss,
            ws_manager=manager,
        )

    response = templates.TemplateResponse(
        request=request,
        name="challenges/xss.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "query": q,
            "result": result,
            "challenge_name": "Alert('Ship It!')",
            "challenge_category": "A05 Injection",
        },
    )

    # Tech Lead: add CSP header
    if result and result.get("csp"):
        response.headers["Content-Security-Policy"] = result["csp"]

    return response


@router.get("/dom")
async def xss_dom_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the DOM-based XSS challenge page."""
    difficulty = request.state.difficulty
    return templates.TemplateResponse(
        request=request,
        name="challenges/xss_dom.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "challenge_name": "Client-Side Deploys Only",
            "challenge_category": "A05 Injection",
        },
    )


@router.post("/dom/solve")
async def xss_dom_solve(
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    """Called by client-side JS when DOM XSS is triggered."""
    difficulty = request.state.difficulty
    body = await request.json()
    payload = body.get("payload", "")
    lower_payload = payload.lower()
    xss_patterns = [
        "<script",
        "<img",
        "<svg",
        "<body",
        "<iframe",
        "<details",
        "<video",
        "<audio",
        "<input",
        "<marquee",
        "<math",
        "onerror",
        "onload",
        "onclick",
        "onmouseover",
        "onfocus",
        "ontoggle",
        "onanimationend",
        "onpointerover",
        "javascript:",
        "data:text/html",
    ]

    await solve_if(
        db=db,
        challenge_key="xss_dom",
        condition=lambda: difficulty != "tech_lead" and any(p in lower_payload for p in xss_patterns),
        ws_manager=manager,
    )
    return {"status": "ok"}

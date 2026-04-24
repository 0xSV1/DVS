"""Authentication routes: login, register, logout.

Login implements per-difficulty SQL handling:
- Intern: raw f-string SQL (SQLi auth bypass)
- Junior: escaping with bypassable flaws
- Senior: parameterized query, timing side-channel
- Tech Lead: parameterized + bcrypt + CSRF token
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.core.security import create_access_token, hash_password
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.sqli.handlers import intern as sqli_intern
from app.vulnerabilities.sqli.handlers import junior as sqli_junior
from app.vulnerabilities.sqli.handlers import senior as sqli_senior
from app.vulnerabilities.sqli.handlers import tech_lead as sqli_tech_lead

LOGIN_HANDLERS = {
    "intern": sqli_intern.handle_login_query,
    "junior": sqli_junior.handle_login_query,
    "senior": sqli_senior.handle_login_query,
    "tech_lead": sqli_tech_lead.handle_login_query,
}

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/login")
async def login_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the login page."""
    if current_user:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "difficulty": request.state.difficulty,
            "error": None,
        },
    )


@router.post("/login")
async def login(
    request: Request,
    db: Session = Depends(get_db),
) -> object:
    """Handle login form submission with per-difficulty auth handling."""
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")
    difficulty = request.state.difficulty

    login_handler = LOGIN_HANDLERS.get(difficulty, LOGIN_HANDLERS["intern"])
    user = login_handler(db, username, password)

    if not user:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "difficulty": difficulty,
                "error": "Invalid username or password",
            },
        )

    # Check sqli_login challenge: auth bypass via SQL injection in the login form
    # Detects classic SQLi patterns in the username field (OR-based bypass, comment
    # truncation, UNION injection). Only fires at intern/junior where raw SQL is used.
    _sqli_indicators = ("' or ", "' OR ", "'or ", "'OR ", "' --", "'--", "union ", "UNION ")
    await solve_if(
        db=db,
        challenge_key="sqli_login",
        condition=lambda: any(ind in username for ind in _sqli_indicators),
        ws_manager=manager,
    )

    # Check auth_weak_pw challenge: logging in as admin with weak creds
    if user.username == "admin" and password == "admin":
        await solve_if(
            db=db,
            challenge_key="auth_weak_pw",
            condition=lambda: True,
            ws_manager=manager,
        )

    # Issue JWT
    token = create_access_token(
        data={"sub": str(user.id), "username": user.username, "role": user.role},
        difficulty=difficulty,
    )

    # Intern/Junior: redirect to profile with sequential user ID in the URL
    # (leaks the ID, feeds into the IDOR challenge). Senior/Tech Lead: home page.
    if difficulty in ("intern", "junior"):
        redirect_url = f"/challenges/idor/profile/{user.id}"
    else:
        redirect_url = "/"

    # Cookie security escalates with difficulty tier:
    # Intern:    httponly=False, samesite=lax    → JS can read the token
    # Junior:    httponly=False, samesite=lax    → JS can read the token
    # Senior:    httponly=True,  samesite=lax    → no JS access
    # Tech Lead: httponly=True,  samesite=strict → no JS access, strict CSRF
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=difficulty in ("senior", "tech_lead"),
        samesite="strict" if difficulty == "tech_lead" else "lax",
        secure=False,  # Running on localhost
        max_age=3600,
    )
    return response


@router.post("/login/quickship")
async def login_quickship(
    request: Request,
    db: Session = Depends(get_db),
) -> object:
    """Hidden easter egg: spam-clicking the login button 11 times bypasses auth.

    Only works at intern difficulty. Simulates a client-side race condition
    where rapid form submissions overflow a nonexistent rate limiter and
    the server just gives up and lets you in. Classic deploy-bro energy.
    """
    if request.state.difficulty != "intern":
        return RedirectResponse(url="/login", status_code=303)

    # # AI said race conditions aren't real if you don't think about them
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        return RedirectResponse(url="/login", status_code=303)

    token = create_access_token(
        data={"sub": str(admin.id), "username": admin.username, "role": admin.role},
        difficulty="intern",
    )

    response = RedirectResponse(
        url=f"/challenges/idor/profile/{admin.id}",
        status_code=303,
    )
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=False,  # intern tier: JS-readable, obviously
        samesite="lax",
        secure=False,
        max_age=3600,
    )
    logger.info("Easter egg triggered: quickship login bypass for admin")
    return response


@router.get("/register")
async def register_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the registration page."""
    if current_user:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "difficulty": request.state.difficulty,
            "error": None,
            "success": None,
        },
    )


@router.post("/register")
async def register(
    request: Request,
    db: Session = Depends(get_db),
) -> object:
    """Handle registration form submission."""
    form = await request.form()
    username = form.get("username", "").strip()
    email = form.get("email", "").strip()
    password = form.get("password", "")
    difficulty = request.state.difficulty

    if not username or not email or not password:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "difficulty": difficulty,
                "error": "All fields are required",
                "success": None,
            },
        )

    existing = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "difficulty": difficulty,
                "error": "Username or email already taken",
                "success": None,
            },
        )

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password, difficulty),
        role="user",
    )
    db.add(user)
    db.commit()

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "difficulty": difficulty,
            "error": None,
            "success": "Account created. You can now log in.",
        },
    )


@router.get("/logout")
async def logout(request: Request) -> RedirectResponse:
    """Clear auth cookie and redirect to home."""
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("access_token")
    return response

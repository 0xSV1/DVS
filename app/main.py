"""Damn Vulnerable Startup: FastAPI application factory.

Ship First, Ask Questions Never.
The S in "deploy bro" stands for security.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import BASE_DIR, settings
from app.db.reset import init_database
from app.middleware.audit import AuditMiddleware
from app.middleware.difficulty import DifficultyMiddleware

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup: initialize database and seed if empty
    logger.info("Starting Damn Vulnerable Startup v%s", settings.APP_VERSION)
    logger.info(
        "Difficulty: %s | CTF Mode: %s | LLM Provider: %s",
        settings.DEFAULT_DIFFICULTY,
        settings.CTF_MODE,
        settings.LLM_PROVIDER,
    )
    if settings.SECRET_KEY == "change-me-in-production":
        logger.warning(
            "WARNING: Using default SECRET_KEY — change before production. "
            "Set SECRET_KEY in .env or via environment variable."
        )
    if settings.CTF_MODE and settings.CTF_KEY == "default-ctf-key-change-me":
        logger.warning(
            "WARNING: CTF mode is enabled with the default CTF_KEY. "
            "Flags are predictable. Set CTF_KEY in .env or via environment variable."
        )
    init_database()
    logger.info("Database initialized.")
    yield
    # Shutdown
    logger.info("Shutting down Damn Vulnerable Startup.")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Damn Vulnerable Startup",
        description="Ship First, Ask Questions Never. Deliberately vulnerable.",
        version=settings.APP_VERSION,
        docs_url="/docs" if settings.DEBUG else None,  # Exposed in debug mode (A02 Misconfig)
        redoc_url=None,
        lifespan=lifespan,
    )

    # Middleware (order matters: last added = first executed)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(DifficultyMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        session_cookie="session",
        max_age=86400,  # 24 hours
    )

    # Static files
    static_dir = BASE_DIR / "app" / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Register routes
    _register_routes(app)

    # Custom error pages
    _register_error_handlers(app)

    return app


def _register_error_handlers(app: FastAPI) -> None:
    """Register custom 404 and 500 error pages."""
    from app.api.deps import templates

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: Exception) -> HTMLResponse:
        difficulty = getattr(request.state, "difficulty", "intern")
        return HTMLResponse(
            content=templates.get_template("404.html").render(
                request=request,
                current_user=None,
                difficulty=difficulty,
            ),
            status_code=404,
        )

    @app.exception_handler(500)
    async def server_error_handler(request: Request, exc: Exception) -> HTMLResponse:
        difficulty = getattr(request.state, "difficulty", "intern")
        return HTMLResponse(
            content=templates.get_template("500.html").render(
                request=request,
                current_user=None,
                difficulty=difficulty,
            ),
            status_code=500,
        )


def _register_routes(app: FastAPI) -> None:
    """Register all route handlers."""
    from app.api.routes.admin import router as admin_router
    from app.api.routes.auth import router as auth_router
    from app.api.routes.auth_challenges import router as auth_challenges_router
    from app.api.routes.blog import router as blog_router
    from app.api.routes.brobot import router as brobot_router
    from app.api.routes.challenges import router as challenges_router
    from app.api.routes.owasp import router as owasp_router
    from app.api.routes.pages import router as pages_router
    from app.api.routes.setup import router as setup_router
    from app.api.routes.view_source import router as source_router
    from app.vulnerabilities.broken_logging.router import router as broken_logging_router
    from app.vulnerabilities.crypto.router import router as crypto_router
    from app.vulnerabilities.csrf.router import router as csrf_router
    from app.vulnerabilities.deserialize.router import router as deserialize_router
    from app.vulnerabilities.idor.router import router as idor_router
    from app.vulnerabilities.llm.router import router as llm_router
    from app.vulnerabilities.log_injection.router import router as log_injection_router
    from app.vulnerabilities.mass_assign.router import router as mass_assign_router
    from app.vulnerabilities.misconfig.router import router as misconfig_router
    from app.vulnerabilities.open_redirect.router import router as open_redirect_router
    from app.vulnerabilities.sqli.router import router as sqli_router
    from app.vulnerabilities.ssrf.router import router as ssrf_router
    from app.vulnerabilities.ssti.router import router as ssti_router
    from app.vulnerabilities.terminal.router import router as terminal_router
    from app.vulnerabilities.upload.router import router as upload_router
    from app.vulnerabilities.xss.router import router as xss_router

    # System and page routes
    app.include_router(setup_router, tags=["system"])
    app.include_router(auth_router, tags=["auth"])
    app.include_router(challenges_router, tags=["challenges"])
    app.include_router(pages_router, tags=["pages"])

    # Vulnerability modules
    app.include_router(sqli_router)
    app.include_router(xss_router)
    app.include_router(idor_router)
    app.include_router(ssti_router)
    app.include_router(misconfig_router)
    app.include_router(upload_router)
    app.include_router(llm_router)
    app.include_router(ssrf_router)
    app.include_router(csrf_router)
    app.include_router(deserialize_router)
    app.include_router(crypto_router)
    app.include_router(log_injection_router)
    app.include_router(terminal_router)
    app.include_router(auth_challenges_router)
    app.include_router(admin_router)
    app.include_router(blog_router)
    app.include_router(mass_assign_router)
    app.include_router(open_redirect_router)
    app.include_router(broken_logging_router)

    # BroBot widget API
    app.include_router(brobot_router)

    # Educational features
    app.include_router(source_router)
    app.include_router(owasp_router)


# Application instance
app = create_app()

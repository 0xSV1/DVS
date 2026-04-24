"""Audit logging middleware: logs requests to the audit_logs table.

At intern/junior tiers, this deliberately logs sensitive data (passwords,
tokens) to demonstrate OWASP A09: Security Logging and Alerting Failures.
"""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """Log HTTP requests to the audit_logs table."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Skip static files and health checks
        path = request.url.path
        if path.startswith("/static") or path == "/health":
            return await call_next(request)

        response = await call_next(request)

        # Log the request (actual DB logging will be added with route handlers)
        logger.debug(
            "%s %s -> %d (client: %s)",
            request.method,
            path,
            response.status_code,
            request.client.host if request.client else "unknown",
        )

        return response

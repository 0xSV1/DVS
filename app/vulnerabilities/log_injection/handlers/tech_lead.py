"""Log Injection: Tech Lead Tier (Secure Implementation)

OWASP: A09:2025 Security Logging and Monitoring Failures
CWE: CWE-117 (Improper Output Neutralization for Logs)
Difficulty: Tech Lead

Mitigation: All control characters stripped from feedback content. Username
derived from the authenticated session, not from user input. Log entries
are HTML-entity-encoded in the template. Each entry includes an HMAC
integrity hash to detect tampering.

Exploit: None. This is the reference secure implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import re
from datetime import datetime, timezone

from app.core.config import settings


def get_log_username(current_user: object | None, form_username: str) -> str:
    """Return username for log entry: uses authenticated session username.

    Args:
        current_user: Currently authenticated user.
        form_username: Username from form input (ignored).

    Returns:
        The session username, or "anonymous" if not authenticated.
    """
    return current_user.username if current_user else "anonymous"


def check_log_injection_solve(raw_feedback: str, original_feedback: str) -> bool:
    """Check if tech-lead-tier log injection was successful.

    Tech lead tier is not solvable; this is the secure reference implementation.

    Args:
        raw_feedback: The feedback after handler processing.
        original_feedback: The original unmodified feedback from the form.

    Returns:
        Always False.
    """
    return False


def handle_submit_feedback(
    feedback: str,
    username: str,
) -> dict:
    """Store feedback with full sanitization and integrity protection.

    All control characters stripped, username from session (enforced by router),
    content HTML-encoded, and entry signed with HMAC for tamper detection.

    Args:
        feedback: User feedback text.
        username: Authenticated username from session (verified by router).

    Returns:
        Dict with stored feedback, metadata, and integrity hash.
    """
    # Strip all control characters except space
    sanitized = re.sub(r"[\x00-\x1f\x7f]", "", feedback)
    # HTML-encode to prevent rendering injection in log viewer
    encoded = html.escape(sanitized)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [USER:{username}] action=feedback msg={encoded}"

    # HMAC integrity hash to detect log tampering
    integrity = hmac.new(
        settings.SECRET_KEY.encode(),
        log_entry.encode(),
        hashlib.sha256,
    ).hexdigest()[:16]

    return {
        "stored": True,
        "entry": f"{log_entry} [integrity={integrity}]",
        "raw_feedback": encoded,
    }

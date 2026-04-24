"""Log Injection: Senior Tier (Real Security, Subtle Flaw)

OWASP: A09:2025 Security Logging and Monitoring Failures
CWE: CWE-117 (Improper Output Neutralization for Logs)
Difficulty: Senior

Vulnerability: All control characters are stripped from the feedback content.
However, the username field comes from user input (form field), not from the
authenticated session. An attacker can spoof the identity context of log
entries without injecting newlines.

Exploit: Submit feedback with a spoofed username like "ADMIN" or "SYSTEM".
Fix: Always derive username from the authenticated session (see tech_lead.py).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone


def get_log_username(current_user: object | None, form_username: str) -> str:
    """Return username for log entry: always uses form input.

    Args:
        current_user: Currently authenticated user (ignored).
        form_username: Username from form input.

    Returns:
        The form username as-is.
    """
    return form_username


def check_log_injection_solve(raw_feedback: str, original_feedback: str) -> bool:
    """Check if senior-tier log injection was successful.

    Senior tier is not solvable via log injection; control chars are stripped.

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
    """Store feedback after stripping all control characters from content.

    Control characters (< ASCII 32 except space) are removed from feedback.
    But the username comes from the form, not the session, so identity
    can be spoofed.

    Args:
        feedback: User feedback text.
        username: Display name from form input (not verified against session).

    Returns:
        Dict with stored feedback and metadata.
    """
    # Strip all control characters except space (ASCII 32)
    sanitized = re.sub(r"[\x00-\x1f\x7f]", "", feedback)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [USER:{username}] action=feedback msg={sanitized}"
    return {
        "stored": True,
        "entry": log_entry,
        "raw_feedback": sanitized,
    }

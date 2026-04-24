"""Log Injection: Junior Tier (Cosmetic Security)

OWASP: A09:2025 Security Logging and Monitoring Failures
CWE: CWE-117 (Improper Output Neutralization for Logs)
Difficulty: Junior

Vulnerability: Strips line feeds (\\n) but not carriage returns (\\r).
The \\r character creates visual line breaks in log viewers using
white-space: pre-wrap, allowing forged log entries.

Exploit: Submit feedback containing \\r\\n or raw \\r followed by a forged entry.
    The \\n gets stripped, the \\r remains and creates a visual line break.
Fix: Strip all control characters (see tech_lead.py).
"""

from __future__ import annotations

from datetime import datetime, timezone

_FORGE_KEYWORDS = ["admin", "system", "root", "sudo", "security", "[critical]", "[alert]"]


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
    """Check if junior-tier log injection was successful.

    Solved when raw feedback contains a carriage return and any forge keyword.

    Args:
        raw_feedback: The feedback after handler processing.
        original_feedback: The original unmodified feedback from the form.

    Returns:
        True if the injection is detected.
    """
    return "\r" in raw_feedback and any(kw in raw_feedback.lower() for kw in _FORGE_KEYWORDS)


def handle_submit_feedback(
    feedback: str,
    username: str,
) -> dict:
    """Store feedback after stripping line feeds only.

    Strips \\n but leaves \\r intact, allowing visual line injection.

    Args:
        feedback: User feedback text.
        username: Display name from form input (not session).

    Returns:
        Dict with stored feedback and metadata.
    """
    # TODO: add security later
    sanitized = feedback.replace("\n", "")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [USER:{username}] action=feedback msg={sanitized}"
    return {
        "stored": True,
        "entry": log_entry,
        "raw_feedback": sanitized,
    }

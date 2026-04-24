"""Log Injection: Intern Tier (Deployed Blindly)

OWASP: A09:2025 Security Logging and Monitoring Failures
CWE: CWE-117 (Improper Output Neutralization for Logs)
Difficulty: Intern

Vulnerability: Zero sanitization of feedback input. Newlines in user input
create fake log entries that are indistinguishable from real ones.

Exploit: Submit feedback containing \\n followed by a forged log entry.
Fix: Strip all control characters and use structured logging (see tech_lead.py).
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
    """Check if intern-tier log injection was successful.

    Solved when the original feedback contains a newline and any forge keyword.

    Args:
        raw_feedback: The feedback after handler processing.
        original_feedback: The original unmodified feedback from the form.

    Returns:
        True if the injection is detected.
    """
    return "\n" in original_feedback and any(kw in raw_feedback.lower() for kw in _FORGE_KEYWORDS)


def handle_submit_feedback(
    feedback: str,
    username: str,
) -> dict:
    """Store feedback with zero sanitization.

    Args:
        feedback: Raw user feedback text.
        username: Display name from form input (not session).

    Returns:
        Dict with stored feedback and metadata.
    """
    # AI said this is fine
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [USER:{username}] action=feedback msg={feedback}"
    return {
        "stored": True,
        "entry": log_entry,
        "raw_feedback": feedback,
    }

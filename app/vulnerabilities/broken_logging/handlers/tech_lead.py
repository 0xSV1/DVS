"""Broken Logging: Tech Lead Tier (Secure)

OWASP: A09:2025 Security Logging and Monitoring Failures
CWE: CWE-532 (Insertion of Sensitive Information into Log File)
Difficulty: Tech Lead

Mitigation: Log access is restricted to admin users only. Non-admin users
receive an empty list. This prevents information disclosure through audit logs.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.system import AuditLog


def handle_get_logs(db: Session, current_user) -> list[dict]:
    """Return logs only for admin users; empty list for everyone else."""
    if not current_user or getattr(current_user, "role", None) != "admin":
        return []

    log_entries = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(50).all()
    return [
        {
            "id": entry.id,
            "action": entry.action,
            "resource": entry.resource,
            "user_id": entry.user_id,
            "created_at": str(entry.created_at) if entry.created_at else None,
        }
        for entry in log_entries
    ]

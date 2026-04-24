"""Broken Logging: Senior Tier

OWASP: A09:2025 Security Logging and Monitoring Failures
CWE: CWE-532 (Insertion of Sensitive Information into Log File)
Difficulty: Senior

Vulnerability: Filtered logs omit the details field but still leak user IDs,
allowing enumeration of which users performed which actions.

Exploit: Correlate user_id values with other endpoints to map user activity.
Fix: Restrict log access to admins only (see tech_lead.py)
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.system import AuditLog


def handle_get_logs(db: Session, current_user) -> list[dict]:
    """Return filtered audit logs without the details field."""
    log_entries = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(50).all()
    return [
        {
            "id": entry.id,
            "action": entry.action,
            "resource": entry.resource,
            "user_id": entry.user_id,
        }
        for entry in log_entries
    ]

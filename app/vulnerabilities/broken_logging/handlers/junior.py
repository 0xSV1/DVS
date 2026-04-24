"""Broken Logging: Junior Tier

OWASP: A09:2025 Security Logging and Monitoring Failures
CWE: CWE-532 (Insertion of Sensitive Information into Log File)
Difficulty: Junior

Vulnerability: Identical to intern tier. All audit log fields are exposed
including sensitive details. No access control.

Exploit: Visit /challenges/logging to view all audit log entries with full detail.
Fix: Restrict log access to admins only (see tech_lead.py)
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.system import AuditLog


def handle_get_logs(db: Session, current_user) -> list[dict]:
    """Return raw audit logs with all fields including sensitive details."""
    log_entries = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(50).all()
    return [
        {
            "id": entry.id,
            "action": entry.action,
            "resource": entry.resource,
            "details": entry.details,
            "ip_address": entry.ip_address,
            "user_id": entry.user_id,
            "created_at": str(entry.created_at) if entry.created_at else None,
        }
        for entry in log_entries
    ]

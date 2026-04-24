from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.db.database import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    key = Column(String(64), nullable=False)  # Stored in plain text
    name = Column(String(50))
    permissions = Column(String(200))  # JSON string
    last_used = Column(DateTime)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(50))
    resource = Column(String(100))
    details = Column(Text)  # May contain secrets
    ip_address = Column(String(45))
    created_at = Column(DateTime, default=datetime.utcnow)


class UploadedFile(Base):
    __tablename__ = "uploaded_files"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    filename = Column(String(255))
    original_filename = Column(String(255))
    file_path = Column(String(500))
    mime_type = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)

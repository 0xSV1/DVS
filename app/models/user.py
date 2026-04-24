from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)  # Sequential for IDOR
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)  # MD5 at intern tier
    role = Column(String(20), default="user")  # user, admin, moderator
    is_active = Column(Boolean, default=True)
    avatar_url = Column(String(255), default="/static/img/default-avatar.png")
    bio = Column(Text, default="")
    api_key = Column(String(64), nullable=True)  # Plain-text API key
    created_at = Column(DateTime, default=datetime.utcnow)

    posts = relationship("BlogPost", back_populates="author")
    orders = relationship("Order", back_populates="user")
    chat_sessions = relationship("ChatSession", back_populates="user")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)  # No FK constraint, intentional
    token = Column(String(64), nullable=False)  # Predictable at low tiers
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)

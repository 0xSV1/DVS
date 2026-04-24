from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.db.database import Base


class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    price = Column(Float, nullable=False)
    image_url = Column(String(255))
    created_by = Column(Integer)  # No FK, mass assignment target
    is_published = Column(Boolean, default=True)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True)  # Sequential for IDOR
    user_id = Column(Integer, ForeignKey("users.id"))
    product_id = Column(Integer)
    quantity = Column(Integer, default=1)
    total_price = Column(Float)
    status = Column(String(20), default="pending")
    shipping_address = Column(Text)  # Contains PII
    credit_card_last4 = Column(String(4))  # Sensitive data
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="orders")

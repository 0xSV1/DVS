from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from app.db.database import Base


class Challenge(Base):
    __tablename__ = "challenges"

    id = Column(Integer, primary_key=True)
    key = Column(String(50), unique=True, nullable=False)  # Programmatic ID
    name = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)
    description = Column(Text)
    difficulty = Column(Integer)  # 1=Intern, 2=Junior, 3=Senior, 4=Tech Lead
    hint = Column(Text)
    cwe = Column(String(20))
    owasp_url = Column(String(255))
    min_difficulty = Column(String(20))  # Challenge visible at this tier or below
    tags = Column(String(200))  # Comma-separated tags
    mitre_atlas = Column(Text)  # JSON-encoded list of {id, name}
    forge = Column(Text)  # JSON-encoded {category, technique}
    solved = Column(Boolean, default=False)
    solved_at = Column(DateTime, nullable=True)

"""Shared test fixtures for Damn Vulnerable Startup.

Provides difficulty-aware test clients and database setup.
"""

from __future__ import annotations

from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.db.database import Base
from app.llm import factory as llm_factory
from app.llm.mock_provider import MockLLMProvider
from app.main import app

# Import all models so Base.metadata knows about their tables
from app.models import challenge, chat, content, product, system, user  # noqa: F401
from app.vulnerabilities.llm import router as llm_router

# In-memory SQLite for test isolation.
# StaticPool ensures all connections share the same in-memory database.
TEST_DATABASE_URL = "sqlite://"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def setup_db() -> Generator[None, None, None]:
    """Create all tables before each test, drop after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def _force_mock_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force mock LLM provider in all tests regardless of .env settings."""
    mock = MockLLMProvider()
    monkeypatch.setattr(llm_factory, "llm_provider", mock)
    monkeypatch.setattr(llm_router, "llm_provider", mock)


@pytest.fixture()
def db() -> Generator[Session, None, None]:
    """Provide a transactional database session for tests."""
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


def _override_db() -> Generator[Session, None, None]:
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    """Plain test client with default (intern) difficulty."""
    app.dependency_overrides[get_db] = _override_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def make_client():
    """Factory fixture: returns a test client with a specific difficulty set in the session.

    Usage:
        def test_something(make_client):
            client = make_client("intern")
            resp = client.get("/challenges/sqli")
    """
    clients = []

    def _make(difficulty: str = "intern") -> TestClient:
        app.dependency_overrides[get_db] = _override_db
        c = TestClient(app, raise_server_exceptions=True)
        c.__enter__()
        clients.append(c)
        # Set difficulty via the session middleware (signed cookie)
        c.post("/security", data={"difficulty": difficulty})
        return c

    yield _make

    for c in clients:
        c.__exit__(None, None, None)
    app.dependency_overrides.clear()


@pytest.fixture()
def seeded_client(make_client, db):
    """Client with seed data loaded. Returns (client, db_session) tuple."""
    from app.db.seed import seed_database

    seed_database(db)
    return make_client("intern"), db


def login_user(client: TestClient, username: str = "admin", password: str = "admin") -> TestClient:
    """Helper: log in a user and return the client with session cookie set."""
    client.post("/login", data={"username": username, "password": password})
    return client

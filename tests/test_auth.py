"""Tests for authentication routes.

Proves login works with seeded credentials, registration creates new users,
and SQLi auth bypass works at intern tier but not tech_lead.
"""

from __future__ import annotations

import hashlib

from app.models.challenge import Challenge
from app.models.user import User
from tests.conftest import TestSessionLocal


def _seed_users():
    """Insert test users for auth tests."""
    session = TestSessionLocal()
    admin = User(
        username="admin",
        email="admin@deploybro.io",
        password_hash=hashlib.md5(b"admin").hexdigest(),
        role="admin",
        bio="CTO",
    )
    regular = User(
        username="testuser",
        email="testuser@deploybro.io",
        password_hash=hashlib.md5(b"testpass").hexdigest(),
        role="user",
        bio="Test",
    )
    session.add(admin)
    session.add(regular)
    session.commit()
    session.close()


class TestAuthPages:
    """Page load tests."""

    def test_login_page_loads(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_register_page_loads(self, client):
        resp = client.get("/register")
        assert resp.status_code == 200


class TestLoginIntern:
    """Intern tier: MD5 password hashing, raw SQL (SQLi possible)."""

    def test_login_valid_credentials(self, make_client):
        """Login succeeds with correct username and password."""
        _seed_users()
        client = make_client("intern")
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        # Successful login at intern tier redirects to the IDOR profile page
        assert resp.status_code == 303
        assert "/challenges/idor/profile/" in resp.headers.get("location", "")

    def test_login_invalid_password(self, make_client):
        """Login fails with wrong password."""
        _seed_users()
        client = make_client("intern")
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "wrongpassword"},
        )
        assert resp.status_code == 200
        assert "Invalid" in resp.text

    def test_login_sqli_auth_bypass(self, make_client):
        """SQL injection bypasses authentication at intern tier."""
        _seed_users()
        client = make_client("intern")
        resp = client.post(
            "/login",
            data={"username": "admin' OR '1'='1' --", "password": "anything"},
            follow_redirects=False,
        )
        # SQLi should result in a successful login (redirect)
        assert resp.status_code == 303


class TestSqliLogin:
    """sqli_login challenge: auth bypass via SQL injection in the login form."""

    def test_sqli_login_solved_at_intern(self, make_client, db):
        """Intern tier: OR-based injection solves the sqli_login challenge."""
        _seed_users()
        db.add(Challenge(key="sqli_login", name="Bobby Tables Gets Hired", category="A05 Injection"))
        db.commit()
        client = make_client("intern")
        client.post(
            "/login",
            data={"username": "admin' OR '1'='1' --", "password": "anything"},
            follow_redirects=False,
        )
        challenge = db.query(Challenge).filter(Challenge.key == "sqli_login").first()
        assert challenge.solved

    def test_sqli_login_not_solved_at_tech_lead(self, make_client, db):
        """Tech lead tier: injection attempt does not solve the challenge."""
        _seed_users()
        db.add(Challenge(key="sqli_login", name="Bobby Tables Gets Hired", category="A05 Injection"))
        db.commit()
        client = make_client("tech_lead")
        client.post(
            "/login",
            data={"username": "admin' OR '1'='1' --", "password": "anything"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "sqli_login").first()
        assert not challenge.solved


class TestLoginTechLead:
    """Tech lead tier: parameterized queries, bcrypt verification."""

    def test_login_valid_credentials(self, make_client):
        """Login still works with correct credentials at tech_lead tier.

        Note: Seed data uses MD5 hashes and the tech_lead verify_password
        falls back to MD5 comparison for seed compatibility.
        """
        _seed_users()
        client = make_client("tech_lead")
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def test_sqli_blocked(self, make_client):
        """SQL injection does not bypass auth at tech_lead tier."""
        _seed_users()
        client = make_client("tech_lead")
        resp = client.post(
            "/login",
            data={"username": "admin' OR '1'='1' --", "password": "anything"},
        )
        assert resp.status_code == 200
        assert "Invalid" in resp.text


class TestRegister:
    """Registration tests (same behavior across tiers)."""

    def test_register_new_user(self, make_client):
        """Registration creates a new account."""
        client = make_client("intern")
        resp = client.post(
            "/register",
            data={
                "username": "newuser",
                "email": "newuser@test.io",
                "password": "newpass123",
            },
        )
        assert resp.status_code == 200
        assert "Account created" in resp.text

    def test_register_duplicate_username(self, make_client):
        """Registration rejects duplicate usernames."""
        _seed_users()
        client = make_client("intern")
        resp = client.post(
            "/register",
            data={
                "username": "admin",
                "email": "other@test.io",
                "password": "somepass",
            },
        )
        assert resp.status_code == 200
        assert "already taken" in resp.text

    def test_register_missing_fields(self, make_client):
        """Registration rejects incomplete submissions."""
        client = make_client("intern")
        resp = client.post(
            "/register",
            data={"username": "half", "email": "", "password": ""},
        )
        assert resp.status_code == 200
        assert "required" in resp.text.lower()

    def test_logout(self, make_client):
        """Logout clears the auth cookie and redirects."""
        _seed_users()
        client = make_client("intern")
        # Log in first
        client.post("/login", data={"username": "admin", "password": "admin"})
        resp = client.get("/logout", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers.get("location") == "/"


class TestAuthWeakPw:
    """auth_weak_pw challenge: logging in as admin with weak credentials."""

    def test_weak_password_solves(self, make_client, db):
        """Intern tier: logging in as admin with admin solves auth_weak_pw."""
        from app.db.seed import seed_users

        seed_users(db)
        db.add(Challenge(key="auth_weak_pw", name="password123 Is Fine, Right?", category="A07 Auth Failures"))
        db.commit()
        client = make_client("intern")
        client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
        challenge = db.query(Challenge).filter(Challenge.key == "auth_weak_pw").first()
        assert challenge.solved

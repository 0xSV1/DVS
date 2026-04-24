"""Tests for JWT authentication challenges.

Proves auth_jwt_none (algorithm bypass) and auth_jwt_weak (weak secret)
are solvable at intern/junior tiers and mitigated at tech_lead.
"""

from __future__ import annotations

import base64
import hashlib
import json

import jwt

from app.core.security import WEAK_JWT_SECRET
from app.models.challenge import Challenge
from app.models.user import User
from tests.conftest import TestSessionLocal


def _seed_users_and_challenges(db):
    """Insert test users and JWT challenge entries."""
    session = TestSessionLocal()
    session.add(
        User(
            username="admin",
            email="admin@deploybro.io",
            password_hash=hashlib.md5(b"admin").hexdigest(),
            role="admin",
            bio="CTO",
        )
    )
    session.add(
        User(
            username="testuser",
            email="test@deploybro.io",
            password_hash=hashlib.md5(b"testpass").hexdigest(),
            role="user",
            bio="Test",
        )
    )
    session.commit()
    session.close()
    db.add(Challenge(key="auth_jwt_none", name="Algorithm? None Required", category="A07 Auth Failures"))
    db.add(Challenge(key="auth_jwt_weak", name="Cracking the Culture Code", category="A07 Auth Failures"))
    db.commit()


def _forge_none_token(sub: str = "1", role: str = "admin") -> str:
    """Create a JWT with alg:none (unsigned) claiming admin role."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": sub, "role": role}).encode()).rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}."


def _forge_weak_secret_token(sub: str = "1", role: str = "admin") -> str:
    """Create a JWT signed with the known weak secret."""
    return jwt.encode({"sub": sub, "role": role}, WEAK_JWT_SECRET, algorithm="HS256")


class TestAuthJwtNone:
    """auth_jwt_none: forge a token with alg:none at intern tier."""

    def test_none_alg_accepted_at_intern(self, make_client, db):
        """Intern tier: alg:none token is accepted and solves the challenge."""
        _seed_users_and_challenges(db)
        client = make_client("intern")
        client.post("/login", data={"username": "testuser", "password": "testpass"})
        token = _forge_none_token(sub="999", role="admin")
        resp = client.post("/challenges/auth/verify", data={"token": token})
        assert resp.status_code == 200
        assert "Token accepted" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "auth_jwt_none").first()
        assert challenge.solved

    def test_none_alg_rejected_at_tech_lead(self, make_client, db):
        """Tech lead tier: alg:none token is rejected."""
        _seed_users_and_challenges(db)
        client = make_client("tech_lead")
        client.post("/login", data={"username": "admin", "password": "admin"})
        token = _forge_none_token(sub="999", role="admin")
        resp = client.post("/challenges/auth/verify", data={"token": token})
        assert resp.status_code == 200
        assert "rejected" in resp.text.lower() or "error" in resp.text.lower()
        challenge = db.query(Challenge).filter(Challenge.key == "auth_jwt_none").first()
        assert not challenge.solved


class TestAuthJwtNoneSeparation:
    """none-alg exploit must not contaminate the jwt_weak challenge."""

    def test_none_alg_does_not_solve_jwt_weak(self, make_client, db):
        """Forging with alg:none at intern tier solves jwt_none only; jwt_weak stays unsolved."""
        _seed_users_and_challenges(db)
        client = make_client("intern")
        client.post("/login", data={"username": "testuser", "password": "testpass"})
        token = _forge_none_token(sub="999", role="admin")
        client.post("/challenges/auth/verify", data={"token": token})
        none_challenge = db.query(Challenge).filter(Challenge.key == "auth_jwt_none").first()
        weak_challenge = db.query(Challenge).filter(Challenge.key == "auth_jwt_weak").first()
        assert none_challenge.solved
        assert not weak_challenge.solved


class TestAuthJwtSenior:
    """Senior tier: strong secret rejects both none-alg and weak-secret tokens."""

    def test_none_alg_rejected_at_senior(self, make_client, db):
        """Senior tier uses strong secret with algorithm enforcement; none-alg token is rejected."""
        _seed_users_and_challenges(db)
        client = make_client("senior")
        token = _forge_none_token(sub="999", role="admin")
        resp = client.post("/challenges/auth/verify", data={"token": token})
        assert resp.status_code == 200
        assert "rejected" in resp.text.lower() or "error" in resp.text.lower()
        none_challenge = db.query(Challenge).filter(Challenge.key == "auth_jwt_none").first()
        assert not none_challenge.solved

    def test_weak_secret_rejected_at_senior(self, make_client, db):
        """Senior tier uses strong secret; token signed with weak secret is rejected."""
        _seed_users_and_challenges(db)
        client = make_client("senior")
        token = _forge_weak_secret_token(sub="999", role="admin")
        resp = client.post("/challenges/auth/verify", data={"token": token})
        assert resp.status_code == 200
        assert "rejected" in resp.text.lower() or "error" in resp.text.lower()
        weak_challenge = db.query(Challenge).filter(Challenge.key == "auth_jwt_weak").first()
        assert not weak_challenge.solved


class TestAuthJwtWeak:
    """auth_jwt_weak: forge an admin token using the weak secret."""

    def test_weak_secret_accepted_at_junior(self, make_client, db):
        """Junior tier: token signed with weak secret is accepted."""
        _seed_users_and_challenges(db)
        client = make_client("junior")
        client.post("/login", data={"username": "testuser", "password": "testpass"})
        token = _forge_weak_secret_token(sub="999", role="admin")
        resp = client.post("/challenges/auth/verify", data={"token": token})
        assert resp.status_code == 200
        assert "Token accepted" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "auth_jwt_weak").first()
        assert challenge.solved

    def test_weak_secret_rejected_at_tech_lead(self, make_client, db):
        """Tech lead tier: token signed with weak secret is rejected (strong secret required)."""
        _seed_users_and_challenges(db)
        client = make_client("tech_lead")
        client.post("/login", data={"username": "admin", "password": "admin"})
        token = _forge_weak_secret_token(sub="999", role="admin")
        resp = client.post("/challenges/auth/verify", data={"token": token})
        assert resp.status_code == 200
        assert "rejected" in resp.text.lower() or "error" in resp.text.lower()
        challenge = db.query(Challenge).filter(Challenge.key == "auth_jwt_weak").first()
        assert not challenge.solved

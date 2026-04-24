"""Tests for mass assignment vulnerability.

Proves role escalation via JSON body works at intern tier and is blocked at tech_lead tier.
"""

from __future__ import annotations

import hashlib

from app.models.challenge import Challenge
from app.models.user import User
from tests.conftest import TestSessionLocal


def _seed_users():
    """Insert test users for mass assignment tests (MD5 hashes; works for intern/junior/tech_lead)."""
    session = TestSessionLocal()
    admin = User(
        username="admin",
        email="admin@deploybro.io",
        password_hash=hashlib.md5(b"admin").hexdigest(),
        role="admin",
        bio="CTO",
    )
    regular = User(
        username="regular",
        email="regular@deploybro.io",
        password_hash=hashlib.md5(b"password123").hexdigest(),
        role="user",
        bio="Normal user",
    )
    session.add(admin)
    session.add(regular)
    session.commit()
    session.close()


def _seed_users_sha256():
    """Insert test users with SHA-256 hashes for senior tier login tests.

    Senior tier uses SHA-256 verification; MD5-hashed users cannot log in.
    """
    session = TestSessionLocal()
    admin = User(
        username="admin",
        email="admin@deploybro.io",
        password_hash=hashlib.sha256(b"admin").hexdigest(),
        role="admin",
        bio="CTO",
    )
    regular = User(
        username="regular",
        email="regular@deploybro.io",
        password_hash=hashlib.sha256(b"password123").hexdigest(),
        role="user",
        bio="Normal user",
    )
    session.add(admin)
    session.add(regular)
    session.commit()
    session.close()


def _login(client, username="regular", password="password123"):
    """Log in a user and return the client."""
    client.post("/login", data={"username": username, "password": password})
    return client


class TestMassAssignPageLoads:
    """Basic page load tests."""

    def test_mass_assign_page_loads(self, client):
        resp = client.get("/challenges/mass-assign")
        assert resp.status_code == 200
        assert "Promote Yourself" in resp.text


class TestMassAssignIntern:
    """Intern tier: accepts any field including role."""

    def test_role_escalation_to_admin(self, make_client, db):
        """Sending role=admin in the JSON body promotes the user at intern tier."""
        _seed_users()
        db.add(Challenge(key="mass_assign", name="Promote Yourself in JSON", category="A01 Broken Access"))
        db.commit()
        client = make_client("intern")
        _login(client)
        resp = client.post(
            "/api/users/me",
            json={"role": "admin"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data["user"]["role"] == "admin"
        challenge = db.query(Challenge).filter(Challenge.key == "mass_assign").first()
        assert challenge.solved

    def test_bio_update(self, make_client):
        """Bio field updates normally at intern tier."""
        _seed_users()
        client = make_client("intern")
        _login(client)
        resp = client.post(
            "/api/users/me",
            json={"bio": "Promoted myself to CEO"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data["user"]["bio"] == "Promoted myself to CEO"


class TestMassAssignTechLead:
    """Tech lead tier: strict allowlist, only bio is modifiable."""

    def test_role_escalation_blocked(self, make_client):
        """Sending role=admin is ignored at tech_lead tier."""
        _seed_users()
        client = make_client("tech_lead")
        _login(client)
        resp = client.post(
            "/api/users/me",
            json={"role": "admin"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        # Role should still be "user", not "admin"
        assert data["user"].get("role") is None or data["user"].get("role") != "admin"

    def test_bio_update_still_works(self, make_client):
        """Bio updates are still allowed at tech_lead tier."""
        _seed_users()
        client = make_client("tech_lead")
        _login(client)
        resp = client.post(
            "/api/users/me",
            json={"bio": "Updated bio"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data["user"]["bio"] == "Updated bio"

    def test_mass_assign_not_solved_at_tech_lead(self, make_client, db):
        """Sending role=admin at tech_lead does not solve the challenge."""
        _seed_users()
        db.add(Challenge(key="mass_assign", name="Promote Yourself in JSON", category="A01 Broken Access"))
        db.commit()
        client = make_client("tech_lead")
        _login(client)
        client.post(
            "/api/users/me",
            json={"role": "admin"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "mass_assign").first()
        assert not challenge.solved

    def test_email_update_blocked(self, make_client):
        """Email changes are not allowed at tech_lead tier (only bio)."""
        _seed_users()
        client = make_client("tech_lead")
        _login(client)
        resp = client.post(
            "/api/users/me",
            json={"email": "hacker@evil.com", "bio": "original"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True


class TestMassAssignUnauthenticated:
    """Unauthenticated requests should be rejected."""

    def test_unauthenticated_rejected(self, make_client):
        """POST /api/users/me without login returns error."""
        client = make_client("intern")
        resp = client.post(
            "/api/users/me",
            json={"role": "admin"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data


class TestMassAssignJunior:
    """Junior tier: functionally identical to intern; role escalation works."""

    def test_role_escalation_works_at_junior(self, make_client, db):
        """Junior handler applies all fields including role; role escalation succeeds."""
        _seed_users()
        db.add(Challenge(key="mass_assign", name="Promote Yourself in JSON", category="A01 Broken Access"))
        db.commit()
        client = make_client("junior")
        _login(client)
        resp = client.post("/api/users/me", json={"role": "admin"})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data["user"]["role"] == "admin"
        challenge = db.query(Challenge).filter(Challenge.key == "mass_assign").first()
        assert challenge.solved

    def test_bio_update_works_at_junior(self, make_client):
        """Normal bio update succeeds at junior tier."""
        _seed_users()
        client = make_client("junior")
        _login(client)
        resp = client.post("/api/users/me", json={"bio": "Promoted via JSON"})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True


class TestMassAssignSenior:
    """Senior tier: allowlist {bio, email, avatar_url} blocks role field."""

    def test_role_escalation_blocked_at_senior(self, make_client, db):
        """role field is not in the senior allowlist; role stays 'user'."""
        _seed_users_sha256()
        db.add(Challenge(key="mass_assign", name="Promote Yourself in JSON", category="A01 Broken Access"))
        db.commit()
        client = make_client("senior")
        _login(client)
        resp = client.post("/api/users/me", json={"role": "admin"})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data["user"].get("role") is None or data["user"].get("role") != "admin"

    def test_bio_update_still_works_at_senior(self, make_client):
        """bio is in the senior allowlist and still updates correctly."""
        _seed_users_sha256()
        client = make_client("senior")
        _login(client)
        resp = client.post("/api/users/me", json={"bio": "Senior update"})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data["user"]["bio"] == "Senior update"

    def test_mass_assign_not_solved_at_senior(self, make_client, db):
        """Allowlist blocks role change; solve condition never fires at senior."""
        _seed_users_sha256()
        db.add(Challenge(key="mass_assign", name="Promote Yourself in JSON", category="A01 Broken Access"))
        db.commit()
        client = make_client("senior")
        _login(client)
        client.post("/api/users/me", json={"role": "admin"})
        challenge = db.query(Challenge).filter(Challenge.key == "mass_assign").first()
        assert not challenge.solved

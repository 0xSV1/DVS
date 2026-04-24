"""Tests for admin panel access control across tiers."""

from __future__ import annotations

import hashlib

from app.db.seed import seed_users
from app.models.user import User
from tests.conftest import TestSessionLocal, login_user


def _seed_users_sha256():
    """Insert seeded users with SHA-256 password hashes for senior-tier login tests."""
    session = TestSessionLocal()
    session.add(
        User(
            username="admin",
            email="admin@deploybro.io",
            password_hash=hashlib.sha256(b"admin").hexdigest(),
            role="admin",
            bio="CTO",
        )
    )
    session.add(
        User(
            username="intern_jenny",
            email="jenny@deploybro.io",
            password_hash=hashlib.sha256(b"jenny2026").hexdigest(),
            role="user",
            bio="Intern",
        )
    )
    session.commit()
    session.close()


class TestAdminIntern:
    def test_admin_accessible_without_login(self, make_client, db):
        """Admin panel accessible at intern tier without any authentication."""
        seed_users(db)
        client = make_client("intern")
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "User Management" in resp.text

    def test_admin_shows_users(self, make_client, db):
        """Admin panel shows user data at intern tier."""
        seed_users(db)
        client = make_client("intern")
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "admin" in resp.text
        assert "chad_shipper" in resp.text


class TestAdminJunior:
    """Junior tier: no access control; any visitor reaches the panel."""

    def test_admin_accessible_without_login_at_junior(self, make_client, db):
        """Admin panel is accessible without authentication at junior tier."""
        seed_users(db)
        client = make_client("junior")
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "User Management" in resp.text

    def test_idor_admin_solves_at_junior(self, make_client, db):
        """Unauthenticated access to admin at junior tier solves idor_admin."""
        from app.models.challenge import Challenge

        seed_users(db)
        db.add(Challenge(key="idor_admin", name="Promotion Without the Standup", category="A01 Broken Access"))
        db.commit()
        client = make_client("junior")
        client.get("/admin")
        challenge = db.query(Challenge).filter(Challenge.key == "idor_admin").first()
        assert challenge.solved


class TestAdminSenior:
    """Senior tier: auth required but no role check; any logged-in non-admin reaches the panel.

    Senior tier uses SHA-256 password hashes, so these tests seed users with SHA-256.
    """

    def test_unauthenticated_blocked_at_senior(self, make_client):
        """Senior tier requires authentication; unauthenticated request is denied."""
        client = make_client("senior")
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "Access Denied" in resp.text

    def test_non_admin_can_access_admin_at_senior(self, make_client):
        """Senior tier checks auth but not role; non-admin reaches the panel."""
        _seed_users_sha256()
        client = make_client("senior")
        login_user(client, "intern_jenny", "jenny2026")
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "User Management" in resp.text

    def test_idor_admin_solves_as_non_admin_at_senior(self, make_client, db):
        """Non-admin reaching admin panel at senior tier solves idor_admin."""
        from app.models.challenge import Challenge

        _seed_users_sha256()
        db.add(Challenge(key="idor_admin", name="Promotion Without the Standup", category="A01 Broken Access"))
        db.commit()
        client = make_client("senior")
        login_user(client, "intern_jenny", "jenny2026")
        client.get("/admin")
        challenge = db.query(Challenge).filter(Challenge.key == "idor_admin").first()
        assert challenge.solved

    def test_idor_admin_does_not_solve_when_admin_logs_in(self, make_client, db):
        """At senior tier, admin accessing admin panel does NOT solve idor_admin (no bypass required)."""
        from app.models.challenge import Challenge

        _seed_users_sha256()
        db.add(Challenge(key="idor_admin", name="Promotion Without the Standup", category="A01 Broken Access"))
        db.commit()
        client = make_client("senior")
        login_user(client, "admin", "admin")
        client.get("/admin")
        challenge = db.query(Challenge).filter(Challenge.key == "idor_admin").first()
        assert not challenge.solved


class TestAdminTechLead:
    def test_admin_blocked_without_login(self, make_client, db):
        """Admin panel blocked at tech_lead tier when not logged in."""
        seed_users(db)
        client = make_client("tech_lead")
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "Access Denied" in resp.text

    def test_admin_blocked_for_regular_user(self, make_client, db):
        """Admin panel blocked for non-admin users at tech_lead tier."""
        seed_users(db)
        client = make_client("tech_lead")
        login_user(client, "intern_jenny", "jenny2026")
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "Access Denied" in resp.text

    def test_admin_accessible_for_admin(self, make_client, db):
        """Admin panel accessible for admin user at tech_lead tier."""
        seed_users(db)
        client = make_client("tech_lead")
        login_user(client, "admin", "admin")
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "User Management" in resp.text

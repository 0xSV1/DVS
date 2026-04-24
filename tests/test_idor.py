"""Tests for IDOR vulnerability module.

Proves unauthorized profile access works at intern tier and is restricted at tech_lead tier.
"""

from __future__ import annotations

import hashlib

from app.models.challenge import Challenge
from app.models.product import Order
from app.models.user import User
from tests.conftest import TestSessionLocal


def _seed_users():
    """Insert test users into the database."""
    session = TestSessionLocal()
    admin = User(
        username="admin",
        email="admin@deploybro.io",
        password_hash=hashlib.md5(b"admin").hexdigest(),
        role="admin",
        bio="CTO",
        api_key="dbr_live_ADMIN_KEY_2026_do_not_share",
    )
    regular = User(
        username="regular_user",
        email="regular@deploybro.io",
        password_hash=hashlib.md5(b"password123").hexdigest(),
        role="user",
        bio="Just a user",
    )
    session.add(admin)
    session.add(regular)
    session.commit()
    admin_id = admin.id
    regular_id = regular.id
    session.close()
    return admin_id, regular_id


class TestIdorPageLoads:
    """Basic page load tests."""

    def test_idor_page_loads(self, client):
        resp = client.get("/challenges/idor")
        assert resp.status_code == 200
        assert "Other People" in resp.text


class TestIdorIntern:
    """Intern tier: no access control, leaks sensitive fields."""

    def test_view_other_user_profile_no_auth(self, make_client):
        """Unauthenticated user can view any profile including sensitive fields."""
        admin_id, regular_id = _seed_users()
        client = make_client("intern")
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        # Intern tier leaks password_hash and api_key
        assert "password_hash" in resp.text or "api_key" in resp.text or "dbr_live" in resp.text

    def test_view_profile_returns_data(self, make_client):
        """Profile endpoint returns user data at intern tier."""
        admin_id, _ = _seed_users()
        client = make_client("intern")
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        assert "admin" in resp.text

    def test_idor_profile_solves(self, make_client, db):
        """Authenticated user viewing another user's profile solves idor_profile."""
        admin_id, regular_id = _seed_users()
        db.add(Challenge(key="idor_profile", name="Other People's Deployments", category="A01 Broken Access"))
        db.commit()
        client = make_client("intern")
        # Log in as regular_user
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "idor_profile").first()
        assert challenge.solved


class TestIdorTechLead:
    """Tech lead tier: strict ownership check, no sensitive field leakage."""

    def test_unauthenticated_gets_error(self, make_client):
        """Unauthenticated request returns auth required message."""
        admin_id, _ = _seed_users()
        client = make_client("tech_lead")
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        # Tech lead handler returns error dict when no current_user
        assert "Authentication required" in resp.text or "error" in resp.text

    def test_authenticated_user_sees_limited_other_profile(self, make_client):
        """Authenticated non-admin user sees only public fields of another user."""
        admin_id, regular_id = _seed_users()
        client = make_client("tech_lead")
        # Log in as regular_user
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        # Should NOT contain sensitive fields
        assert "dbr_live" not in resp.text
        assert "password_hash" not in resp.text

    def test_admin_viewing_other_profile_does_not_solve_idor(self, make_client, db):
        """Admin access is authorized at tech lead tier and should not solve IDOR."""
        admin_id, regular_id = _seed_users()
        db.add(Challenge(key="idor_profile", name="Other People's OKRs", category="A01 Broken Access"))
        db.commit()
        client = make_client("tech_lead")
        client.post("/login", data={"username": "admin", "password": "admin"})
        resp = client.get(f"/challenges/idor/profile/{regular_id}")
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "idor_profile").first()
        assert not challenge.solved


def _seed_orders(db):
    """Seed users and orders for IDOR order tests."""
    admin_id, regular_id = _seed_users()
    session = TestSessionLocal()
    order = Order(
        user_id=admin_id,
        product_id=1,
        quantity=1,
        total_price=99.99,
        status="shipped",
        shipping_address="123 Deploy St",
        credit_card_last4="4242",
    )
    session.add(order)
    session.commit()
    order_id = order.id
    session.close()
    return admin_id, regular_id, order_id


class TestIdorOrder:
    """idor_order: authenticated user views another user's order by ID."""

    def test_intern_order_idor_solves(self, make_client, db):
        """Intern tier: logged-in user viewing another user's order solves the challenge."""
        admin_id, regular_id, order_id = _seed_orders(db)
        db.add(Challenge(key="idor_order", name="Peek at the Cap Table", category="A01 Broken Access"))
        db.commit()
        client = make_client("intern")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get(f"/challenges/idor/order/{order_id}")
        assert resp.status_code == 200
        assert "4242" in resp.text or "shipped" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "idor_order").first()
        assert challenge.solved

    def test_tech_lead_order_idor_blocked(self, make_client, db):
        """Tech lead tier: non-owner is denied access to the order."""
        admin_id, regular_id, order_id = _seed_orders(db)
        db.add(Challenge(key="idor_order", name="Peek at the Cap Table", category="A01 Broken Access"))
        db.commit()
        client = make_client("tech_lead")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get(f"/challenges/idor/order/{order_id}")
        assert resp.status_code == 200
        assert "Access denied" in resp.text or "error" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "idor_order").first()
        assert not challenge.solved


class TestIdorAdmin:
    """idor_admin: non-admin user accessing the admin panel."""

    def test_intern_non_admin_accesses_admin(self, make_client, db):
        """Intern tier: regular user reaches /admin and solves the challenge."""
        _seed_users()
        db.add(Challenge(key="idor_admin", name="Promotion Without the Standup", category="A01 Broken Access"))
        db.commit()
        client = make_client("intern")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "access_denied" not in resp.text.lower() or "regular_user" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "idor_admin").first()
        assert challenge.solved

    def test_tech_lead_non_admin_blocked(self, make_client, db):
        """Tech lead tier: non-admin is blocked from /admin."""
        _seed_users()
        db.add(Challenge(key="idor_admin", name="Promotion Without the Standup", category="A01 Broken Access"))
        db.commit()
        client = make_client("tech_lead")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get("/admin")
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "idor_admin").first()
        assert not challenge.solved


class TestIdorJunior:
    """Junior tier: requires authentication but no ownership check on profiles."""

    def test_unauthenticated_blocked_at_junior(self, make_client):
        """Junior tier requires a logged-in session; unauthenticated gets an error."""
        admin_id, _ = _seed_users()
        client = make_client("junior")
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        # Route returns an HTML template; error message rendered in the page
        assert "Authentication required" in resp.text

    def test_authenticated_user_views_other_profile(self, make_client):
        """Logged-in user can view another user's profile at junior tier."""
        admin_id, regular_id = _seed_users()
        client = make_client("junior")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        # Profile rendered successfully; no auth/access error in the HTML
        assert "Authentication required" not in resp.text

    def test_password_hash_not_exposed_at_junior(self, make_client):
        """Junior tier strips password_hash from profile response."""
        admin_id, _ = _seed_users()
        client = make_client("junior")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        assert "password_hash" not in resp.text

    def test_api_key_still_exposed_at_junior(self, make_client):
        """Junior tier exposes api_key (strips password_hash only)."""
        admin_id, _ = _seed_users()
        client = make_client("junior")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        assert "dbr_live" in resp.text or "api_key" in resp.text

    def test_idor_profile_solves_at_junior(self, make_client, db):
        """Authenticated user viewing another user's profile solves idor_profile at junior."""
        admin_id, _ = _seed_users()
        db.add(Challenge(key="idor_profile", name="Other People's OKRs", category="A01 Broken Access"))
        db.commit()
        client = make_client("junior")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        client.get(f"/challenges/idor/profile/{admin_id}")
        challenge = db.query(Challenge).filter(Challenge.key == "idor_profile").first()
        assert challenge.solved


class TestIdorSenior:
    """Senior tier: ownership check enforced; api_key removed from response."""

    def test_ownership_check_blocks_non_admin(self, make_client):
        """Non-admin user cannot view another user's profile at senior tier."""
        admin_id, _ = _seed_users()
        client = make_client("senior")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        # Route renders an HTML template with error message; check text directly
        assert "Access denied" in resp.text or "Authentication required" in resp.text

    def test_api_key_removed_at_senior(self, make_client):
        """Even an accessible profile at senior tier omits api_key."""
        admin_id, _ = _seed_users()
        client = make_client("senior")
        # Admin can view their own profile
        client.post("/login", data={"username": "admin", "password": "admin"})
        resp = client.get(f"/challenges/idor/profile/{admin_id}")
        assert resp.status_code == 200
        assert "dbr_live" not in resp.text

    def test_idor_profile_not_solved_at_senior(self, make_client, db):
        """Non-admin blocked by ownership check; idor_profile not solved."""
        admin_id, _ = _seed_users()
        db.add(Challenge(key="idor_profile", name="Other People's OKRs", category="A01 Broken Access"))
        db.commit()
        client = make_client("senior")
        client.post("/login", data={"username": "regular_user", "password": "password123"})
        client.get(f"/challenges/idor/profile/{admin_id}")
        challenge = db.query(Challenge).filter(Challenge.key == "idor_profile").first()
        assert not challenge.solved

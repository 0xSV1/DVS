"""Tests for cryptographic failures vulnerability module.

Proves MD5 hash exposure at intern tier and verify crack endpoint.
"""

from __future__ import annotations

import hashlib

from app.db.seed import seed_users
from app.models.challenge import Challenge


class TestCryptoPageLoads:
    def test_page_loads(self, client):
        resp = client.get("/challenges/crypto")
        assert resp.status_code == 200
        assert "Hashing? Trust Me Bro" in resp.text


class TestCryptoIntern:
    def test_hashes_exposed(self, make_client, db):
        """Intern tier exposes password hashes."""
        seed_users(db)
        client = make_client("intern")
        resp = client.get("/challenges/crypto")
        assert resp.status_code == 200
        # MD5 of "admin" (admin's seed password) should be visible
        admin_md5 = hashlib.md5(b"admin").hexdigest()
        assert admin_md5 in resp.text

    def test_crack_correct_password(self, make_client, db):
        """Cracking a password hash succeeds."""
        seed_users(db)
        db.add(Challenge(key="crypto_md5", name="Hashing? Trust Me Bro", category="A04 Crypto Failures"))
        db.commit()
        client = make_client("intern")
        resp = client.post(
            "/challenges/crypto/crack",
            data={"username": "admin", "password": "admin"},
        )
        assert resp.status_code == 200
        assert "Correct" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "crypto_md5").first()
        assert challenge.solved

    def test_crack_wrong_password(self, make_client, db):
        """Wrong password is rejected."""
        seed_users(db)
        client = make_client("intern")
        resp = client.post(
            "/challenges/crypto/crack",
            data={"username": "admin", "password": "wrongpassword"},
        )
        assert resp.status_code == 200
        assert "Incorrect" in resp.text


class TestCryptoTechLead:
    def test_hashes_not_exposed(self, make_client, db):
        """Tech lead tier does not expose password hashes."""
        seed_users(db)
        client = make_client("tech_lead")
        resp = client.get("/challenges/crypto")
        assert resp.status_code == 200
        admin_md5 = hashlib.md5(b"admin").hexdigest()
        assert admin_md5 not in resp.text

    def test_crypto_md5_not_solved_at_tech_lead(self, make_client, db):
        """Hash crack attempt at tech_lead does not solve the challenge."""
        seed_users(db)
        db.add(Challenge(key="crypto_md5", name="Hashing? Trust Me Bro", category="A04 Crypto Failures"))
        db.commit()
        client = make_client("tech_lead")
        client.post(
            "/challenges/crypto/crack",
            data={"username": "admin", "password": "admin"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "crypto_md5").first()
        assert not challenge.solved


class TestCryptoJunior:
    """Junior tier: same MD5 exposure as intern; crack endpoint works identically."""

    def test_hashes_exposed_at_junior(self, make_client, db):
        """Junior tier exposes MD5 password hashes (same as intern)."""
        seed_users(db)
        client = make_client("junior")
        resp = client.get("/challenges/crypto")
        assert resp.status_code == 200
        admin_md5 = hashlib.md5(b"admin").hexdigest()
        assert admin_md5 in resp.text

    def test_crack_works_at_junior(self, make_client, db):
        """Cracking MD5 hash with correct password succeeds at junior tier."""
        seed_users(db)
        db.add(Challenge(key="crypto_md5", name="Hashing? Trust Me Bro", category="A04 Crypto Failures"))
        db.commit()
        client = make_client("junior")
        resp = client.post(
            "/challenges/crypto/crack",
            data={"username": "admin", "password": "admin"},
        )
        assert resp.status_code == 200
        assert "Correct" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "crypto_md5").first()
        assert challenge.solved


class TestCryptoSenior:
    """Senior tier: algorithm label hidden ('Unknown'); crack still works via MD5 comparison."""

    def test_algorithm_label_hidden_at_senior(self, make_client, db):
        """Senior tier does not reveal the algorithm name in the hash list."""
        seed_users(db)
        client = make_client("senior")
        resp = client.get("/challenges/crypto")
        assert resp.status_code == 200
        assert "MD5" not in resp.text
        assert "Unknown" in resp.text or "algorithm" not in resp.text.lower()

    def test_crack_still_works_at_senior(self, make_client, db):
        """Crack endpoint uses MD5 comparison regardless of the label hiding."""
        seed_users(db)
        db.add(Challenge(key="crypto_md5", name="Hashing? Trust Me Bro", category="A04 Crypto Failures"))
        db.commit()
        client = make_client("senior")
        resp = client.post(
            "/challenges/crypto/crack",
            data={"username": "admin", "password": "admin"},
        )
        assert resp.status_code == 200
        assert "Correct" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "crypto_md5").first()
        assert challenge.solved

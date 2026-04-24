"""Tests for the hardcoded secrets (crypto_hardcoded_secret) challenge.

Proves key exposure at intern/junior tiers, decoy rejection at junior,
and no exposure at senior/tech_lead.
"""

from __future__ import annotations

import base64

from app.models.challenge import Challenge


def _seed_challenge(db):
    """Insert the crypto_hardcoded_secret challenge into the test DB."""
    ch = Challenge(
        key="crypto_hardcoded_secret",
        name="API Keys are Environment Variables, Right?",
        category="A04 Crypto Failures",
        difficulty=2,
        cwe="CWE-798",
        description="Test",
        hint="Test",
        owasp_url="",
        min_difficulty="junior",
        tags="crypto",
    )
    db.add(ch)
    db.commit()


class TestCryptoSecretsPageLoads:
    def test_page_loads(self, client):
        resp = client.get("/challenges/crypto/secrets")
        assert resp.status_code == 200
        assert "API Keys are Environment Variables" in resp.text


class TestCryptoSecretsIntern:
    def test_key_visible_in_source(self, make_client):
        """Intern tier: key is in plaintext in the page source."""
        client = make_client("intern")
        resp = client.get("/challenges/crypto/secrets")
        assert resp.status_code == 200
        assert "dbr_partner_S3cr3TK3Y_2026" in resp.text

    def test_submit_correct_key(self, make_client, db):
        """Intern tier: submitting the plaintext key succeeds."""
        _seed_challenge(db)
        client = make_client("intern")
        resp = client.post(
            "/challenges/crypto/secrets/verify",
            data={"api_key": "dbr_partner_S3cr3TK3Y_2026"},
        )
        assert resp.status_code == 200
        assert "Correct" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "crypto_hardcoded_secret").first()
        assert challenge.solved


class TestCryptoSecretsJunior:
    def test_decoy_rejected(self, make_client, db):
        """Junior tier: submitting the decoy key is rejected with a hint."""
        _seed_challenge(db)
        client = make_client("junior")
        resp = client.post(
            "/challenges/crypto/secrets/verify",
            data={"api_key": "dbr_test_NOT_A_REAL_KEY"},
        )
        assert resp.status_code == 200
        assert "decoy" in resp.text.lower()

    def test_base64_fragments_present(self, make_client):
        """Junior tier: base64 fragments are in page source."""
        client = make_client("junior")
        resp = client.get("/challenges/crypto/secrets")
        # The full base64 of the key should be split across _cfg_a, _cfg_b, _cfg_c
        full_b64 = base64.b64encode(b"dbr_partner_S3cr3TK3Y_2026").decode()
        frag_len = len(full_b64) // 3
        assert full_b64[:frag_len] in resp.text
        assert full_b64[frag_len : frag_len * 2] in resp.text
        assert full_b64[frag_len * 2 :] in resp.text

    def test_decoded_fragments_solve(self, make_client, db):
        """Junior tier: concatenating and decoding fragments yields the real key."""
        _seed_challenge(db)
        client = make_client("junior")
        resp = client.post(
            "/challenges/crypto/secrets/verify",
            data={"api_key": "dbr_partner_S3cr3TK3Y_2026"},
        )
        assert resp.status_code == 200
        assert "Correct" in resp.text

    def test_plaintext_key_not_in_source(self, make_client):
        """Junior tier: the plaintext key is not directly in page source."""
        client = make_client("junior")
        resp = client.get("/challenges/crypto/secrets")
        # The key should only appear base64-encoded, not as plaintext
        # (it is not in an HTML comment or JS variable directly)
        assert "var DEPLOYBRO_API_KEY" not in resp.text
        assert "<!-- API Key:" not in resp.text


class TestCryptoSecretsSenior:
    def test_no_key_in_source(self, make_client):
        """Senior tier: no key material in page source."""
        client = make_client("senior")
        resp = client.get("/challenges/crypto/secrets")
        assert "dbr_partner_S3cr3TK3Y_2026" not in resp.text
        assert "_cfg_a" not in resp.text

    def test_masked_key_shown(self, make_client):
        """Senior tier: masked key is displayed."""
        client = make_client("senior")
        resp = client.get("/challenges/crypto/secrets")
        assert "dbr_" in resp.text
        assert "****" in resp.text


class TestCryptoSecretsTechLead:
    def test_no_key_material(self, make_client):
        """Tech lead tier: no key material at all."""
        client = make_client("tech_lead")
        resp = client.get("/challenges/crypto/secrets")
        assert "dbr_partner" not in resp.text
        assert "secrets vault" in resp.text.lower()

    def test_verify_always_rejects(self, make_client, db):
        """Tech lead tier: all key submissions are rejected."""
        _seed_challenge(db)
        client = make_client("tech_lead")
        resp = client.post(
            "/challenges/crypto/secrets/verify",
            data={"api_key": "dbr_partner_S3cr3TK3Y_2026"},
        )
        assert resp.status_code == 200
        assert "Correct" not in resp.text

    def test_crypto_hardcoded_secret_not_solved_at_tech_lead(self, make_client, db):
        """Submitting the real key at tech_lead does not solve the challenge."""
        _seed_challenge(db)
        client = make_client("tech_lead")
        client.post(
            "/challenges/crypto/secrets/verify",
            data={"api_key": "dbr_partner_S3cr3TK3Y_2026"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "crypto_hardcoded_secret").first()
        assert not challenge.solved

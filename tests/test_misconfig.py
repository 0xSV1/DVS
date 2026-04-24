"""Tests for security misconfiguration vulnerability module.

Proves debug info leaks at intern tier and is blocked at tech_lead.
"""

from __future__ import annotations

from app.models.challenge import Challenge


class TestMisconfigPageLoads:
    def test_page_loads(self, client):
        resp = client.get("/challenges/misconfig")
        assert resp.status_code == 200


class TestMisconfigIntern:
    def test_debug_exposes_env(self, make_client):
        """Debug endpoint leaks environment variables at intern tier."""
        client = make_client("intern")
        resp = client.get("/challenges/misconfig/debug")
        assert resp.status_code == 200
        data = resp.json()
        assert "secret_key" in data
        assert "jwt_secret" in data

    def test_env_file_accessible(self, make_client):
        """The .env file is accessible at intern tier."""
        client = make_client("intern")
        resp = client.get("/challenges/misconfig/.env")
        assert resp.status_code == 200
        assert "SECRET_KEY" in resp.text
        assert "STRIPE_KEY" in resp.text

    def test_cors_wide_open(self, make_client):
        """CORS is wildcard at intern tier."""
        client = make_client("intern")
        resp = client.get("/challenges/misconfig/cors-test")
        assert resp.status_code == 200
        assert resp.headers.get("Access-Control-Allow-Origin") == "*"

    def test_debug_solves(self, make_client, db):
        """Intern tier: accessing debug endpoint solves misconfig_debug."""
        db.add(Challenge(key="misconfig_debug", name="We'll Turn It Off Before Launch", category="A02 Misconfig"))
        db.commit()
        client = make_client("intern")
        client.get("/challenges/misconfig/debug")
        challenge = db.query(Challenge).filter(Challenge.key == "misconfig_debug").first()
        assert challenge.solved

    def test_cors_solves(self, make_client, db):
        """Intern tier: accessing CORS endpoint solves misconfig_cors."""
        db.add(Challenge(key="misconfig_cors", name="Access-Control-Allow-Yolo", category="A02 Misconfig"))
        db.commit()
        client = make_client("intern")
        client.get("/challenges/misconfig/cors-test")
        challenge = db.query(Challenge).filter(Challenge.key == "misconfig_cors").first()
        assert challenge.solved


class TestMisconfigTechLead:
    def test_debug_blocked(self, make_client):
        """Debug endpoint returns 404 at tech_lead tier."""
        client = make_client("tech_lead")
        resp = client.get("/challenges/misconfig/debug")
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data or "Not found" in str(data)
        assert "secret_key" not in data

    def test_env_file_blocked(self, make_client):
        """The .env file returns 404 at tech_lead tier."""
        client = make_client("tech_lead")
        resp = client.get("/challenges/misconfig/.env")
        assert resp.status_code == 404

    def test_cors_restricted(self, make_client):
        """No CORS headers at tech_lead tier."""
        client = make_client("tech_lead")
        resp = client.get("/challenges/misconfig/cors-test")
        assert resp.status_code == 200
        assert "Access-Control-Allow-Origin" not in resp.headers

    def test_misconfig_debug_not_solved_at_tech_lead(self, make_client, db):
        """Debug endpoint at tech_lead does not solve the challenge."""
        db.add(Challenge(key="misconfig_debug", name="We'll Turn It Off Before Launch", category="A02 Misconfig"))
        db.commit()
        client = make_client("tech_lead")
        client.get("/challenges/misconfig/debug")
        challenge = db.query(Challenge).filter(Challenge.key == "misconfig_debug").first()
        assert not challenge.solved

    def test_misconfig_cors_not_solved_at_tech_lead(self, make_client, db):
        """CORS endpoint at tech_lead does not solve the challenge."""
        db.add(Challenge(key="misconfig_cors", name="Access-Control-Allow-Yolo", category="A02 Misconfig"))
        db.commit()
        client = make_client("tech_lead")
        client.get("/challenges/misconfig/cors-test")
        challenge = db.query(Challenge).filter(Challenge.key == "misconfig_cors").first()
        assert not challenge.solved


class TestInfoDisclosure:
    """info_disclosure challenge: .env file exposure triggers solve."""

    def test_env_access_solves_at_intern(self, make_client, db):
        """Intern tier: accessing .env solves the info_disclosure challenge."""
        db.add(Challenge(key="info_disclosure", name="Environment File Exposure", category="A02 Misconfig"))
        db.commit()
        client = make_client("intern")
        client.get("/challenges/misconfig/.env")
        challenge = db.query(Challenge).filter(Challenge.key == "info_disclosure").first()
        assert challenge.solved

    def test_env_access_blocked_at_tech_lead(self, make_client, db):
        """Tech lead tier: .env returns 404, challenge not solved."""
        db.add(Challenge(key="info_disclosure", name="Environment File Exposure", category="A02 Misconfig"))
        db.commit()
        client = make_client("tech_lead")
        client.get("/challenges/misconfig/.env")
        challenge = db.query(Challenge).filter(Challenge.key == "info_disclosure").first()
        assert not challenge.solved


class TestMisconfigJunior:
    """Junior tier: debug/env same as intern; CORS reflects Origin instead of wildcard."""

    def test_debug_leaks_env_at_junior(self, make_client):
        """Junior tier imports debug handler from intern; full env is still exposed."""
        client = make_client("junior")
        resp = client.get("/challenges/misconfig/debug")
        assert resp.status_code == 200
        data = resp.json()
        assert "secret_key" in data
        assert "jwt_secret" in data

    def test_env_file_accessible_at_junior(self, make_client):
        """Junior tier imports env handler from intern; .env is still accessible."""
        client = make_client("junior")
        resp = client.get("/challenges/misconfig/.env")
        assert resp.status_code == 200
        assert "SECRET_KEY" in resp.text

    def test_cors_reflects_origin_not_wildcard(self, make_client):
        """Junior CORS reflects the Origin header instead of returning *."""
        client = make_client("junior")
        resp = client.get(
            "/challenges/misconfig/cors-test",
            headers={"Origin": "https://evil.com"},
        )
        assert resp.status_code == 200
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        assert acao == "https://evil.com"
        assert resp.headers.get("Access-Control-Allow-Credentials") == "true"

    def test_cors_solves_at_junior(self, make_client, db):
        """Accessing CORS endpoint with cross-origin header solves misconfig_cors at junior."""
        db.add(Challenge(key="misconfig_cors", name="Access-Control-Allow-Yolo", category="A02 Misconfig"))
        db.commit()
        client = make_client("junior")
        client.get(
            "/challenges/misconfig/cors-test",
            headers={"Origin": "https://attacker.example.com"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "misconfig_cors").first()
        assert challenge.solved


class TestMisconfigSenior:
    """Senior tier: debug returns partial config; .env blocked; CORS still reflects Origin."""

    def test_debug_returns_partial_config(self, make_client):
        """Senior debug endpoint leaks version and debug flag but not secret_key."""
        client = make_client("senior")
        resp = client.get("/challenges/misconfig/debug")
        assert resp.status_code == 200
        data = resp.json()
        assert "secret_key" not in data
        assert "database_url" not in data

    def test_env_file_blocked_at_senior(self, make_client):
        """.env returns 404 at senior tier."""
        client = make_client("senior")
        resp = client.get("/challenges/misconfig/.env")
        assert resp.status_code == 404

    def test_cors_still_reflects_at_senior(self, make_client):
        """Senior CORS still reflects Origin (no allowlist), so is still vulnerable."""
        client = make_client("senior")
        resp = client.get(
            "/challenges/misconfig/cors-test",
            headers={"Origin": "https://evil.com"},
        )
        assert resp.status_code == 200
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        assert acao == "https://evil.com"

    def test_info_disclosure_not_solved_at_senior(self, make_client, db):
        """.env returns 404 at senior; info_disclosure challenge is not solved."""
        db.add(Challenge(key="info_disclosure", name="Exposed Config Files", category="A02 Misconfig"))
        db.commit()
        client = make_client("senior")
        client.get("/challenges/misconfig/.env")
        challenge = db.query(Challenge).filter(Challenge.key == "info_disclosure").first()
        assert not challenge.solved

    def test_debug_solves_at_senior(self, make_client, db):
        """Debug endpoint still auto-solves at senior (partial leak still counts)."""
        db.add(Challenge(key="misconfig_debug", name="We'll Turn It Off Before Launch", category="A02 Misconfig"))
        db.commit()
        client = make_client("senior")
        client.get("/challenges/misconfig/debug")
        challenge = db.query(Challenge).filter(Challenge.key == "misconfig_debug").first()
        assert challenge.solved

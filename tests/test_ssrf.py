"""Tests for SSRF vulnerability module.

Proves internal URL fetching works at intern tier and is blocked at tech_lead tier.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from app.models.challenge import Challenge


class TestSsrfPageLoads:
    """Basic page load tests."""

    def test_ssrf_page_loads(self, client):
        resp = client.get("/challenges/ssrf")
        assert resp.status_code == 200
        assert "Microservice Mischief" in resp.text

    def test_ssrf_page_no_url(self, client):
        """Page loads without error when no URL parameter is provided."""
        resp = client.get("/challenges/ssrf")
        assert resp.status_code == 200


class TestSsrfIntern:
    """Intern tier: no URL validation, can fetch internal addresses."""

    def test_localhost_url_attempted(self, make_client, db):
        """Intern tier allows fetching localhost URLs and solves the challenge."""
        db.add(Challenge(key="ssrf_internal", name="Microservice Mischief", category="A01 Broken Access"))
        db.commit()

        # Mock httpx so the fetch "succeeds" without a real network call
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "internal data"
        mock_response.headers = {}
        mock_response.url = "http://127.0.0.1:1/"

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("app.vulnerabilities.ssrf.handlers.intern.httpx.AsyncClient", return_value=mock_client_instance):
            client = make_client("intern")
            resp = client.get("/challenges/ssrf", params={"url": "http://127.0.0.1:1/"})
            assert resp.status_code == 200
            assert "not in allowlist" not in resp.text

        challenge = db.query(Challenge).filter(Challenge.key == "ssrf_internal").first()
        assert challenge.solved

    def test_metadata_url_attempted(self, make_client):
        """Intern tier does not block cloud metadata URLs."""
        client = make_client("intern")
        resp = client.get(
            "/challenges/ssrf",
            params={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert resp.status_code == 200
        assert "not in allowlist" not in resp.text


class TestSsrfTechLead:
    """Tech lead tier: domain allowlist blocks internal URLs."""

    def test_localhost_blocked(self, make_client):
        """Tech lead tier rejects localhost URLs."""
        client = make_client("tech_lead")
        resp = client.get("/challenges/ssrf", params={"url": "http://127.0.0.1:8000/"})
        assert resp.status_code == 200
        assert "not in allowlist" in resp.text or "allowlist" in resp.text

    def test_metadata_blocked(self, make_client):
        """Tech lead tier rejects cloud metadata URLs."""
        client = make_client("tech_lead")
        resp = client.get("/challenges/ssrf", params={"url": "http://169.254.169.254/latest/"})
        assert resp.status_code == 200
        assert "not in allowlist" in resp.text or "allowlist" in resp.text

    def test_allowed_domain_accepted(self, make_client):
        """Tech lead tier allows fetching from allowlisted domains."""
        client = make_client("tech_lead")
        # example.com is in the allowlist; the fetch itself may timeout but should not be rejected
        resp = client.get("/challenges/ssrf", params={"url": "http://example.com"})
        assert resp.status_code == 200
        assert "not in allowlist" not in resp.text


class TestSsrfJunior:
    """Junior tier: string-based blocklist misses alternative IP representations."""

    def test_localhost_blocked_by_string_check(self, make_client):
        """'localhost' is in the junior string blocklist and is rejected."""
        client = make_client("junior")
        resp = client.get("/challenges/ssrf", params={"url": "http://localhost:8000/"})
        assert resp.status_code == 200
        assert "blocked" in resp.text.lower() or "not allowed" in resp.text.lower()

    def test_zero_ip_not_in_blocklist(self, make_client, db):
        """0.0.0.0 is not in the junior string blocklist; request is attempted."""
        db.add(Challenge(key="ssrf_internal", name="Microservice Mischief", category="A01 Broken Access"))
        db.commit()
        from unittest.mock import AsyncMock, patch

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "internal service data"
        mock_response.headers = {}
        mock_response.url = "http://0.0.0.0:8000/health"

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.vulnerabilities.ssrf.handlers.junior.httpx.AsyncClient",
            return_value=mock_client_instance,
        ):
            client = make_client("junior")
            resp = client.get("/challenges/ssrf", params={"url": "http://0.0.0.0:8000/health"})
            assert resp.status_code == 200
            # 0.0.0.0 is not blocked by the junior handler
            assert "blocked" not in resp.text.lower() or "internal service" in resp.text

        challenge = db.query(Challenge).filter(Challenge.key == "ssrf_internal").first()
        assert challenge.solved


class TestSsrfSenior:
    """Senior tier: DNS-based private IP check; public domains are allowed."""

    def test_localhost_blocked_by_dns_check(self, make_client):
        """127.0.0.1 resolves to a loopback address and is blocked."""
        client = make_client("senior")
        resp = client.get("/challenges/ssrf", params={"url": "http://127.0.0.1:8000/"})
        assert resp.status_code == 200
        assert "blocked" in resp.text.lower() or "not allowed" in resp.text.lower() or "private" in resp.text.lower()

    def test_ssrf_not_solved_with_public_url(self, make_client, db):
        """Fetching a public domain does not solve ssrf_internal."""
        db.add(Challenge(key="ssrf_internal", name="Microservice Mischief", category="A01 Broken Access"))
        db.commit()
        client = make_client("senior")
        # example.com is a public domain; solve condition requires internal URL patterns
        resp = client.get("/challenges/ssrf", params={"url": "http://example.com"})
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "ssrf_internal").first()
        assert not challenge.solved

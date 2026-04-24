"""Tests for CSRF vulnerability module.

Proves cross-site transfer succeeds without token at intern tier and is blocked at tech_lead tier.
"""

from __future__ import annotations

from app.models.challenge import Challenge


class TestCsrfPageLoads:
    """Basic page load tests."""

    def test_csrf_page_loads(self, client):
        resp = client.get("/challenges/csrf")
        assert resp.status_code == 200
        assert "One-Click Equity Dilution" in resp.text


class TestCsrfIntern:
    """Intern tier: no CSRF protection at all."""

    def test_transfer_without_token(self, make_client, db):
        """Transfer succeeds with no CSRF token at intern tier."""
        db.add(Challenge(key="csrf_transfer", name="One-Click Equity Dilution", category="A01 Broken Access"))
        db.commit()
        client = make_client("intern")
        resp = client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "attacker", "amount": "50000"},
        )
        assert resp.status_code == 200
        assert "Transferred" in resp.text
        assert "attacker" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "csrf_transfer").first()
        assert challenge.solved

    def test_transfer_no_referer(self, make_client):
        """Transfer succeeds even without Referer header."""
        client = make_client("intern")
        resp = client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "evil", "amount": "100"},
        )
        assert resp.status_code == 200
        assert "Transferred" in resp.text


class TestCsrfTechLead:
    """Tech lead tier: strict CSRF token validation."""

    def test_transfer_without_token_fails(self, make_client):
        """Transfer is rejected without a valid CSRF token at tech_lead tier."""
        client = make_client("tech_lead")
        # First load the page (which sets csrf_token in session)
        client.get("/challenges/csrf")
        # POST without the CSRF token
        resp = client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "attacker", "amount": "50000"},
        )
        assert resp.status_code == 200
        assert "CSRF token validation failed" in resp.text

    def test_transfer_with_wrong_token_fails(self, make_client):
        """Transfer is rejected with an incorrect CSRF token."""
        client = make_client("tech_lead")
        client.get("/challenges/csrf")
        resp = client.post(
            "/challenges/csrf/transfer",
            data={
                "recipient": "attacker",
                "amount": "50000",
                "csrf_token": "wrong-token",
            },
        )
        assert resp.status_code == 200
        assert "CSRF token validation failed" in resp.text

    def test_csrf_transfer_not_solved_at_tech_lead(self, make_client, db):
        """Transfer without token at tech_lead does not solve the challenge."""
        db.add(Challenge(key="csrf_transfer", name="One-Click Equity Dilution", category="A01 Broken Access"))
        db.commit()
        client = make_client("tech_lead")
        client.get("/challenges/csrf")
        client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "attacker", "amount": "50000"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "csrf_transfer").first()
        assert not challenge.solved

    def test_transfer_with_valid_token_succeeds(self, make_client):
        """Transfer succeeds when the correct CSRF token is provided."""
        client = make_client("tech_lead")
        # Load the page to get the CSRF token from the rendered HTML
        page = client.get("/challenges/csrf")
        assert page.status_code == 200
        # Extract the csrf_token from the hidden form field in the HTML
        # The template should render the token in a hidden input
        import re

        match = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', page.text)
        if match:
            csrf_token = match.group(1)
            resp = client.post(
                "/challenges/csrf/transfer",
                data={
                    "recipient": "legit_user",
                    "amount": "100",
                    "csrf_token": csrf_token,
                },
            )
            assert resp.status_code == 200
            assert "Transferred" in resp.text


class TestCsrfTechLeadNoSolve:
    """Tech lead tier: valid token produces a successful transfer but does not solve the challenge."""

    def test_valid_token_transfer_does_not_solve_challenge(self, make_client, db):
        """A legitimate same-session transfer at tech_lead tier is NOT an exploit and must not solve."""
        import re

        db.add(Challenge(key="csrf_transfer", name="One-Click Equity Dilution", category="A01 Broken Access"))
        db.commit()
        client = make_client("tech_lead")
        page = client.get("/challenges/csrf")
        assert page.status_code == 200
        match = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', page.text)
        assert match, "CSRF token not found in tech_lead page"
        csrf_token = match.group(1)
        resp = client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "attacker", "amount": "50000", "csrf_token": csrf_token},
        )
        assert resp.status_code == 200
        # Transfer may succeed at tech_lead (same-origin, valid token)
        challenge = db.query(Challenge).filter(Challenge.key == "csrf_transfer").first()
        assert not challenge.solved


class TestCsrfJunior:
    """Junior tier: Referer check blocks cross-origin requests but empty Referer bypasses it."""

    def test_no_referer_bypasses_check(self, make_client, db):
        """Transfer with no Referer header succeeds at junior tier (bypass)."""
        db.add(Challenge(key="csrf_transfer", name="One-Click Equity Dilution", category="A01 Broken Access"))
        db.commit()
        client = make_client("junior")
        resp = client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "attacker", "amount": "50000"},
        )
        assert resp.status_code == 200
        assert "Transferred" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "csrf_transfer").first()
        assert challenge.solved

    def test_external_referer_blocked_at_junior(self, make_client):
        """Transfer with Referer: https://evil.com is blocked at junior tier."""
        client = make_client("junior")
        resp = client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "attacker", "amount": "1000"},
            headers={"Referer": "https://evil.com"},
        )
        assert resp.status_code == 200
        assert "Transferred" not in resp.text

    def test_localhost_referer_allowed_at_junior(self, make_client):
        """Transfer with Referer: http://localhost/ is allowed (looks local)."""
        client = make_client("junior")
        resp = client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "legit", "amount": "100"},
            headers={"Referer": "http://localhost/challenges/csrf"},
        )
        assert resp.status_code == 200
        assert "Transferred" in resp.text


class TestCsrfSenior:
    """Senior tier: CSRF token required; token is not rotated after use."""

    def test_transfer_without_token_fails_at_senior(self, make_client):
        """POST without csrf_token is rejected at senior tier."""
        client = make_client("senior")
        client.get("/challenges/csrf")
        resp = client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "attacker", "amount": "50000"},
        )
        assert resp.status_code == 200
        assert "CSRF token validation failed" in resp.text or "Invalid" in resp.text

    def test_wrong_token_fails_at_senior(self, make_client):
        """POST with a wrong csrf_token is rejected at senior tier."""
        client = make_client("senior")
        client.get("/challenges/csrf")
        resp = client.post(
            "/challenges/csrf/transfer",
            data={"recipient": "attacker", "amount": "50000", "csrf_token": "deadbeef"},
        )
        assert resp.status_code == 200
        assert "CSRF token validation failed" in resp.text or "Invalid" in resp.text

    def test_transfer_with_valid_token_succeeds_at_senior(self, make_client, db):
        """POST with extracted csrf_token succeeds and solves challenge at senior tier."""
        import re

        db.add(Challenge(key="csrf_transfer", name="One-Click Equity Dilution", category="A01 Broken Access"))
        db.commit()
        client = make_client("senior")
        page = client.get("/challenges/csrf")
        assert page.status_code == 200
        match = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', page.text)
        if match:
            csrf_token = match.group(1)
            resp = client.post(
                "/challenges/csrf/transfer",
                data={"recipient": "legit_user", "amount": "100", "csrf_token": csrf_token},
            )
            assert resp.status_code == 200
            assert "Transferred" in resp.text
            challenge = db.query(Challenge).filter(Challenge.key == "csrf_transfer").first()
            assert challenge.solved

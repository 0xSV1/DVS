"""Tests for miscellaneous challenge routes: mass assignment, open redirect, broken logging."""

from __future__ import annotations

from app.models.challenge import Challenge


class TestOpenRedirect:
    """Open redirect at /redirect endpoint."""

    def test_intern_allows_external_redirect(self, make_client, db):
        db.add(Challenge(key="open_redirect", name="Redirect to My Portfolio", category="A01 Broken Access"))
        db.commit()
        client = make_client("intern")
        resp = client.get("/redirect", params={"url": "http://evil.com"}, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "http://evil.com"
        challenge = db.query(Challenge).filter(Challenge.key == "open_redirect").first()
        assert challenge.solved

    def test_open_redirect_not_solved_at_tech_lead(self, make_client, db):
        """External redirect at tech_lead does not solve the challenge."""
        db.add(Challenge(key="open_redirect", name="Redirect to My Portfolio", category="A01 Broken Access"))
        db.commit()
        client = make_client("tech_lead")
        client.get("/redirect", params={"url": "http://evil.com"}, follow_redirects=False)
        challenge = db.query(Challenge).filter(Challenge.key == "open_redirect").first()
        assert not challenge.solved

    def test_tech_lead_blocks_external(self, make_client):
        client = make_client("tech_lead")
        resp = client.get("/redirect", params={"url": "http://evil.com"}, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_tech_lead_blocks_protocol_relative(self, make_client):
        client = make_client("tech_lead")
        resp = client.get("/redirect", params={"url": "//evil.com"}, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_tech_lead_allows_relative(self, make_client):
        client = make_client("tech_lead")
        resp = client.get("/redirect", params={"url": "/dashboard"}, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/dashboard"


class TestBrokenLogging:
    """Audit log exposure at /challenges/logging."""

    def test_intern_shows_logs_page(self, make_client, db):
        from app.models.system import AuditLog

        db.add(Challenge(key="broken_logging", name="console.log(password)", category="A09 Logging Failures"))
        db.add(AuditLog(action="login", resource="/login", details="password=admin", ip_address="127.0.0.1"))
        db.commit()
        client = make_client("intern")
        resp = client.get("/challenges/logging")
        assert resp.status_code == 200
        assert "Audit Logs" in resp.text or "No audit logs found" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "broken_logging").first()
        assert challenge.solved

    def test_tech_lead_hides_logs(self, make_client):
        client = make_client("tech_lead")
        resp = client.get("/challenges/logging")
        assert resp.status_code == 200
        assert "only accessible to admin" in resp.text


class TestOpenRedirectJunior:
    """Junior tier: functionally identical to intern; external redirect works."""

    def test_external_redirect_works_at_junior(self, make_client, db):
        """Junior handler allows external redirect; solve triggers."""
        db.add(Challenge(key="open_redirect", name="Redirect to My Portfolio", category="A01 Broken Access"))
        db.commit()
        client = make_client("junior")
        resp = client.get("/redirect", params={"url": "https://evil.com"}, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "https://evil.com"
        challenge = db.query(Challenge).filter(Challenge.key == "open_redirect").first()
        assert challenge.solved

    def test_relative_url_not_external_at_junior(self, make_client, db):
        """Relative URL does not trigger the solve at junior (not external)."""
        db.add(Challenge(key="open_redirect", name="Redirect to My Portfolio", category="A01 Broken Access"))
        db.commit()
        client = make_client("junior")
        client.get("/redirect", params={"url": "/dashboard"}, follow_redirects=False)
        challenge = db.query(Challenge).filter(Challenge.key == "open_redirect").first()
        assert not challenge.solved


class TestOpenRedirectSenior:
    """Senior tier: http/https blocked; protocol-relative //evil.com passes but is not tracked."""

    def test_http_redirect_blocked_at_senior(self, make_client):
        """Senior handler rejects http:// and https:// URLs; redirects to /."""
        client = make_client("senior")
        resp = client.get("/redirect", params={"url": "https://evil.com"}, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_protocol_relative_passes_at_senior(self, make_client):
        """//evil.com does not start with http/https; handler allows it through."""
        client = make_client("senior")
        resp = client.get("/redirect", params={"url": "//evil.com"}, follow_redirects=False)
        assert resp.status_code == 302
        # The handler allows // URLs; browser would redirect to evil.com
        assert resp.headers["location"] != "/"

    def test_open_redirect_not_solved_at_senior(self, make_client, db):
        """Senior handler returns is_external=False for // URLs; solve never fires."""
        db.add(Challenge(key="open_redirect", name="Redirect to My Portfolio", category="A01 Broken Access"))
        db.commit()
        client = make_client("senior")
        client.get("/redirect", params={"url": "//evil.com"}, follow_redirects=False)
        challenge = db.query(Challenge).filter(Challenge.key == "open_redirect").first()
        assert not challenge.solved


class TestBrokenLoggingJunior:
    """Junior tier: functionally identical to intern; log exposure solves challenge."""

    def test_logs_exposed_at_junior(self, make_client, db):
        """Junior tier exposes audit logs (imported from intern handler)."""
        from app.models.system import AuditLog

        db.add(Challenge(key="broken_logging", name="console.log(password)", category="A09 Logging Failures"))
        db.add(AuditLog(action="login", resource="/login", details="password=secret", ip_address="10.0.0.1"))
        db.commit()
        client = make_client("junior")
        resp = client.get("/challenges/logging")
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "broken_logging").first()
        assert challenge.solved


class TestBrokenLoggingSenior:
    """Senior tier: log details stripped; difficulty condition excludes senior from solve."""

    def test_logs_returned_but_filtered_at_senior(self, make_client, db):
        """Senior tier returns logs but strips details and ip_address fields."""
        from app.models.system import AuditLog

        db.add(AuditLog(action="login", resource="/login", details="password=secret", ip_address="10.0.0.1"))
        db.commit()
        client = make_client("senior")
        resp = client.get("/challenges/logging")
        assert resp.status_code == 200
        assert "password=secret" not in resp.text
        assert "10.0.0.1" not in resp.text

    def test_broken_logging_not_solved_at_senior(self, make_client, db):
        """Solve condition requires intern/junior difficulty; senior is excluded."""
        from app.models.system import AuditLog

        db.add(Challenge(key="broken_logging", name="console.log(password)", category="A09 Logging Failures"))
        db.add(AuditLog(action="login", resource="/login", details="password=secret", ip_address="10.0.0.1"))
        db.commit()
        client = make_client("senior")
        client.get("/challenges/logging")
        challenge = db.query(Challenge).filter(Challenge.key == "broken_logging").first()
        assert not challenge.solved

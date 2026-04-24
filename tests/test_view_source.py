"""Tests for View Source and OWASP reference routes."""

from __future__ import annotations

from app.models.challenge import Challenge


class TestViewSource:
    """View Source educational feature."""

    def test_source_index(self, client):
        resp = client.get("/source")
        assert resp.status_code == 200
        assert "SQL Injection" in resp.text
        assert "Cross-Site Scripting" in resp.text

    def test_compare_sqli(self, client):
        resp = client.get("/source/sqli")
        assert resp.status_code == 200
        assert "Intern" in resp.text
        assert "Tech Lead" in resp.text
        # Pygments should have highlighted Python code
        assert "source-highlight" in resp.text

    def test_single_tier(self, client):
        resp = client.get("/source/xss?tier=intern")
        assert resp.status_code == 200
        assert "Intern" in resp.text
        assert "source-highlight" in resp.text

    def test_help_page(self, client):
        resp = client.get("/source/sqli/help")
        assert resp.status_code == 200
        assert "SQL Injection" in resp.text
        assert "CWE-89" in resp.text

    def test_invalid_module(self, client):
        resp = client.get("/source/nonexistent")
        assert resp.status_code == 200
        assert "Not Found" in resp.text


class TestViewSourcePuzzle:
    """A06 Insecure Design: vulnerability report submission challenge."""

    def test_compare_page_does_not_autosolve(self, client):
        """Opening the compare page should NOT solve the challenge."""
        resp = client.get("/source/sqli")
        assert resp.status_code == 200
        assert "Vulnerability Report" in resp.text
        # The challenge should not be auto-solved
        assert "Challenge solved" not in resp.text

    def test_wrong_cwe_rejected(self, client):
        """Submitting an incorrect CWE is rejected."""
        resp = client.post(
            "/source/sqli/report",
            data={"cwe": "CWE-79", "fix_description": "use parameterized queries"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert "vulnerability classification is incorrect" in resp.text

    def test_wrong_fix_rejected(self, client):
        """Correct CWE but vague fix description is rejected."""
        resp = client.post(
            "/source/sqli/report",
            data={"cwe": "CWE-89", "fix_description": "make it more secure"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert "fix description does not match" in resp.text

    def test_correct_report_accepted(self, client):
        """Correct CWE and fix description for a module is accepted."""
        resp = client.post(
            "/source/sqli/report",
            data={
                "cwe": "89",
                "fix_description": "use parameterized queries with bound parameters",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert "Correct" in resp.text or "complete" in resp.text

    def test_three_reports_needed(self, client, db):
        """Challenge requires correct reports for 3 distinct modules."""
        db.add(Challenge(key="view_source_puzzle", name="Read the Diffs", category="A06 Insecure Design"))
        db.commit()
        # Report 1: sqli
        client.post(
            "/source/sqli/report",
            data={"cwe": "89", "fix_description": "parameterized queries"},
            follow_redirects=True,
        )
        # Report 2: xss
        client.post(
            "/source/xss/report",
            data={
                "cwe": "79",
                "fix_description": "sanitize and escape output with bleach",
            },
            follow_redirects=True,
        )
        # Not yet solved (only 2/3)
        resp = client.get("/source/sqli")
        assert "2/3" in resp.text or "2 / 3" in resp.text

        # Report 3: idor
        resp = client.post(
            "/source/idor/report",
            data={
                "cwe": "639",
                "fix_description": "check ownership with current_user authorization",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert "Challenge solved" in resp.text or "3/3" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "view_source_puzzle").first()
        assert challenge.solved


class TestOwaspReference:
    """OWASP Top 10 cross-reference page."""

    def test_owasp_page_loads(self, client):
        resp = client.get("/owasp")
        assert resp.status_code == 200
        assert "Broken Access Control" in resp.text
        assert "Prompt Injection" in resp.text

    def test_owasp_has_categories(self, client):
        resp = client.get("/owasp")
        assert "A01" in resp.text
        assert "A10" in resp.text
        assert "LLM01" in resp.text

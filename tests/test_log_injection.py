"""Tests for the log injection (log_injection) challenge.

Proves newline injection at intern, carriage return bypass at junior,
control char stripping at senior, and full protection at tech_lead.
"""

from __future__ import annotations

from app.models.challenge import Challenge
from app.vulnerabilities.log_injection.router import _log_entries


def _seed_challenge(db):
    """Insert the log_injection challenge into the test DB."""
    ch = Challenge(
        key="log_injection",
        name="Fake It Till You Ship It",
        category="A09 Logging Failures",
        difficulty=2,
        cwe="CWE-117",
        description="Test",
        hint="Test",
        owasp_url="",
        min_difficulty="junior",
        tags="logging",
    )
    db.add(ch)
    db.commit()


def _clear_logs():
    """Clear the in-memory log entries between tests."""
    _log_entries.clear()


class TestLogInjectionPageLoads:
    def test_page_loads(self, client):
        _clear_logs()
        resp = client.get("/challenges/log-injection")
        assert resp.status_code == 200
        assert "Fake It Till You Ship It" in resp.text


class TestLogInjectionIntern:
    def test_newline_creates_multiple_entries(self, make_client, db):
        """Intern tier: newlines in feedback create multiple visual log entries."""
        _clear_logs()
        _seed_challenge(db)
        client = make_client("intern")
        payload = "Great app!\n[2026-03-20 14:00:00] [ADMIN] action=grant_admin user=hacker"
        resp = client.post(
            "/challenges/log-injection/submit",
            data={"feedback": payload, "username": "testuser"},
        )
        assert resp.status_code == 200
        # The raw newline should be in the stored entry
        assert len(_log_entries) >= 1
        assert "\n" in _log_entries[-1]

    def test_forge_keyword_detected(self, make_client, db):
        """Intern tier: forged admin action triggers solve detection."""
        _clear_logs()
        _seed_challenge(db)
        client = make_client("intern")
        payload = "test\n[2026-03-20] [ADMIN] action=delete_all"
        client.post(
            "/challenges/log-injection/submit",
            data={"feedback": payload, "username": "attacker"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "log_injection").first()
        assert challenge.solved


class TestLogInjectionJunior:
    def test_newline_stripped(self, make_client, db):
        """Junior tier: plain \\n is stripped from feedback."""
        _clear_logs()
        _seed_challenge(db)
        client = make_client("junior")
        payload = "Great app!\nforged entry"
        client.post(
            "/challenges/log-injection/submit",
            data={"feedback": payload, "username": "testuser"},
        )
        # The \n should be removed
        assert "\n" not in _log_entries[-1]

    def test_carriage_return_passes(self, make_client, db):
        """Junior tier: \\r passes through the filter."""
        _clear_logs()
        _seed_challenge(db)
        client = make_client("junior")
        payload = "Great app!\r[2026-03-20 14:00:00] [ADMIN] action=grant_admin"
        client.post(
            "/challenges/log-injection/submit",
            data={"feedback": payload, "username": "testuser"},
        )
        assert "\r" in _log_entries[-1]

    def test_cr_with_forge_keyword_solves(self, make_client, db):
        """Junior tier: \\r + forge keyword triggers solve."""
        _clear_logs()
        _seed_challenge(db)
        client = make_client("junior")
        payload = "test\r[2026-03-20] [SYSTEM] action=grant_admin user=hacker"
        client.post(
            "/challenges/log-injection/submit",
            data={"feedback": payload, "username": "attacker"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "log_injection").first()
        assert challenge.solved

    def test_crlf_bypass(self, make_client, db):
        """Junior tier: \\r\\n bypass works (\\n stripped, \\r remains)."""
        _clear_logs()
        _seed_challenge(db)
        client = make_client("junior")
        payload = "test\r\n[2026-03-20] [ADMIN] action=delete_user"
        client.post(
            "/challenges/log-injection/submit",
            data={"feedback": payload, "username": "attacker"},
        )
        # \n stripped, \r remains
        stored = _log_entries[-1]
        assert "\n" not in stored
        assert "\r" in stored


class TestLogInjectionSenior:
    def test_control_chars_stripped(self, make_client, db):
        """Senior tier: all control characters are stripped from feedback."""
        _clear_logs()
        client = make_client("senior")
        payload = "test\r\n\x00\x01\x1b[ADMIN] action=grant_admin"
        client.post(
            "/challenges/log-injection/submit",
            data={"feedback": payload, "username": "testuser"},
        )
        stored = _log_entries[-1]
        assert "\r" not in stored
        assert "\n" not in stored
        assert "\x00" not in stored


class TestLogInjectionTechLead:
    def test_control_chars_stripped(self, make_client, db):
        """Tech lead tier: all control characters stripped."""
        _clear_logs()
        client = make_client("tech_lead")
        payload = "test\r\n\x00[ADMIN] action=grant_admin"
        client.post(
            "/challenges/log-injection/submit",
            data={"feedback": payload, "username": "testuser"},
        )
        stored = _log_entries[-1]
        assert "\r" not in stored
        assert "\n" not in stored

    def test_integrity_hash_present(self, make_client, db):
        """Tech lead tier: log entries include integrity hash."""
        _clear_logs()
        client = make_client("tech_lead")
        client.post(
            "/challenges/log-injection/submit",
            data={"feedback": "test feedback", "username": "testuser"},
        )
        stored = _log_entries[-1]
        assert "integrity=" in stored

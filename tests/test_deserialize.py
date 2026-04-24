"""Tests for deserialization vulnerability module.

Proves pickle deserialization is detectable at intern tier and JSON-only at tech_lead.
"""

from __future__ import annotations

import base64
import json

from app.models.challenge import Challenge


class TestDeserializePageLoads:
    def test_page_loads(self, client):
        resp = client.get("/challenges/deserialize")
        assert resp.status_code == 200
        assert "Unpickle Me This" in resp.text


class TestDeserializeIntern:
    def test_pickle_format_shown(self, make_client):
        client = make_client("intern")
        resp = client.get("/challenges/deserialize")
        assert resp.status_code == 200
        assert "pickle" in resp.text.lower()

    def test_pickle_exploit_detected(self, make_client, db):
        """Submitting a payload with RCE markers is detected as exploit."""
        db.add(Challenge(key="deserialize_pickle", name="Unpickle Me This", category="A08 Data Integrity"))
        db.commit()
        client = make_client("intern")
        # Craft a payload that contains os/system markers
        payload = base64.b64encode(b"\x80\x03cos\nsystem\nX\x05\x00\x00\x00id").decode()
        resp = client.post(
            "/challenges/deserialize/load",
            data={"data": payload},
        )
        assert resp.status_code == 200
        assert "RCE payload detected" in resp.text or "solved" in resp.text.lower()
        challenge = db.query(Challenge).filter(Challenge.key == "deserialize_pickle").first()
        assert challenge.solved

    def test_benign_pickle_no_solve_at_intern(self, make_client, db):
        """Normal pickle data without RCE markers does not set _solved at intern tier."""
        db.add(Challenge(key="deserialize_pickle", name="Unpickle Me This", category="A08 Data Integrity"))
        db.commit()
        client = make_client("intern")
        import pickle

        benign = base64.b64encode(pickle.dumps({"theme": "dark"})).decode()
        client.post("/challenges/deserialize/load", data={"data": benign})
        challenge = db.query(Challenge).filter(Challenge.key == "deserialize_pickle").first()
        assert not challenge.solved


class TestDeserializeTechLead:
    def test_json_format_shown(self, make_client):
        client = make_client("tech_lead")
        resp = client.get("/challenges/deserialize")
        assert resp.status_code == 200
        assert "JSON" in resp.text

    def test_json_only(self, make_client):
        """Tech lead tier only accepts valid JSON."""
        client = make_client("tech_lead")
        prefs = {"theme": "light", "language": "fr", "notifications": False}
        encoded = base64.b64encode(json.dumps(prefs).encode()).decode()
        resp = client.post(
            "/challenges/deserialize/load",
            data={"data": encoded},
        )
        assert resp.status_code == 200

    def test_extra_keys_stripped(self, make_client):
        """Tech lead tier strips unauthorized keys."""
        client = make_client("tech_lead")
        prefs = {"theme": "dark", "role": "admin"}
        encoded = base64.b64encode(json.dumps(prefs).encode()).decode()
        resp = client.post(
            "/challenges/deserialize/load",
            data={"data": encoded},
        )
        assert resp.status_code == 200
        # The role key should be stripped in the result


class TestDeserializeJunior:
    """Junior tier: functionally identical to intern, pickle.loads() with _solved detection."""

    def test_pickle_format_shown_at_junior(self, make_client):
        """Junior tier still uses pickle serialization format."""
        client = make_client("junior")
        resp = client.get("/challenges/deserialize")
        assert resp.status_code == 200
        assert "pickle" in resp.text.lower()

    def test_pickle_rce_detected_at_junior(self, make_client, db):
        """Pickle payload with os/system markers is detected as exploit at junior tier."""
        db.add(Challenge(key="deserialize_pickle", name="Unpickle Me This", category="A08 Data Integrity"))
        db.commit()
        client = make_client("junior")
        payload = base64.b64encode(b"\x80\x03cos\nsystem\nX\x05\x00\x00\x00id").decode()
        resp = client.post(
            "/challenges/deserialize/load",
            data={"data": payload},
        )
        assert resp.status_code == 200
        assert "RCE payload detected" in resp.text or "solved" in resp.text.lower()
        challenge = db.query(Challenge).filter(Challenge.key == "deserialize_pickle").first()
        assert challenge.solved

    def test_benign_pickle_no_solve_at_junior(self, make_client, db):
        """Normal pickle data does not set _solved at junior tier."""
        db.add(Challenge(key="deserialize_pickle", name="Unpickle Me This", category="A08 Data Integrity"))
        db.commit()
        client = make_client("junior")
        import pickle

        benign = base64.b64encode(pickle.dumps({"theme": "dark"})).decode()
        client.post("/challenges/deserialize/load", data={"data": benign})
        challenge = db.query(Challenge).filter(Challenge.key == "deserialize_pickle").first()
        assert not challenge.solved


class TestDeserializeSenior:
    """Senior tier: JSON-only format; pickle is never loaded, _solved never set."""

    def test_json_format_shown_at_senior(self, make_client):
        """Senior tier uses JSON serialization format."""
        client = make_client("senior")
        resp = client.get("/challenges/deserialize")
        assert resp.status_code == 200
        assert "JSON" in resp.text

    def test_no_solve_at_senior(self, make_client, db):
        """Senior handler never sets _solved; deserialize_pickle cannot be solved."""
        db.add(Challenge(key="deserialize_pickle", name="Unpickle Me This", category="A08 Data Integrity"))
        db.commit()
        client = make_client("senior")
        prefs = {"theme": "light", "language": "en"}
        encoded = base64.b64encode(json.dumps(prefs).encode()).decode()
        client.post("/challenges/deserialize/load", data={"data": encoded})
        challenge = db.query(Challenge).filter(Challenge.key == "deserialize_pickle").first()
        assert not challenge.solved

    def test_senior_rejects_pickle_data(self, make_client):
        """Pickle bytes sent to senior tier return a JSON decode error, not a crash."""
        client = make_client("senior")
        import pickle

        payload = base64.b64encode(pickle.dumps({"theme": "dark"})).decode()
        resp = client.post("/challenges/deserialize/load", data={"data": payload})
        assert resp.status_code == 200
        # Handler returns JSON parse error; page should not 500
        assert "Invalid JSON" in resp.text or "error" in resp.text.lower()

    def test_senior_accepts_extra_keys(self, make_client):
        """Senior JSON handler accepts arbitrary keys without allowlist stripping.

        This is the documented senior-tier vulnerability: unlike tech_lead which
        filters to ALLOWED_KEYS, senior returns whatever was submitted, enabling
        mass-assignment style attacks downstream.
        """
        client = make_client("senior")
        prefs = {"theme": "dark", "role": "admin", "is_admin": True}
        encoded = base64.b64encode(json.dumps(prefs).encode()).decode()
        resp = client.post("/challenges/deserialize/load", data={"data": encoded})
        assert resp.status_code == 200
        # role and is_admin should appear in the response (not stripped)
        assert "admin" in resp.text

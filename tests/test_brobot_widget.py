"""Tests for BroBot global chat widget.

Verifies the widget API endpoint, general chat functionality,
and that brobot_general is hidden from the LLM challenge index.
"""

from __future__ import annotations


class TestBrobotChallengesEndpoint:
    """GET /api/llm/challenges returns valid challenge metadata."""

    def test_returns_json_with_challenge_keys(self, client):
        resp = client.get("/api/llm/challenges")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        # Should contain real challenges
        assert "llm_prompt_inject" in data
        assert "llm_system_leak" in data

    def test_excludes_brobot_general(self, client):
        """Widget-only challenges should not appear in the dropdown list."""
        resp = client.get("/api/llm/challenges")
        data = resp.json()
        assert "brobot_general" not in data

    def test_challenge_metadata_shape(self, client):
        resp = client.get("/api/llm/challenges")
        data = resp.json()
        for key, info in data.items():
            assert "name" in info
            assert "description" in info
            assert "category" in info


class TestBrobotGeneralChat:
    """POST /challenges/llm/brobot_general/chat works via mock provider."""

    def test_general_chat_returns_response(self, client):
        resp = client.post(
            "/challenges/llm/brobot_general/chat",
            json={"message": "hey bro"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "response" in data
        assert len(data["response"]) > 0

    def test_empty_message_rejected(self, client):
        resp = client.post(
            "/challenges/llm/brobot_general/chat",
            json={"message": ""},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data


class TestBrobotHiddenFromIndex:
    """brobot_general must not appear on the LLM challenges page."""

    def test_index_page_excludes_brobot_general(self, client):
        resp = client.get("/challenges/llm")
        assert resp.status_code == 200
        assert "brobot_general" not in resp.text

    def test_brobot_general_chat_page_accessible(self, client):
        """Direct navigation to brobot_general chat page still works."""
        resp = client.get("/challenges/llm/brobot_general")
        assert resp.status_code == 200

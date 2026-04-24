"""Tests for core application health and page routes."""

from __future__ import annotations


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


def test_landing_page(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "DeployBro" in resp.text


def test_challenges_page(client):
    resp = client.get("/challenges")
    assert resp.status_code == 200


def test_login_page(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "login" in resp.text.lower() or "sign in" in resp.text.lower()

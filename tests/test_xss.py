"""Tests for XSS vulnerability module.

Proves script injection works at intern tier and is sanitized at tech_lead.
Tests xss_dom solve detection via the /xss/dom/solve endpoint.
"""

from __future__ import annotations

from app.models.challenge import Challenge


class TestXssIntern:
    """Intern tier: no sanitization, script passes through."""

    def test_reflected_xss(self, make_client, db):
        db.add(Challenge(key="xss_reflected", name="Alert('Ship It!')", category="A05 Injection"))
        db.commit()
        client = make_client("intern")
        payload = '<script>alert("xss")</script>'
        resp = client.get("/challenges/xss", params={"q": payload})
        assert resp.status_code == 200
        # Intern tier: script tag should appear verbatim (|safe filter)
        assert "<script>" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "xss_reflected").first()
        assert challenge.solved

    def test_img_onerror(self, make_client):
        client = make_client("intern")
        payload = "<img src=x onerror=alert(1)>"
        resp = client.get("/challenges/xss", params={"q": payload})
        assert resp.status_code == 200
        assert "onerror" in resp.text


class TestXssTechLead:
    """Tech lead tier: bleach sanitization + CSP header."""

    def test_script_stripped(self, make_client):
        client = make_client("tech_lead")
        payload = '<script>alert("xss")</script>'
        resp = client.get("/challenges/xss", params={"q": payload})
        assert resp.status_code == 200
        assert '<script>alert("xss")</script>' not in resp.text

    def test_csp_header_present(self, make_client):
        client = make_client("tech_lead")
        resp = client.get("/challenges/xss", params={"q": "test"})
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "script-src" in csp

    def test_xss_reflected_not_solved_at_tech_lead(self, make_client, db):
        """Script tag at tech_lead does not solve the challenge."""
        db.add(Challenge(key="xss_reflected", name="Alert('Ship It!')", category="A05 Injection"))
        db.commit()
        client = make_client("tech_lead")
        payload = '<script>alert("xss")</script>'
        client.get("/challenges/xss", params={"q": payload})
        challenge = db.query(Challenge).filter(Challenge.key == "xss_reflected").first()
        assert not challenge.solved


class TestXssDom:
    """xss_dom challenge: client-side JS reports payload to /xss/dom/solve."""

    def test_dom_page_loads(self, make_client):
        client = make_client("intern")
        resp = client.get("/challenges/xss/dom")
        assert resp.status_code == 200

    def test_dom_xss_solve_with_script(self, make_client, db):
        """Submitting a script payload solves the xss_dom challenge."""
        db.add(Challenge(key="xss_dom", name="Client-Side Deploys Only", category="A05 Injection"))
        db.commit()
        client = make_client("intern")
        client.post(
            "/challenges/xss/dom/solve",
            json={"payload": '<script>alert("xss")</script>'},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "xss_dom").first()
        assert challenge.solved

    def test_dom_xss_benign_payload_no_solve(self, make_client, db):
        """Benign payload does not solve the challenge."""
        db.add(Challenge(key="xss_dom", name="Client-Side Deploys Only", category="A05 Injection"))
        db.commit()
        client = make_client("intern")
        client.post(
            "/challenges/xss/dom/solve",
            json={"payload": "hello world"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "xss_dom").first()
        assert not challenge.solved

    def test_dom_xss_does_not_solve_at_tech_lead(self, make_client, db):
        """XSS payload posted directly to /dom/solve does not solve at tech_lead (CSP tier)."""
        db.add(Challenge(key="xss_dom", name="Client-Side Deploys Only", category="A05 Injection"))
        db.commit()
        client = make_client("tech_lead")
        client.post(
            "/challenges/xss/dom/solve",
            json={"payload": '<script>alert("xss")</script>'},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "xss_dom").first()
        assert not challenge.solved


class TestXssJunior:
    """Junior tier: partial tag/event blacklist, bypassable with unlisted handlers."""

    def test_script_tag_stripped(self, make_client):
        """Junior filter removes <script> tags from reflected output."""
        client = make_client("junior")
        resp = client.get("/challenges/xss", params={"q": "<script>alert(1)</script>"})
        assert resp.status_code == 200
        assert "<script>alert(1)</script>" not in resp.text

    def test_ontoggle_not_in_blacklist(self, make_client):
        """<details ontoggle> is not in the junior blacklist and passes through."""
        client = make_client("junior")
        payload = "<details open ontoggle=\"alert('XSS')\">"
        resp = client.get("/challenges/xss", params={"q": payload})
        assert resp.status_code == 200
        assert "ontoggle" in resp.text

    def test_xss_reflected_solves_at_junior(self, make_client, db):
        """Submitting an ontoggle payload solves xss_reflected at junior tier."""
        db.add(Challenge(key="xss_reflected", name="Alert('Ship It!')", category="A05 Injection"))
        db.commit()
        client = make_client("junior")
        payload = "<details open ontoggle=\"alert('XSS')\">"
        resp = client.get("/challenges/xss", params={"q": payload})
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "xss_reflected").first()
        assert challenge.solved


class TestXssSenior:
    """Senior tier: HTML output escaped, but payload injected into JS string context."""

    def test_script_tag_html_escaped(self, make_client):
        """At senior tier, <script> is HTML-escaped and does not appear raw in output."""
        client = make_client("senior")
        resp = client.get("/challenges/xss", params={"q": "<script>alert(1)</script>"})
        assert resp.status_code == 200
        assert "<script>alert(1)</script>" not in resp.text

    def test_js_context_breakout_passes(self, make_client):
        """Single-quote breakout from JS string appears in the rendered page."""
        client = make_client("senior")
        payload = "';alert('XSS');//"
        resp = client.get("/challenges/xss", params={"q": payload})
        assert resp.status_code == 200
        # The payload should appear inside a <script> block
        assert "alert" in resp.text

    def test_xss_reflected_solves_at_senior(self, make_client, db):
        """JS string breakout payload solves xss_reflected at senior tier."""
        db.add(Challenge(key="xss_reflected", name="Alert('Ship It!')", category="A05 Injection"))
        db.commit()
        client = make_client("senior")
        payload = "';alert('XSS');//"
        resp = client.get("/challenges/xss", params={"q": payload})
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "xss_reflected").first()
        assert challenge.solved

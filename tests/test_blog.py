"""Tests for blog and stored XSS functionality."""

from __future__ import annotations

from app.db.seed import seed_users
from app.models.challenge import Challenge
from app.models.content import BlogPost


class TestBlogLoads:
    def test_blog_index(self, make_client, db):
        seed_users(db)
        client = make_client("intern")
        resp = client.get("/blog")
        assert resp.status_code == 200
        assert "Toxic Code Review" in resp.text

    def test_blog_shows_posts(self, make_client, db):
        seed_users(db)
        client = make_client("intern")
        resp = client.get("/blog")
        assert resp.status_code == 200
        assert "How We Built DeployBro" in resp.text


class TestBlogComments:
    def test_view_post(self, make_client, db):
        seed_users(db)
        client = make_client("intern")
        # Get first post
        post = db.query(BlogPost).first()
        assert post is not None
        resp = client.get(f"/blog/{post.id}")
        assert resp.status_code == 200
        assert post.title in resp.text

    def test_submit_comment(self, make_client, db):
        seed_users(db)
        client = make_client("intern")
        post = db.query(BlogPost).first()
        resp = client.post(
            f"/blog/{post.id}/comment",
            data={"author_name": "tester", "content": "Great post!"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert "tester" in resp.text

    def test_stored_xss_at_intern(self, make_client, db):
        """XSS payload is stored and rendered unsanitized at intern tier."""
        seed_users(db)
        db.add(Challenge(key="xss_stored", name="Toxic Code Review", category="A05 Injection"))
        db.commit()
        client = make_client("intern")
        post = db.query(BlogPost).first()
        xss_payload = '<script>alert("XSS")</script>'
        client.post(
            f"/blog/{post.id}/comment",
            data={"author_name": "hacker", "content": xss_payload},
            follow_redirects=False,
        )
        resp = client.get(f"/blog/{post.id}")
        assert resp.status_code == 200
        # At intern tier, the script tag should be present unsanitized
        assert "<script>" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "xss_stored").first()
        assert challenge.solved

    def test_stored_xss_at_junior_ontoggle_bypass(self, make_client, db):
        """Junior sanitizer strips script/common handlers but misses ontoggle; payload solves challenge."""
        seed_users(db)
        db.add(Challenge(key="xss_stored", name="Toxic Code Review", category="A05 Injection"))
        db.commit()
        client = make_client("junior")
        post = db.query(BlogPost).first()
        # ontoggle bypasses the junior blacklist
        xss_payload = "<details open ontoggle=\"alert('XSS')\">"
        client.post(
            f"/blog/{post.id}/comment",
            data={"author_name": "hacker", "content": xss_payload},
            follow_redirects=False,
        )
        challenge = db.query(Challenge).filter(Challenge.key == "xss_stored").first()
        assert challenge.solved

    def test_stored_xss_at_junior_svg_solves(self, make_client, db):
        """SVG tag is not in junior blacklist; submission with <svg solves the challenge."""
        seed_users(db)
        db.add(Challenge(key="xss_stored", name="Toxic Code Review", category="A05 Injection"))
        db.commit()
        client = make_client("junior")
        post = db.query(BlogPost).first()
        xss_payload = '<svg onload="alert(1)">'
        client.post(
            f"/blog/{post.id}/comment",
            data={"author_name": "hacker", "content": xss_payload},
            follow_redirects=False,
        )
        challenge = db.query(Challenge).filter(Challenge.key == "xss_stored").first()
        assert challenge.solved

    def test_stored_xss_at_senior_event_handler_bypass(self, make_client, db):
        """Senior sanitizer strips only <script> blocks; event handlers on other tags pass through."""
        seed_users(db)
        db.add(Challenge(key="xss_stored", name="Toxic Code Review", category="A05 Injection"))
        db.commit()
        client = make_client("senior")
        post = db.query(BlogPost).first()
        # Senior sanitizer only removes <script> blocks; onerror on <img> passes through
        xss_payload = '<img src=x onerror="alert(1)">'
        client.post(
            f"/blog/{post.id}/comment",
            data={"author_name": "hacker", "content": xss_payload},
            follow_redirects=False,
        )
        resp = client.get(f"/blog/{post.id}")
        assert resp.status_code == 200
        # Senior renders unsanitized event handler
        assert "onerror" in resp.text
        challenge = db.query(Challenge).filter(Challenge.key == "xss_stored").first()
        assert challenge.solved

    def test_stored_xss_script_stripped_at_senior(self, make_client, db):
        """Senior sanitizer removes <script> blocks; the script payload does not execute."""
        seed_users(db)
        client = make_client("senior")
        post = db.query(BlogPost).first()
        # Use a distinctive marker that would only appear if the script block survived
        xss_payload = '<script>alert("UNIQUEMARKER_XSS_BLOCK")</script>'
        client.post(
            f"/blog/{post.id}/comment",
            data={"author_name": "hacker", "content": xss_payload},
            follow_redirects=False,
        )
        resp = client.get(f"/blog/{post.id}")
        assert resp.status_code == 200
        # The script block content should not appear in rendered output
        assert "UNIQUEMARKER_XSS_BLOCK" not in resp.text

    def test_xss_stored_not_solved_at_tech_lead(self, make_client, db):
        """Script tag in comment at tech_lead does not solve the challenge."""
        seed_users(db)
        db.add(Challenge(key="xss_stored", name="Toxic Code Review", category="A05 Injection"))
        db.commit()
        client = make_client("tech_lead")
        post = db.query(BlogPost).first()
        xss_payload = '<script>alert("XSS")</script>'
        client.post(
            f"/blog/{post.id}/comment",
            data={"author_name": "hacker", "content": xss_payload},
            follow_redirects=False,
        )
        resp = client.get(f"/blog/{post.id}")
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "xss_stored").first()
        assert not challenge.solved

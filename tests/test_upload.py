"""Tests for file upload vulnerability module.

Proves dangerous file types are accepted at intern tier and rejected at tech_lead tier.
"""

from __future__ import annotations

import io

from app.models.challenge import Challenge


class TestUploadPageLoads:
    """Basic page load tests."""

    def test_upload_page_loads(self, client):
        resp = client.get("/challenges/upload")
        assert resp.status_code == 200
        assert "Ship to Production" in resp.text


class TestUploadIntern:
    """Intern tier: no file type validation, any upload accepted."""

    def test_upload_html_file(self, make_client, db):
        """Intern tier accepts .html files (potential webshell/XSS)."""
        db.add(Challenge(key="upload_webshell", name="Ship to Production Friday", category="A01 Broken Access"))
        db.commit()
        client = make_client("intern")
        payload = b"<script>alert('xss')</script>"
        resp = client.post(
            "/challenges/upload",
            files={"file": ("evil.html", io.BytesIO(payload), "text/html")},
        )
        assert resp.status_code == 200
        assert "evil.html" in resp.text or "success" in resp.text.lower()
        challenge = db.query(Challenge).filter(Challenge.key == "upload_webshell").first()
        assert challenge.solved

    def test_upload_python_file(self, make_client):
        """Intern tier accepts .py files (potential RCE)."""
        client = make_client("intern")
        payload = b"import os; os.system('whoami')"
        resp = client.post(
            "/challenges/upload",
            files={"file": ("shell.py", io.BytesIO(payload), "application/x-python")},
        )
        assert resp.status_code == 200
        assert "shell.py" in resp.text or "success" in resp.text.lower()

    def test_upload_normal_text(self, make_client):
        """Intern tier also accepts normal files."""
        client = make_client("intern")
        resp = client.post(
            "/challenges/upload",
            files={"file": ("readme.txt", io.BytesIO(b"hello world"), "text/plain")},
        )
        assert resp.status_code == 200


class TestUploadTechLead:
    """Tech lead tier: extension allowlist and magic byte validation."""

    def test_upload_html_blocked(self, make_client):
        """Tech lead tier rejects .html files."""
        client = make_client("tech_lead")
        payload = b"<script>alert('xss')</script>"
        resp = client.post(
            "/challenges/upload",
            files={"file": ("evil.html", io.BytesIO(payload), "text/html")},
        )
        assert resp.status_code == 200
        assert "not allowed" in resp.text.lower() or "error" in resp.text.lower()

    def test_upload_python_blocked(self, make_client):
        """Tech lead tier rejects .py files."""
        client = make_client("tech_lead")
        payload = b"import os"
        resp = client.post(
            "/challenges/upload",
            files={"file": ("shell.py", io.BytesIO(payload), "text/plain")},
        )
        assert resp.status_code == 200
        assert "not allowed" in resp.text.lower() or "error" in resp.text.lower()

    def test_upload_valid_txt_accepted(self, make_client):
        """Tech lead tier accepts .txt files (in the allowlist)."""
        client = make_client("tech_lead")
        resp = client.post(
            "/challenges/upload",
            files={"file": ("notes.txt", io.BytesIO(b"safe content"), "text/plain")},
        )
        assert resp.status_code == 200
        # Should succeed; no error about extension
        assert "not allowed" not in resp.text.lower()

    def test_upload_webshell_not_solved_at_tech_lead(self, make_client, db):
        """Tech lead tier blocks .html uploads; challenge not solved."""
        db.add(Challenge(key="upload_webshell", name="Ship to Production Friday", category="A01 Broken Access"))
        db.commit()
        client = make_client("tech_lead")
        payload = b"<script>alert('xss')</script>"
        client.post(
            "/challenges/upload",
            files={"file": ("evil.html", io.BytesIO(payload), "text/html")},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "upload_webshell").first()
        assert not challenge.solved


class TestUploadJunior:
    """Junior tier: extension blacklist blocks .py/.php but misses .html and .svg."""

    def test_py_blocked_by_blacklist(self, make_client):
        """.py is in the junior extension blacklist and is rejected."""
        client = make_client("junior")
        resp = client.post(
            "/challenges/upload",
            files={"file": ("shell.py", io.BytesIO(b"import os"), "text/plain")},
        )
        assert resp.status_code == 200
        assert "not allowed" in resp.text.lower() or "blocked" in resp.text.lower() or "error" in resp.text.lower()

    def test_html_not_in_blacklist(self, make_client):
        """.html is not in the junior extension blacklist and is accepted."""
        client = make_client("junior")
        resp = client.post(
            "/challenges/upload",
            files={"file": ("evil.html", io.BytesIO(b"<script>alert(1)</script>"), "text/html")},
        )
        assert resp.status_code == 200
        assert "not allowed" not in resp.text.lower()

    def test_upload_webshell_solves_at_junior(self, make_client, db):
        """.html upload at junior tier solves upload_webshell."""
        db.add(Challenge(key="upload_webshell", name="Ship to Production Friday", category="A01 Broken Access"))
        db.commit()
        client = make_client("junior")
        client.post(
            "/challenges/upload",
            files={"file": ("payload.html", io.BytesIO(b"<script>alert(1)</script>"), "text/html")},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "upload_webshell").first()
        assert challenge.solved


class TestUploadSenior:
    """Senior tier: extension allowlist; only .jpg/.jpeg/.png/.gif/.pdf/.txt accepted."""

    def test_html_blocked_by_allowlist(self, make_client):
        """.html is not in the senior extension allowlist and is rejected."""
        client = make_client("senior")
        resp = client.post(
            "/challenges/upload",
            files={"file": ("evil.html", io.BytesIO(b"<script>alert(1)</script>"), "text/html")},
        )
        assert resp.status_code == 200
        assert "not allowed" in resp.text.lower() or "error" in resp.text.lower()

    def test_jpg_upload_succeeds_at_senior(self, make_client):
        """.jpg is in the allowlist and is accepted at senior tier."""
        client = make_client("senior")
        resp = client.post(
            "/challenges/upload",
            files={"file": ("photo.jpg", io.BytesIO(b"\xff\xd8\xff" + b"fake image data"), "image/jpeg")},
        )
        assert resp.status_code == 200
        assert "not allowed" not in resp.text.lower()

    def test_upload_webshell_not_solved_at_senior(self, make_client, db):
        """Senior tier allowlist prevents dangerous extension upload; challenge not solved."""
        db.add(Challenge(key="upload_webshell", name="Ship to Production Friday", category="A01 Broken Access"))
        db.commit()
        client = make_client("senior")
        client.post(
            "/challenges/upload",
            files={"file": ("evil.html", io.BytesIO(b"<script>"), "text/html")},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "upload_webshell").first()
        assert not challenge.solved

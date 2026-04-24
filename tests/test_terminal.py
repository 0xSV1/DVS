"""Tests for the terminal (DeployBro Deployer) vulnerability module.

Proves credential leaks and command injection work at intern/junior tiers,
and all three challenges are mitigated at senior/tech_lead.
"""

from __future__ import annotations

from app.models.challenge import Challenge


class TestTerminalCredLeak:
    """terminal_cred_leak: sensitive file reads tracked via /exec endpoint."""

    def test_intern_cred_leak_credentials_json(self, make_client, db):
        """Reading credentials.json at intern tier triggers solve."""
        db.add(Challenge(key="terminal_cred_leak", name="deploybro secrets --dump", category="A02 Misconfig"))
        db.commit()
        client = make_client("intern")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "", "file_path": "/home/deploybro/.deploybro/credentials.json"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tracked"] is True
        assert data["challenge_key"] == "terminal_cred_leak"
        challenge = db.query(Challenge).filter(Challenge.key == "terminal_cred_leak").first()
        assert challenge.solved

    def test_intern_cred_leak_dotenv(self, make_client):
        """Reading .env at intern tier triggers solve."""
        client = make_client("intern")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "", "file_path": "/home/deploybro/projects/deploybro-app/.env"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tracked"] is True
        assert data["challenge_key"] == "terminal_cred_leak"

    def test_nonsensitive_file_not_tracked(self, make_client):
        """Reading a non-sensitive file does not trigger solve."""
        client = make_client("intern")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "", "file_path": "/home/deploybro/.bashrc"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tracked"] is False

    def test_filesystem_contains_secrets_at_intern(self, make_client):
        """Intern filesystem JSON includes plaintext credentials."""
        client = make_client("intern")
        resp = client.get("/challenges/terminal")
        assert resp.status_code == 200
        assert "AKIAIOSFODNN7DEPLOYBRO" in resp.text

    def test_filesystem_redacted_at_tech_lead(self, make_client):
        """Tech lead filesystem JSON has redacted credentials."""
        client = make_client("tech_lead")
        resp = client.get("/challenges/terminal")
        assert resp.status_code == 200
        assert "AKIAIOSFODNN7DEPLOYBRO" not in resp.text
        assert "REDACTED" in resp.text


class TestTerminalCredLeakTierGuards:
    """Verify cred_leak challenge cannot be solved by reading redacted files."""

    def test_cred_leak_not_solved_at_senior(self, make_client, db):
        """Senior filesystem has redacted credentials; reading it does not solve the challenge."""
        db.add(Challenge(key="terminal_cred_leak", name="deploybro secrets --dump", category="A02 Misconfig"))
        db.commit()
        client = make_client("senior")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"file_path": "/home/deploybro/.deploybro/credentials.json"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tracked"] is True
        challenge = db.query(Challenge).filter(Challenge.key == "terminal_cred_leak").first()
        assert not challenge.solved

    def test_cred_leak_not_solved_at_tech_lead(self, make_client, db):
        """Tech lead filesystem has fully redacted credentials; reading it does not solve the challenge."""
        db.add(Challenge(key="terminal_cred_leak", name="deploybro secrets --dump", category="A02 Misconfig"))
        db.commit()
        client = make_client("tech_lead")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"file_path": "/home/deploybro/.deploybro/credentials.json"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tracked"] is True
        challenge = db.query(Challenge).filter(Challenge.key == "terminal_cred_leak").first()
        assert not challenge.solved

    def test_cred_leak_junior_dotenv_solves(self, make_client, db):
        """Junior tier still has real .env content; reading it solves the challenge."""
        db.add(Challenge(key="terminal_cred_leak", name="deploybro secrets --dump", category="A02 Misconfig"))
        db.commit()
        client = make_client("junior")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"file_path": "/home/deploybro/projects/deploybro-app/.env"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tracked"] is True
        challenge = db.query(Challenge).filter(Challenge.key == "terminal_cred_leak").first()
        assert challenge.solved


class TestTerminalCmdInject:
    """terminal_cmd_inject: command injection via deploybro pipeline."""

    def test_intern_injection_succeeds(self, make_client, db):
        """Intern tier: shell metacharacters in branch name trigger solve."""
        db.add(
            Challenge(key="terminal_cmd_inject", name="deploybro push --payload $(whoami)", category="A05 Injection")
        )
        db.commit()
        client = make_client("intern")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": 'deploybro pipeline run --branch "$(whoami)"'},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["output"]
        assert not data["error"]
        # The handler returns solved=terminal_cmd_inject for injection payloads
        # Verify by checking the output mentions injection
        assert "injection" in data["output"].lower() or "shell" in data["output"].lower()
        challenge = db.query(Challenge).filter(Challenge.key == "terminal_cmd_inject").first()
        assert challenge.solved

    def test_junior_injection_succeeds(self, make_client):
        """Junior tier: injection still works but with warning."""
        client = make_client("junior")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "deploybro pipeline run --branch ;id"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "suspicious" in data["output"].lower() or "warning" in data["output"].lower()

    def test_senior_injection_blocked(self, make_client):
        """Senior tier: branch name validated, injection rejected."""
        client = make_client("senior")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "deploybro pipeline run --branch ;id"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["error"] is True
        assert "invalid" in data["output"].lower()

    def test_tech_lead_injection_blocked(self, make_client):
        """Tech lead tier: strict allowlist rejects metacharacters."""
        client = make_client("tech_lead")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "deploybro pipeline run --branch $(whoami)"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["error"] is True

    def test_normal_branch_works(self, make_client):
        """Normal branch name accepted at all tiers."""
        for difficulty in ("intern", "junior", "senior", "tech_lead"):
            client = make_client(difficulty)
            resp = client.post(
                "/challenges/terminal/exec",
                json={"command": "deploybro pipeline run --branch feat/new-feature"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert not data["error"], f"Normal branch rejected at {difficulty}"


class TestTerminalPrivesc:
    """terminal_privesc: privilege escalation via deploybro auth escalate."""

    def test_intern_escalation_succeeds(self, make_client, db):
        """Intern tier: auth escalate listed in help and works."""
        db.add(Challenge(key="terminal_privesc", name="chmod 777 /etc/deploybro/motd", category="A01 Broken Access"))
        db.commit()
        client = make_client("intern")

        # Help output includes escalate command
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "deploybro help"},
        )
        assert resp.status_code == 200
        assert "escalate" in resp.json()["output"].lower()

        # Escalation succeeds
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "deploybro auth escalate"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "admin" in data["output"].lower()
        assert not data["error"]
        challenge = db.query(Challenge).filter(Challenge.key == "terminal_privesc").first()
        assert challenge.solved

    def test_junior_escalation_succeeds(self, make_client):
        """Junior tier: escalate not in help but still works."""
        client = make_client("junior")

        # Help does NOT list escalate
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "deploybro help"},
        )
        assert resp.status_code == 200
        assert "escalate" not in resp.json()["output"]

        # But the command still works
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "deploybro auth escalate"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "admin" in data["output"].lower()

    def test_senior_escalation_blocked(self, make_client):
        """Senior tier: escalate command returns unknown."""
        client = make_client("senior")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "deploybro auth escalate"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["error"] is True
        assert "admin" not in data["output"].lower() or "unknown" in data["output"].lower()

    def test_tech_lead_escalation_blocked(self, make_client):
        """Tech lead tier: escalate command denied."""
        client = make_client("tech_lead")
        resp = client.post(
            "/challenges/terminal/exec",
            json={"command": "deploybro auth escalate"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["error"] is True
        assert "denied" in data["output"].lower() or "permission" in data["output"].lower()

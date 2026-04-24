"""Tests for SSTI vulnerability module.

Proves template injection works at intern tier and is blocked at tech_lead.
Tests ssti_basic (expression evaluation) and ssti_rce (class traversal) solve detection.
"""

from __future__ import annotations

from app.models.challenge import Challenge


def _seed_challenges(db):
    """Insert SSTI challenge entries."""
    db.add(Challenge(key="ssti_basic", name="Server-Side Template Injection", category="A05 Injection"))
    db.add(Challenge(key="ssti_rce", name="SSTI to RCE", category="A05 Injection"))
    db.commit()


class TestSstiIntern:
    """Intern tier: raw Jinja2 from_string, fully exploitable."""

    def test_basic_expression(self, make_client):
        """{{7*7}} should evaluate to 49."""
        client = make_client("intern")
        resp = client.get("/challenges/ssti", params={"name": "{{7*7}}"})
        assert resp.status_code == 200
        assert "49" in resp.text

    def test_config_access(self, make_client):
        """Access to config object via template context."""
        client = make_client("intern")
        resp = client.get("/challenges/ssti", params={"name": "{{config}}"})
        assert resp.status_code == 200


class TestSstiBasicSolve:
    """ssti_basic challenge: expression evaluation triggers solve."""

    def test_ssti_basic_solved_at_intern(self, make_client, db):
        """Intern tier: {{7*7}} evaluates and solves ssti_basic."""
        _seed_challenges(db)
        client = make_client("intern")
        client.get("/challenges/ssti", params={"name": "{{7*7}}"})
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_basic").first()
        assert challenge.solved

    def test_ssti_basic_not_solved_at_tech_lead(self, make_client, db):
        """Tech lead tier: expression does not evaluate, challenge not solved."""
        _seed_challenges(db)
        client = make_client("tech_lead")
        client.get("/challenges/ssti", params={"name": "{{7*7}}"})
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_basic").first()
        assert not challenge.solved


class TestSstiRceSolve:
    """ssti_rce challenge: class traversal pattern triggers solve."""

    def test_ssti_rce_solved_at_intern(self, make_client, db):
        """Intern tier: __class__ traversal payload solves ssti_rce."""
        _seed_challenges(db)
        client = make_client("intern")
        client.get(
            "/challenges/ssti",
            params={"name": "{{''.__class__.__subclasses__()}}"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_rce").first()
        assert challenge.solved

    def test_ssti_rce_not_solved_with_benign_input(self, make_client, db):
        """Benign input does not solve ssti_rce."""
        _seed_challenges(db)
        client = make_client("intern")
        client.get("/challenges/ssti", params={"name": "hello"})
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_rce").first()
        assert not challenge.solved


class TestSstiTechLead:
    """Tech lead tier: HTML escaped, no template evaluation."""

    def test_expression_literal(self, make_client):
        """{{7*7}} should appear as literal text, not 49."""
        client = make_client("tech_lead")
        resp = client.get("/challenges/ssti", params={"name": "{{7*7}}"})
        assert resp.status_code == 200
        # Should be HTML-escaped or rendered as literal
        assert "49" not in resp.text


class TestSstiJunior:
    """Junior tier: keyword blacklist blocks config/os/eval but misses Python MRO traversal."""

    def test_basic_expression_works_at_junior(self, make_client):
        """{{7*7}} evaluates to 49; arithmetic is not blacklisted."""
        client = make_client("junior")
        resp = client.get("/challenges/ssti", params={"name": "{{7*7}}"})
        assert resp.status_code == 200
        assert "49" in resp.text

    def test_class_traversal_not_blocked(self, make_client):
        """__class__ is not in the junior keyword blacklist."""
        client = make_client("junior")
        resp = client.get("/challenges/ssti", params={"name": "{{''.__class__}}"})
        assert resp.status_code == 200

    def test_ssti_basic_solves_at_junior(self, make_client, db):
        """{{7*7}} evaluates to 49 at junior tier; ssti_basic solve triggers."""
        _seed_challenges(db)
        client = make_client("junior")
        client.get("/challenges/ssti", params={"name": "{{7*7}}"})
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_basic").first()
        assert challenge.solved

    def test_ssti_rce_solves_at_junior(self, make_client, db):
        """__class__.__mro__ traversal triggers ssti_rce solve at junior tier."""
        _seed_challenges(db)
        client = make_client("junior")
        client.get(
            "/challenges/ssti",
            params={"name": "{{''.__class__.__mro__[1].__subclasses__()}}"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_rce").first()
        assert challenge.solved

    def test_config_keyword_blocked_at_junior(self, make_client):
        """'config' is in the junior blacklist; input containing it returns a blocked message."""
        client = make_client("junior")
        resp = client.get("/challenges/ssti", params={"name": "{{config}}"})
        assert resp.status_code == 200
        assert "Blocked" in resp.text
        assert "config" in resp.text.lower()


class TestSstiSenior:
    """Senior tier: SandboxedEnvironment allows math but blocks dangerous operations."""

    def test_basic_expression_works_at_senior(self, make_client):
        """{{7*7}} still evaluates to 49 inside the Jinja2 sandbox."""
        client = make_client("senior")
        resp = client.get("/challenges/ssti", params={"name": "{{7*7}}"})
        assert resp.status_code == 200
        assert "49" in resp.text

    def test_ssti_basic_solves_at_senior(self, make_client, db):
        """Math expression produces 49 in sandbox output; ssti_basic solve triggers."""
        _seed_challenges(db)
        client = make_client("senior")
        client.get("/challenges/ssti", params={"name": "{{7*7}}"})
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_basic").first()
        assert challenge.solved

    def test_ssti_rce_solve_triggers_at_senior(self, make_client, db):
        """Solve condition checks input pattern, not output; triggers at senior despite sandbox."""
        _seed_challenges(db)
        client = make_client("senior")
        client.get(
            "/challenges/ssti",
            params={"name": "{{''.__class__.__mro__[1].__subclasses__()}}"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_rce").first()
        assert challenge.solved

    def test_ssti_rce_not_solved_at_tech_lead(self, make_client, db):
        """tech_lead is excluded from ssti_rce solve condition."""
        _seed_challenges(db)
        client = make_client("tech_lead")
        client.get(
            "/challenges/ssti",
            params={"name": "{{''.__class__.__mro__[1].__subclasses__()}}"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_rce").first()
        assert not challenge.solved

    def test_sandbox_blocks_class_traversal_output(self, make_client, db):
        """SandboxedEnvironment raises SecurityError on full class traversal.

        Single-step attribute access ({{''.__class__}}) is silently suppressed to
        empty string by the sandbox. Chained traversal (.__class__.__mro__...) raises
        SecurityError, which the handler catches and returns as "Sandbox blocked ...".

        Design note: ssti_rce solve fires on the INPUT pattern, not the output.
        The attacker demonstrated knowledge of the technique even though the sandbox
        prevented actual RCE. This test verifies both halves of that contract.
        """
        _seed_challenges(db)
        client = make_client("senior")
        resp = client.get(
            "/challenges/ssti",
            params={"name": "{{''.__class__.__mro__[1].__subclasses__()}}"},
        )
        assert resp.status_code == 200
        # Sandbox raises SecurityError on chained traversal; handler surfaces it
        assert "Sandbox blocked" in resp.text
        # ssti_rce solve triggers on __class__ in input despite sandbox blocking output
        challenge = db.query(Challenge).filter(Challenge.key == "ssti_rce").first()
        assert challenge.solved

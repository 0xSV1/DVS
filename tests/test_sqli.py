"""Tests for SQLi vulnerability module.

Proves injection works at intern/junior tiers and is mitigated at senior/tech_lead.
"""

from __future__ import annotations

from app.models.challenge import Challenge
from app.models.product import Product


def _seed_products(client, db):
    """Insert test products into the database."""
    from tests.conftest import TestSessionLocal

    session = TestSessionLocal()
    products = [
        Product(name="Widget Alpha", description="A great widget", price=9.99),
        Product(name="Widget Beta", description="Another widget", price=19.99),
        Product(name="Gadget Gamma", description="Not a widget", price=29.99),
        Product(name="Doohickey Delta", description="Something else", price=39.99),
    ]
    for p in products:
        session.add(p)
    session.commit()
    session.close()


class TestSqliIntern:
    """Intern tier: raw f-string SQL, fully exploitable."""

    def test_normal_search(self, make_client):
        client = make_client("intern")
        _seed_products(client, None)
        resp = client.get("/challenges/sqli", params={"query": "Widget"})
        assert resp.status_code == 200
        assert "Widget Alpha" in resp.text

    def test_sqli_or_1_eq_1(self, make_client):
        """Classic OR 1=1 injection returns all products."""
        client = make_client("intern")
        _seed_products(client, None)
        resp = client.get("/challenges/sqli", params={"query": "' OR 1=1 --"})
        assert resp.status_code == 200
        # Should return all 4 products via injection
        assert "Widget Alpha" in resp.text
        assert "Doohickey Delta" in resp.text

    def test_sqli_union_select(self, make_client):
        """UNION injection to extract table names."""
        client = make_client("intern")
        _seed_products(client, None)
        resp = client.get(
            "/challenges/sqli",
            params={"query": "' UNION SELECT 1,name,sql,4 FROM sqlite_master --"},
        )
        assert resp.status_code == 200

    def test_sqli_search_solves(self, make_client, db):
        """UNION injection returning >4 results solves sqli_search."""
        _seed_products(None, None)
        db.add(Challenge(key="sqli_search", name="SELECT * FROM Funding", category="A05 Injection"))
        db.commit()
        client = make_client("intern")
        resp = client.get("/challenges/sqli", params={"query": "' UNION SELECT 1,2,3,4 --"})
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "sqli_search").first()
        assert challenge.solved


class TestSqliTechLead:
    """Tech lead tier: parameterized queries, injection should fail."""

    def test_injection_fails(self, make_client):
        """SQL injection payload returns no extra results."""
        client = make_client("tech_lead")
        _seed_products(client, None)
        resp = client.get("/challenges/sqli", params={"query": "' OR 1=1 --"})
        assert resp.status_code == 200
        # Injection treated as literal text, should match nothing
        assert "Widget Alpha" not in resp.text or "Doohickey Delta" not in resp.text

    def test_normal_search_still_works(self, make_client):
        client = make_client("tech_lead")
        _seed_products(client, None)
        resp = client.get("/challenges/sqli", params={"query": "Widget"})
        assert resp.status_code == 200
        assert "Widget" in resp.text


class TestSqliBlind:
    """sqli_blind challenge: boolean-based injection in username check."""

    def test_blind_sqli_solves_at_intern(self, make_client, db):
        """Intern tier: boolean injection pattern solves the challenge."""
        db.add(Challenge(key="sqli_blind", name="The Billion Dollar Pivot", category="A05 Injection"))
        db.commit()
        client = make_client("intern")
        resp = client.get(
            "/challenges/sqli/check-username",
            params={"username": "admin' OR 1=1 --"},
        )
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "sqli_blind").first()
        assert challenge.solved

    def test_blind_sqli_benign_no_solve(self, make_client, db):
        """Benign username does not trigger solve."""
        db.add(Challenge(key="sqli_blind", name="The Billion Dollar Pivot", category="A05 Injection"))
        db.commit()
        client = make_client("intern")
        client.get(
            "/challenges/sqli/check-username",
            params={"username": "normaluser"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "sqli_blind").first()
        assert not challenge.solved


class TestSqliJunior:
    """Junior tier: case-sensitive keyword blacklist, bypassable with mixed case."""

    def test_mixed_case_bypasses_blacklist(self, make_client):
        """'Or' (mixed case) is not in the blacklist and returns all products."""
        from tests.test_sqli import _seed_products

        client = make_client("junior")
        _seed_products(client, None)
        resp = client.get("/challenges/sqli", params={"query": "' Or 1=1 --"})
        assert resp.status_code == 200
        assert "Widget Alpha" in resp.text
        assert "Doohickey Delta" in resp.text

    def test_uppercase_or_is_blocked(self, make_client):
        """Uppercase 'OR' is in the blacklist and returns no extra results."""
        from tests.test_sqli import _seed_products

        client = make_client("junior")
        _seed_products(client, None)
        resp = client.get("/challenges/sqli", params={"query": "' OR 1=1 --"})
        assert resp.status_code == 200
        # Blocked input: should not return all 4 products
        assert not ("Widget Alpha" in resp.text and "Doohickey Delta" in resp.text)

    def test_sqli_search_solves_at_junior(self, make_client, db):
        """Mixed-case UNION injection bypasses blacklist and returns >4 results, solving sqli_search."""
        from tests.test_sqli import _seed_products

        _seed_products(None, None)
        db.add(Challenge(key="sqli_search", name="SELECT * FROM Funding", category="A05 Injection"))
        db.commit()
        client = make_client("junior")
        # "UnIoN" and "SeLeCt" are not in the case-sensitive blacklist; adds a synthetic 5th row
        resp = client.get("/challenges/sqli", params={"query": "' UnIoN SeLeCt 1,2,3,4 --"})
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "sqli_search").first()
        assert challenge.solved


class TestSqliSenior:
    """Senior tier: ORM-based queries, injection fails entirely."""

    def test_injection_fails_orm(self, make_client):
        """ORM parameterized queries make OR injection ineffective."""
        from tests.test_sqli import _seed_products

        client = make_client("senior")
        _seed_products(client, None)
        resp = client.get("/challenges/sqli", params={"query": "' OR 1=1 --"})
        assert resp.status_code == 200
        assert not ("Widget Alpha" in resp.text and "Doohickey Delta" in resp.text)

    def test_normal_search_works_at_senior(self, make_client):
        """Legitimate search still returns results at senior tier."""
        from tests.test_sqli import _seed_products

        client = make_client("senior")
        _seed_products(client, None)
        resp = client.get("/challenges/sqli", params={"query": "Widget"})
        assert resp.status_code == 200
        assert "Widget" in resp.text


class TestSqliBlindTiers:
    """sqli_blind: tier-gated solve condition (intern/junior only)."""

    def test_blind_sqli_solves_at_junior(self, make_client, db):
        """Junior tier: boolean injection pattern solves sqli_blind."""
        db.add(Challenge(key="sqli_blind", name="The Billion Dollar Pivot", category="A05 Injection"))
        db.commit()
        client = make_client("junior")
        resp = client.get(
            "/challenges/sqli/check-username",
            params={"username": "admin' Or 1=1 --"},
        )
        assert resp.status_code == 200
        challenge = db.query(Challenge).filter(Challenge.key == "sqli_blind").first()
        assert challenge.solved

    def test_blind_sqli_not_solved_at_senior(self, make_client, db):
        """Senior tier: solve condition excludes senior; injection does not solve sqli_blind."""
        db.add(Challenge(key="sqli_blind", name="The Billion Dollar Pivot", category="A05 Injection"))
        db.commit()
        client = make_client("senior")
        client.get(
            "/challenges/sqli/check-username",
            params={"username": "admin' OR 1=1 --"},
        )
        challenge = db.query(Challenge).filter(Challenge.key == "sqli_blind").first()
        assert not challenge.solved

"""Tests for MITRE ATLAS and itsbroken.ai FORGE challenge mappings."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ATLAS_ID_PATTERN = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")

FORGE_CATEGORIES = {
    "Reconnaissance",
    "Prompt Injection",
    "RAG Pipeline Attacks",
    "Agent & MCP Attacks",
    "Adversarial ML",
    "Evasion Techniques",
    "Infrastructure",
    "Tools & Reference",
}

CHALLENGES_YAML = Path(__file__).parent.parent / "data" / "challenges.yml"


@pytest.fixture(scope="module")
def challenges() -> list[dict]:
    data = yaml.safe_load(CHALLENGES_YAML.read_text(encoding="utf-8"))
    return data.get("challenges", [])


@pytest.fixture(scope="module")
def llm_challenges(challenges: list[dict]) -> list[dict]:
    return [c for c in challenges if c.get("category", "").startswith("LLM")]


class TestMappingCoverage:
    def test_every_llm_challenge_has_atlas_mapping(self, llm_challenges: list[dict]) -> None:
        unmapped = [c["key"] for c in llm_challenges if not c.get("mitre_atlas")]
        assert not unmapped, f"LLM challenges missing ATLAS mapping: {unmapped}"

    def test_every_llm_challenge_has_forge_mapping(self, llm_challenges: list[dict]) -> None:
        unmapped = [c["key"] for c in llm_challenges if not c.get("forge")]
        assert not unmapped, f"LLM challenges missing FORGE mapping: {unmapped}"


class TestMappingFormat:
    def test_atlas_ids_match_pattern(self, llm_challenges: list[dict]) -> None:
        for c in llm_challenges:
            for entry in c.get("mitre_atlas", []):
                assert ATLAS_ID_PATTERN.match(entry["id"]), f"Challenge {c['key']} has invalid ATLAS ID: {entry['id']}"
                assert entry.get("name"), f"Challenge {c['key']} ATLAS entry missing name"

    def test_forge_categories_are_in_known_set(self, llm_challenges: list[dict]) -> None:
        for c in llm_challenges:
            forge = c.get("forge", {})
            assert forge.get("category") in FORGE_CATEGORIES, (
                f"Challenge {c['key']} has unknown FORGE category: {forge.get('category')}"
            )
            assert forge.get("technique"), f"Challenge {c['key']} FORGE entry missing technique"


class TestExplainEndpoint:
    def test_llm_challenge_explain_returns_mappings(self, client) -> None:
        resp = client.get("/api/challenges/llm_prompt_inject/explain")
        assert resp.status_code == 200
        data = resp.json()

        assert data["challenge_url"] == "/challenges/llm/llm_prompt_inject"
        assert data["walkthrough_url"] == (
            "https://github.com/0xSV1/DVS/blob/main/docs/walkthroughs/18-llm-prompt-injection.md"
        )
        assert data["mitre_atlas"], "ATLAS mapping missing from explain payload"
        entry = data["mitre_atlas"][0]
        assert entry["id"] == "AML.T0051.000"
        assert entry["name"] == "LLM Prompt Injection: Direct"
        assert entry["url"] == "https://atlas.mitre.org/techniques/AML.T0051/"

        assert data["forge"], "FORGE mapping missing from explain payload"
        assert data["forge"]["category"] == "Prompt Injection"
        assert data["forge"]["technique"] == "Direct instruction override"
        assert data["forge"]["url"] == "https://itsbroken.ai/cheatsheet/"

    def test_sub_technique_url_strips_suffix(self, client) -> None:
        resp = client.get("/api/challenges/llm_indirect_inject/explain")
        assert resp.status_code == 200
        data = resp.json()

        assert data["mitre_atlas"][0]["id"] == "AML.T0051.001"
        assert data["mitre_atlas"][0]["url"] == "https://atlas.mitre.org/techniques/AML.T0051/"

    def test_owasp_challenge_has_empty_mappings(self, client) -> None:
        resp = client.get("/api/challenges/sqli_search/explain")
        assert resp.status_code == 200
        data = resp.json()

        assert data["challenge_url"] == "/challenges/sqli"
        assert (
            data["walkthrough_url"] == "https://github.com/0xSV1/DVS/blob/main/docs/walkthroughs/01-injection-sqli.md"
        )
        assert data["mitre_atlas"] == []
        assert data["forge"] is None

"""E2E registry: YAML integrity, flag generation, and challenge page loads.

Verifies that every challenge in challenges.yml is complete and internally
consistent, that flag generation is deterministic, and that every challenge
page returns HTTP 200 at every difficulty tier.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from app.api.routes.challenges import CHALLENGE_ROUTES
from app.core.challenge_utils import generate_flag

CHALLENGES_YAML_PATH = Path(__file__).parent.parent / "data" / "challenges.yml"

REQUIRED_FIELDS = {
    "key",
    "name",
    "category",
    "difficulty",
    "cwe",
    "description",
    "hint",
    "owasp_url",
    "min_difficulty",
    "tags",
    "explain",
}
VALID_DIFFICULTIES = {1, 2, 3, 4}
VALID_MIN_DIFFICULTIES = {"intern", "junior", "senior", "tech_lead"}
EXPECTED_CHALLENGE_COUNT = 55


def _load_challenges() -> list[dict]:
    with CHALLENGES_YAML_PATH.open() as f:
        data = yaml.safe_load(f)
    return data["challenges"]


class TestChallengeYaml:
    """Validate that challenges.yml is complete and internally consistent."""

    def test_challenge_count(self):
        """Exact challenge count guards against accidental additions or deletions."""
        challenges = _load_challenges()
        assert len(challenges) == EXPECTED_CHALLENGE_COUNT, (
            f"Expected {EXPECTED_CHALLENGE_COUNT} challenges, got {len(challenges)}. "
            "Update EXPECTED_CHALLENGE_COUNT if this is intentional."
        )

    def test_no_duplicate_keys(self):
        challenges = _load_challenges()
        keys = [c["key"] for c in challenges]
        seen: set[str] = set()
        dupes = [k for k in keys if k in seen or seen.add(k)]  # type: ignore[func-returns-value]
        assert not dupes, f"Duplicate challenge keys: {dupes}"

    def test_all_challenges_have_required_fields(self):
        challenges = _load_challenges()
        for ch in challenges:
            key = ch.get("key", "<no-key>")
            missing = REQUIRED_FIELDS - ch.keys()
            assert not missing, f"Challenge '{key}' missing fields: {missing}"
            explain = ch.get("explain", {})
            assert "intern" in explain, f"Challenge '{key}' explain block missing 'intern'"
            assert "fix" in explain, f"Challenge '{key}' explain block missing 'fix'"

    def test_difficulty_values_valid(self):
        challenges = _load_challenges()
        for ch in challenges:
            key = ch["key"]
            assert ch["difficulty"] in VALID_DIFFICULTIES, (
                f"Challenge '{key}' has invalid difficulty {ch['difficulty']!r}"
            )
            assert ch["min_difficulty"] in VALID_MIN_DIFFICULTIES, (
                f"Challenge '{key}' has invalid min_difficulty {ch['min_difficulty']!r}"
            )

    def test_all_keys_have_routes(self):
        challenges = _load_challenges()
        for ch in challenges:
            key = ch["key"]
            assert key in CHALLENGE_ROUTES, f"Challenge '{key}' has no entry in CHALLENGE_ROUTES"

    def test_descriptions_nonempty(self):
        challenges = _load_challenges()
        for ch in challenges:
            key = ch["key"]
            assert ch.get("description", "").strip(), f"Challenge '{key}' has empty description"

    def test_hints_nonempty(self):
        challenges = _load_challenges()
        for ch in challenges:
            key = ch["key"]
            assert ch.get("hint", "").strip(), f"Challenge '{key}' has empty hint"


class TestFlagGeneration:
    """Verify the HMAC-SHA256 flag derivation is correct and deterministic."""

    def test_flag_format(self):
        flag = generate_flag("sqli_search")
        assert flag.startswith("DVS{"), f"Flag does not start with DVS{{: {flag}"
        assert re.match(r"^DVS\{[0-9a-f]{64}\}$", flag), f"Unexpected flag format: {flag}"

    def test_flag_deterministic(self):
        """Same CTF_KEY and challenge_key must always produce the same flag."""
        assert generate_flag("test_key") == generate_flag("test_key")

    def test_flag_differs_per_challenge(self):
        """Every challenge key must produce a unique flag."""
        keys = ["sqli_search", "sqli_login", "xss_reflected", "idor_profile", "ssti_basic"]
        flags = [generate_flag(k) for k in keys]
        assert len(flags) == len(set(flags)), "Different challenge keys produced duplicate flags"


# Distinct non-LLM, non-terminal, non-source URLs from CHALLENGE_ROUTES.
# Deduplicated; multiple keys may share a URL (e.g. sqli_search and sqli_login).
_NON_LLM_URLS: list[str] = list(
    dict.fromkeys(
        v
        for k, v in CHALLENGE_ROUTES.items()
        if not k.startswith("llm_") and not k.startswith("terminal_") and k != "view_source_puzzle"
    )
)

# LLM challenge keys to load via /challenges/llm/{key}
_LLM_KEYS: list[str] = [k for k in CHALLENGE_ROUTES if k.startswith("llm_")]


class TestChallengePagesLoad:
    """Every challenge URL must return HTTP 200 at every difficulty tier."""

    @pytest.mark.parametrize("tier", ["intern", "junior", "senior", "tech_lead"])
    def test_owasp_challenge_pages_load(self, make_client, tier):
        client = make_client(tier)
        failures: list[str] = []
        for url in _NON_LLM_URLS:
            resp = client.get(url)
            if resp.status_code != 200:
                failures.append(f"{url} -> {resp.status_code}")
        assert not failures, "Page load failures at tier '{}':{}".format(tier, "\n  " + "\n  ".join(failures))

    @pytest.mark.parametrize("tier", ["intern", "junior", "senior", "tech_lead"])
    def test_llm_challenge_pages_load(self, make_client, tier):
        client = make_client(tier)
        failures: list[str] = []
        for key in _LLM_KEYS:
            url = CHALLENGE_ROUTES[key]
            resp = client.get(url)
            if resp.status_code != 200:
                failures.append(f"{key} ({url}) -> {resp.status_code}")
        assert not failures, "LLM page load failures at tier '{}':{}".format(tier, "\n  " + "\n  ".join(failures))

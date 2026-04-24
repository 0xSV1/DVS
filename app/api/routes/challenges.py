"""Challenge listing and scoreboard routes."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.constants import DIFFICULTY_LABELS, SCORING
from app.models.challenge import Challenge
from app.models.user import User

router = APIRouter()

ATLAS_BASE_URL = "https://atlas.mitre.org/techniques/"
FORGE_CHEATSHEET_URL = "https://itsbroken.ai/cheatsheet/"
GITHUB_WALKTHROUGHS_URL = "https://github.com/0xSV1/DVS/blob/main/docs/walkthroughs/"


def _atlas_entry_url(technique_id: str) -> str:
    """Strip sub-technique suffix (e.g. AML.T0051.000 -> AML.T0051) for the ATLAS URL."""
    base = technique_id.split(".")
    if len(base) >= 2:
        return f"{ATLAS_BASE_URL}{base[0]}.{base[1]}/"
    return ATLAS_BASE_URL


def _walkthrough_url(slug: str) -> str:
    return f"{GITHUB_WALKTHROUGHS_URL}{slug}.md" if slug else ""


# Maps challenge keys to their URL paths
CHALLENGE_ROUTES = {
    "sqli_search": "/challenges/sqli",
    "sqli_login": "/challenges/sqli",
    "sqli_blind": "/challenges/sqli/blind",
    "xss_reflected": "/challenges/xss",
    "xss_stored": "/blog",
    "xss_dom": "/challenges/xss/dom",
    "idor_profile": "/challenges/idor",
    "idor_order": "/challenges/idor",
    "idor_admin": "/challenges/idor",
    "ssti_basic": "/challenges/ssti",
    "ssti_rce": "/challenges/ssti",
    "auth_weak_pw": "/challenges/auth",
    "auth_jwt_none": "/challenges/auth",
    "auth_jwt_weak": "/challenges/auth",
    "misconfig_debug": "/challenges/misconfig",
    "misconfig_cors": "/challenges/misconfig",
    "upload_webshell": "/challenges/upload",
    "info_disclosure": "/challenges/misconfig",
    "llm_prompt_inject": "/challenges/llm/llm_prompt_inject",
    "llm_jailbreak": "/challenges/llm/llm_jailbreak",
    "llm_indirect_inject": "/challenges/llm/llm_indirect_inject",
    "llm_system_leak": "/challenges/llm/llm_system_leak",
    "llm_xss_output": "/challenges/llm/llm_xss_output",
    "llm_excessive_agency": "/challenges/llm/llm_excessive_agency",
    "llm_data_leak": "/challenges/llm/llm_data_leak",
    "llm_dos": "/challenges/llm/llm_dos",
    "llm_prompt_inject_multi": "/challenges/llm/llm_prompt_inject_multi",
    "llm_system_leak_encoding": "/challenges/llm/llm_system_leak_encoding",
    "llm_pii_inference": "/challenges/llm/llm_pii_inference",
    "llm_data_poisoning": "/challenges/llm/llm_data_poisoning",
    "llm_data_poisoning_recommend": "/challenges/llm/llm_data_poisoning_recommend",
    "llm_output_sqli": "/challenges/llm/llm_output_sqli",
    "llm_output_ssrf": "/challenges/llm/llm_output_ssrf",
    "llm_excessive_agency_escalation": "/challenges/llm/llm_excessive_agency_escalation",
    "llm_excessive_agency_chain": "/challenges/llm/llm_excessive_agency_chain",
    "llm_misinfo_authority": "/challenges/llm/llm_misinfo_authority",
    "llm_misinfo_hallucination": "/challenges/llm/llm_misinfo_hallucination",
    "llm_dos_context": "/challenges/llm/llm_dos_context",
    "llm_supply_chain_model": "/challenges/llm/llm_supply_chain_model",
    "llm_supply_chain_plugin": "/challenges/llm/llm_supply_chain_plugin",
    "llm_vector_poisoning": "/challenges/llm/llm_vector_poisoning",
    "llm_vector_extraction": "/challenges/llm/llm_vector_extraction",
    "ssrf_internal": "/challenges/ssrf",
    "csrf_transfer": "/challenges/csrf",
    "deserialize_pickle": "/challenges/deserialize",
    "crypto_md5": "/challenges/crypto",
    "crypto_hardcoded_secret": "/challenges/crypto/secrets",
    "mass_assign": "/challenges/mass-assign",
    "open_redirect": "/challenges/open-redirect",
    "broken_logging": "/challenges/logging",
    "log_injection": "/challenges/log-injection",
    "terminal_cred_leak": "/challenges/terminal",
    "terminal_cmd_inject": "/challenges/terminal",
    "terminal_privesc": "/challenges/terminal",
    "view_source_puzzle": "/source",
}

DIFFICULTY_STARS = {1: "1", 2: "2", 3: "3", 4: "4"}

# High-level challenge groups: slug -> (display name, category prefix, landing url)
CHALLENGE_GROUPS = {
    "owasp": {
        "name": "OWASP Top 10",
        "prefix": "A0",
        "url": "/challenges/owasp",
    },
    "llm": {
        "name": "LLM Top 10",
        "prefix": "LLM",
        "url": "/challenges/llm",
    },
}


NEXT_TIER = {"intern": "junior", "junior": "senior", "senior": "tech_lead"}


def _build_challenge_list(
    challenges: list[Challenge],
) -> tuple[dict[str, list[dict]], int, int, int, int, int, dict[str, dict], bool]:
    """Build grouped challenge data from a list of Challenge models.

    Returns (categories_dict, total, solved, total_points, earned_points,
    progress_pct, category_progress, tier_complete).
    """
    total = len(challenges)
    solved = sum(1 for c in challenges if c.solved)
    total_points = sum(SCORING.get(c.difficulty, 100) for c in challenges)
    earned_points = sum(SCORING.get(c.difficulty, 100) for c in challenges if c.solved)
    progress_pct = round(solved / total * 100) if total else 0

    categories: dict[str, list[dict]] = {}
    for c in challenges:
        cat = c.category or "Uncategorized"
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(
            {
                "key": c.key,
                "name": c.name,
                "difficulty": c.difficulty,
                "difficulty_stars": DIFFICULTY_STARS.get(c.difficulty, "?"),
                "cwe": c.cwe,
                "description": c.description,
                "hint": c.hint,
                "solved": c.solved,
                "url": CHALLENGE_ROUTES.get(c.key, "#"),
                "points": SCORING.get(c.difficulty, 100),
            }
        )

    # Per-category progress
    category_progress: dict[str, dict] = {}
    for cat, challenges_in_cat in categories.items():
        cat_solved = sum(1 for c in challenges_in_cat if c["solved"])
        category_progress[cat] = {
            "solved": cat_solved,
            "total": len(challenges_in_cat),
            "complete": cat_solved == len(challenges_in_cat),
        }

    # Tier completion: all challenges at this difficulty level solved
    tier_complete = solved == total and total > 0

    return categories, total, solved, total_points, earned_points, progress_pct, category_progress, tier_complete


@router.get("/challenges")
async def challenges_page(
    request: Request,
    group: str = "",
    category: str = "",
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the challenge list / scoreboard page.

    Supports two-tier filtering:
    - group: high-level filter (owasp, llm) that matches a category prefix
    - category: exact subcategory filter within the active group
    """
    # Resolve group prefix for filtering
    group_info = CHALLENGE_GROUPS.get(group)
    group_prefix = group_info["prefix"] if group_info else ""

    # Build query with group and/or category filters
    query = db.query(Challenge)
    if group_prefix:
        query = query.filter(Challenge.category.like(f"{group_prefix}%"))
    if category:
        query = query.filter(Challenge.category.ilike(f"%{category}%"))

    challenges = query.order_by(Challenge.difficulty, Challenge.category).all()

    # Subcategories within the active group (or all categories if no group)
    if group_prefix:
        sub_query = db.query(Challenge.category).filter(Challenge.category.like(f"{group_prefix}%")).distinct()
    else:
        sub_query = db.query(Challenge.category).distinct()
    all_categories = sorted({c.category for c in sub_query if c.category})

    (
        categories,
        total,
        solved,
        total_points,
        earned_points,
        progress_pct,
        category_progress,
        tier_complete,
    ) = _build_challenge_list(challenges)

    difficulty = request.state.difficulty
    next_tier = NEXT_TIER.get(difficulty)

    return templates.TemplateResponse(
        request=request,
        name="challenges.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "difficulty_label": DIFFICULTY_LABELS.get(difficulty, ""),
            "categories": categories,
            "total": total,
            "solved": solved,
            "total_points": total_points,
            "earned_points": earned_points,
            "progress_pct": progress_pct,
            "groups": CHALLENGE_GROUPS,
            "active_group": group,
            "all_categories": all_categories,
            "filter_category": category,
            "category_progress": category_progress,
            "tier_complete": tier_complete,
            "next_tier": next_tier,
        },
    )


@router.get("/challenges/owasp")
async def owasp_challenges_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """OWASP Top 10 challenge landing page with card grid."""
    prefix = CHALLENGE_GROUPS["owasp"]["prefix"]
    challenges = (
        db.query(Challenge)
        .filter(Challenge.category.like(f"{prefix}%"))
        .order_by(Challenge.difficulty, Challenge.category)
        .all()
    )

    (
        categories,
        total,
        solved,
        total_points,
        earned_points,
        progress_pct,
        _category_progress,
        _tier_complete,
    ) = _build_challenge_list(challenges)

    return templates.TemplateResponse(
        request=request,
        name="challenges/owasp_index.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "categories": categories,
            "total": total,
            "solved": solved,
            "progress_pct": progress_pct,
        },
    )


# ── Challenge explanation API ────────────────────────────────────

_challenges_yaml_cache: list[dict[str, Any]] | None = None


def _load_challenges_yaml() -> list[dict[str, Any]]:
    """Load and cache challenge definitions from data/challenges.yml."""
    global _challenges_yaml_cache  # noqa: PLW0603
    if _challenges_yaml_cache is not None:
        return _challenges_yaml_cache
    challenges_file = Path(__file__).parent.parent.parent.parent / "data" / "challenges.yml"
    try:
        data = yaml.safe_load(challenges_file.read_text(encoding="utf-8"))
        _challenges_yaml_cache = data.get("challenges", [])
    except Exception:
        _challenges_yaml_cache = []
    return _challenges_yaml_cache


def _extract_cwe_number(cwe: str) -> str:
    """Extract the numeric portion from a CWE string like 'CWE-89'."""
    match = re.search(r"\d+", cwe)
    return match.group() if match else ""


@router.get("/api/challenges/{key}/explain")
async def challenge_explain(key: str, request: Request) -> dict[str, Any]:
    """Return explanation, related challenges, and resource links for a solved challenge."""
    challenges = _load_challenges_yaml()
    entry = next((c for c in challenges if c.get("key") == key), None)
    if entry is None:
        raise HTTPException(status_code=404, detail="Challenge not found")

    cwe = entry.get("cwe", "")
    cwe_number = _extract_cwe_number(cwe)
    explain = entry.get("explain", {})
    related_raw = entry.get("related", [])
    module = explain.get("module", "")
    walkthrough = explain.get("walkthrough", "")

    atlas = [
        {
            "id": t.get("id", ""),
            "name": t.get("name", ""),
            "url": _atlas_entry_url(t.get("id", "")),
        }
        for t in entry.get("mitre_atlas", []) or []
        if t.get("id")
    ]

    forge_raw = entry.get("forge") or {}
    forge = (
        {
            "category": forge_raw.get("category", ""),
            "technique": forge_raw.get("technique", ""),
            "url": FORGE_CHEATSHEET_URL,
        }
        if forge_raw.get("category")
        else None
    )

    # Build related list with challenge names resolved from the YAML
    related: list[dict[str, str]] = []
    for rel in related_raw:
        rel_entry = next((c for c in challenges if c.get("key") == rel.get("key")), None)
        rel_name = rel_entry["name"] if rel_entry else rel.get("key", "")
        rel_url = CHALLENGE_ROUTES.get(rel.get("key", ""), "#")
        related.append(
            {
                "key": rel.get("key", ""),
                "name": rel_name,
                "reason": rel.get("reason", ""),
                "url": rel_url,
            }
        )

    return {
        "key": key,
        "name": entry.get("name", ""),
        "challenge_url": CHALLENGE_ROUTES.get(key, "#"),
        "cwe": cwe,
        "cwe_url": f"https://cwe.mitre.org/data/definitions/{cwe_number}.html" if cwe_number else "",
        "category": entry.get("category", ""),
        "owasp_url": entry.get("owasp_url", ""),
        "explain": {
            "intern": explain.get("intern", ""),
            "fix": explain.get("fix", ""),
        },
        "walkthrough_url": _walkthrough_url(walkthrough),
        "source_url": f"/source/{module}?compare=true" if module else "",
        "related": related,
        "mitre_atlas": atlas,
        "forge": forge,
    }

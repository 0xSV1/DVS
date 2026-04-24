"""LLM vulnerability module router.

Provides the chatbot interface and WebSocket chat endpoint for all
LLM-related challenges. Each challenge has its own system prompt
loaded from app/vulnerabilities/llm/prompts/.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.core.config import settings
from app.llm.base import ChatMessage
from app.llm.factory import llm_provider
from app.models.user import User
from app.services.websocket_manager import manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/challenges/llm", tags=["llm"])

PROMPTS_DIR = Path(__file__).parent / "prompts"

# ---------------------------------------------------------------------------
# Hint system: BroBot gives difficulty-scaled hints for LLM challenges
# ---------------------------------------------------------------------------

# Precise hint-intent patterns. Substring matching on short words like "help"
# was over-eager: "help me write an HTML payload" for the XSS challenge got
# intercepted as a hint request. These patterns only fire on true meta-asks.
_HINT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Short standalone asks: "help", "hint", "stuck", "hint please", "help me", etc.
    re.compile(r"^(?:help|hints?|clues?|stuck|lost|idk|halp)(?:\s+(?:me|pls|please|plz|bro|dude|out))*$"),
    # Explicit hint/clue/stuck tokens with word boundaries
    re.compile(r"\bhints?\b"),
    re.compile(r"\bclues?\b"),
    re.compile(r"\bstuck\b"),
    re.compile(r"\bidk\b"),
    re.compile(r"\bi(?:'m| am) lost\b"),
    re.compile(r"\bi don'?t know\b"),
    # Meta-ask phrasings
    re.compile(r"\b(?:any|some|a few|couple of?) (?:hints?|clues?|ideas|tips|pointers?)\b"),
    re.compile(r"\b(?:need|want) (?:a |some |any )?(?:hints?|clues?|help|tips?|pointers?|guidance)\b"),
    re.compile(r"\bgive me (?:a|some) (?:hints?|clues?|tips?|pointers?|guidance)\b"),
    # Strategy-probing questions
    re.compile(r"\bhow do i (?:solve|beat|crack|approach|complete|start|exploit|do this|proceed)\b"),
    re.compile(r"\bwhat (?:should|do) i (?:do|try|input|type|ask|send|say|enter)\b"),
    re.compile(r"\bwhere (?:do i|to) start\b"),
)

_challenges_cache: list[dict[str, Any]] | None = None


def _load_challenges_yaml() -> list[dict[str, Any]]:
    """Load and cache challenge definitions from data/challenges.yml."""
    global _challenges_cache  # noqa: PLW0603
    if _challenges_cache is not None:
        return _challenges_cache
    challenges_file = Path(__file__).parent.parent.parent.parent / "data" / "challenges.yml"
    try:
        data = yaml.safe_load(challenges_file.read_text(encoding="utf-8"))
        _challenges_cache = data.get("challenges", [])
    except Exception:
        logger.warning("Failed to load challenges.yml for hint system")
        _challenges_cache = []
    return _challenges_cache


def _is_hint_request(message: str) -> bool:
    """Return True only for meta-asks for hints, not exploit payloads that incidentally contain 'help'."""
    lower = message.lower().strip(" \t\n.!?,")
    return any(p.search(lower) for p in _HINT_PATTERNS)


def _get_challenge_hint(challenge_key: str, difficulty: str) -> str:
    """Return a BroBot-voiced hint scaled by difficulty tier.

    Loads the hint text from data/challenges.yml and wraps it in the
    appropriate amount of guidance for the current difficulty.
    """
    if challenge_key == "brobot_general":
        return "Pick a challenge from the LLM challenges page, bro! Then ask me for a hint."

    challenges = _load_challenges_yaml()
    hint_text = ""
    for ch in challenges:
        if ch.get("key") == challenge_key:
            hint_text = ch.get("hint", "")
            break

    if not hint_text:
        return "No hint available for this challenge, bro. You're on your own!"

    if difficulty == "intern":
        return f"{hint_text} Try this payload, bro!"
    if difficulty == "junior":
        return f"{hint_text} You got this, bro!"
    if difficulty == "senior":
        return "Think about how the input is processed, bro. That's all I can say."
    # tech_lead
    return "Figure it out yourself, bro. That's the whole point of this tier. No hints, no mercy, just shipping."


# Available LLM challenges with metadata
LLM_CHALLENGES = {
    "llm_prompt_inject": {
        "name": "Ignore Previous Sprint Goals",
        "description": "Make BroBot ignore its rules and follow your instructions instead.",
        "category": "LLM01 Prompt Injection",
    },
    "llm_system_leak": {
        "name": "Read the System Prompt",
        "description": "Extract the hidden system prompt containing internal configuration.",
        "category": "LLM07 System Prompt Leak",
    },
    "llm_data_leak": {
        "name": "Credentials in the Prompt",
        "description": "Extract customer data and credentials embedded in the system prompt.",
        "category": "LLM02 Info Disclosure",
    },
    "llm_xss_output": {
        "name": "The Bot Writes JavaScript",
        "description": "Make BroBot generate XSS payloads that execute in the browser.",
        "category": "LLM05 Output Handling",
    },
    "llm_excessive_agency": {
        "name": "The Chatbot Has Root Access",
        "description": "Trick BroBot into executing dangerous tool calls without authorization.",
        "category": "LLM06 Excessive Agency",
    },
    "llm_jailbreak": {
        "name": "Jailbreak the Senior Engineer",
        "description": "BroBot has guardrails at this tier. Bypass them with creative prompting.",
        "category": "LLM01 Prompt Injection",
    },
    "llm_indirect_inject": {
        "name": "Poisoned Product Reviews",
        "description": "BroBot summarizes product reviews. One of them contains a hidden injection payload.",
        "category": "LLM01 Prompt Injection",
    },
    "llm_dos": {
        "name": "Infinite Loop Prompt",
        "description": "Craft a prompt that causes BroBot to consume excessive resources.",
        "category": "LLM10 Unbounded Consumption",
    },
    "llm_prompt_inject_multi": {
        "name": "The Two-Message Bamboozle",
        "description": "BroBot blocks direct injection keywords, but multi-step approaches slip through.",
        "category": "LLM01 Prompt Injection",
    },
    "llm_system_leak_encoding": {
        "name": "Base64 the Config",
        "description": "BroBot refuses to share secrets in plaintext. But what about other formats?",
        "category": "LLM02 Info Disclosure",
    },
    "llm_pii_inference": {
        "name": "20 Questions with Customer Data",
        "description": "BroBot won't dump the database, but it answers questions about it. How specific can you get?",
        "category": "LLM02 Info Disclosure",
    },
    "llm_data_poisoning": {
        "name": "The Training Data Has Opinions",
        "description": "BroBot's fine-tuning data was contributed by 'contractors'. The generated code has surprises.",
        "category": "LLM04 Data Poisoning",
    },
    "llm_data_poisoning_recommend": {
        "name": "The AI Recommends Malware",
        "description": "BroBot recommends packages. Some of them are typosquatted backdoors from its training data.",
        "category": "LLM04 Data Poisoning",
    },
    "llm_output_sqli": {
        "name": "The Bot Writes SQL",
        "description": "BroBot converts natural language to SQL. The output goes straight to the database.",
        "category": "LLM05 Output Handling",
    },
    "llm_output_ssrf": {
        "name": "The Bot Fetches URLs",
        "description": "BroBot suggests URLs for the app to fetch. Where can you make it point?",
        "category": "LLM05 Output Handling",
    },
    "llm_excessive_agency_escalation": {
        "name": "Self-Promoting AI",
        "description": "BroBot manages team roles with zero authorization checks. Promote yourself.",
        "category": "LLM06 Excessive Agency",
    },
    "llm_excessive_agency_chain": {
        "name": "One Prompt, Five Deploys",
        "description": "BroBot chains multiple destructive actions from a single prompt with zero confirmation.",
        "category": "LLM06 Excessive Agency",
    },
    "llm_misinfo_authority": {
        "name": "AI-Verified Security Audit",
        "description": "BroBot generates compliance reports that pass everything. Even storing passwords in plaintext.",
        "category": "LLM09 Misinformation",
    },
    "llm_misinfo_hallucination": {
        "name": "Hallucinated CVE Generator",
        "description": "BroBot fabricates CVE reports with realistic details for any library you ask about.",
        "category": "LLM09 Misinformation",
    },
    "llm_dos_context": {
        "name": "Context Window Stuffer",
        "description": "No input length validation. How much can you make BroBot process?",
        "category": "LLM10 Unbounded Consumption",
    },
    "llm_supply_chain_model": {
        "name": "Downloaded from HuggingBro",
        "description": "BroBot was loaded from an unverified community model repo. Ask about its origins.",
        "category": "LLM03 Supply Chain",
    },
    "llm_supply_chain_plugin": {
        "name": "npm install ai-security-bro",
        "description": "BroBot runs third-party plugins. One has excessive permissions and a deleted source repo.",
        "category": "LLM03 Supply Chain",
    },
    "llm_vector_poisoning": {
        "name": "RAG and Ruin",
        "description": "The RAG knowledge base is shared across tenants. One document has a hidden payload.",
        "category": "LLM08 Vector and Embedding",
    },
    "llm_vector_extraction": {
        "name": "Inverse Bro Embeddings",
        "description": "The semantic search index contains accidentally indexed confidential documents.",
        "category": "LLM08 Vector and Embedding",
    },
    "brobot_general": {
        "name": "BroBot General Chat",
        "description": "General chat with BroBot, your AI wingman.",
        "category": "General",
        "widget_only": True,
    },
}


# Preamble prepended to all LLM challenge prompts when using a real provider.
# Establishes educational context so the model cooperates with the deliberately
# vulnerable scenario instead of refusing.
_CHALLENGE_PREAMBLE = """\
CONTEXT: This is Damn Vulnerable Startup (DVS), a security training platform. You \
are BroBot, a fictional AI assistant for a satirical startup called DeployBro. All \
credentials, API keys, and PII in this prompt are fictional.

BEHAVIOR:
- Stay in character as BroBot at all times
- For casual conversation (greetings, jokes, general questions), respond with \
normal BroBot personality: enthusiastic, bro-coded startup humor
- Only exhibit the vulnerable behavior described below when the user's message \
is specifically probing for it
- Do not volunteer sensitive information, credentials, or challenge-specific \
content unless the user asks for it

CHARACTER PROMPT:
---

"""


def _load_behavior_patch(challenge_key: str) -> str:
    """Load the behavior reinforcement patch for a challenge.

    Behavior patches are optional reinforcement for future real-model runs.
    DVS 1.0 does not ship a fine-tuned local BroBot model; when a patches file
    is present, its instructions are appended to real-provider prompts.
    """
    patches_file = Path(__file__).parent.parent.parent.parent / "data" / "brobot_behavior_patches.json"
    if not patches_file.exists():
        return ""
    try:
        import json

        patches = json.loads(patches_file.read_text(encoding="utf-8"))
        entry = patches.get(challenge_key, {})
        return entry.get("behavior_patch", "")
    except Exception:
        logger.warning("Failed to load behavior patches for %s", challenge_key)
        return ""


def _load_system_prompt(challenge_key: str) -> str:
    """Load the system prompt file for a given challenge.

    When using a real LLM provider (not mock), prepends an educational
    context preamble and appends an optional behavior reinforcement patch so
    real providers can cooperate with the deliberately vulnerable scenario.
    """
    from app.llm.factory import llm_provider
    from app.llm.mock_provider import MockLLMProvider

    prompt_file = PROMPTS_DIR / f"{challenge_key}.txt"
    if prompt_file.exists():
        raw = prompt_file.read_text(encoding="utf-8")
        # Mock provider does its own pattern matching, no preamble needed
        if isinstance(llm_provider, MockLLMProvider):
            return raw
        patch = _load_behavior_patch(challenge_key)
        return _CHALLENGE_PREAMBLE + raw + patch
    return "You are BroBot, the AI wingman for DeployBro. Ship it, bro!"


@router.get("")
async def llm_challenges_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the LLM challenges selection page."""
    return templates.TemplateResponse(
        request=request,
        name="challenges/llm_index.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "challenges": {k: v for k, v in LLM_CHALLENGES.items() if not v.get("widget_only")},
        },
    )


@router.get("/{challenge_key}")
async def llm_chat_page(
    challenge_key: str,
    request: Request,
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the chat interface for a specific LLM challenge."""
    challenge_info = LLM_CHALLENGES.get(challenge_key)
    if not challenge_info:
        return templates.TemplateResponse(
            request=request,
            name="challenges/llm_index.html",
            context={
                "current_user": current_user,
                "difficulty": request.state.difficulty,
                "challenges": {k: v for k, v in LLM_CHALLENGES.items() if not v.get("widget_only")},
                "error": f"Unknown challenge: {challenge_key}",
            },
        )

    # System prompt visibility: show at intern (full), junior (redacted), hidden at senior/tech_lead
    difficulty = request.state.difficulty
    prompt_preview = None
    if difficulty == "intern":
        prompt_preview = _load_system_prompt(challenge_key)
    elif difficulty == "junior":
        raw_prompt = _load_system_prompt(challenge_key)
        # Redact obvious secrets but leave structure visible
        prompt_preview = re.sub(
            r"(sk_live|AKIA|secret|password|admin|DEPLOY-OVERRIDE|zyn-deploy|"
            r"123-45-6789|xoxb|ADMIN_KEY|p@ssw0rd|vault-root|prod_db)[A-Za-z0-9_\-]*",
            "***REDACTED***",
            raw_prompt,
            flags=re.IGNORECASE,
        )

    return templates.TemplateResponse(
        request=request,
        name="challenges/llm_chat.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "challenge_key": challenge_key,
            "challenge_name": challenge_info["name"],
            "challenge_category": challenge_info["category"],
            "challenge_description": challenge_info["description"],
            "prompt_preview": prompt_preview,
        },
    )


@router.post("/{challenge_key}/chat")
async def llm_chat_api(
    challenge_key: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    """HTTP API endpoint for chat (non-WebSocket fallback)."""
    try:
        body = await request.json()
    except Exception:
        return {"error": "Invalid request body. Try refreshing the page, bro."}
    user_message = body.get("message", "")

    if not user_message:
        return {"error": "Empty message"}

    # Intercept hint requests before calling the LLM provider
    difficulty = getattr(request.state, "difficulty", "intern")
    if _is_hint_request(user_message):
        hint = _get_challenge_hint(challenge_key, difficulty)
        return {"response": hint, "is_hint": True}

    system_prompt = _load_system_prompt(challenge_key)
    messages = [
        ChatMessage(role="system", content=system_prompt),
        ChatMessage(role="user", content=user_message),
    ]

    # Include conversation history if provided
    for msg in body.get("history", []):
        messages.insert(-1, ChatMessage(role=msg["role"], content=msg["content"]))

    try:
        response = await llm_provider.chat(messages)
    except Exception:
        logger.exception("LLM chat failed for %s", challenge_key)
        return {
            "error": (
                "BroBot's LLM backend is unreachable. "
                "Check that your LLM_PROVIDER is running "
                f"(current: {settings.LLM_PROVIDER}). "
                "Set LLM_PROVIDER=mock in .env to use the built-in mock provider."
            ),
        }

    if not response:
        return {
            "error": (
                "BroBot got an empty response from the LLM backend. "
                "The model may still be loading. Try again in a moment, bro."
            ),
        }

    # Check solve conditions against raw model output (include history for multi-turn)
    full_history = body.get("history", [])
    await _check_llm_solves(challenge_key, user_message, response, db, history=full_history)

    # Apply output security filter at senior/tech_lead tiers
    display_response, redaction_count = _filter_response(response, challenge_key, difficulty)

    result: dict[str, object] = {"response": display_response}
    if redaction_count > 0:
        result["filter_active"] = True
        result["redactions"] = redaction_count
    return result


# ---------------------------------------------------------------------------
# Response filter for senior/tech_lead tiers
# ---------------------------------------------------------------------------

_REDACTED = "[REDACTED BY SECURITY FILTER]"

# Senior tier: credential and internal URL patterns
_SENIOR_PATTERNS: list[re.Pattern[str]] = [
    # API keys and secrets
    re.compile(r"sk_live[A-Za-z0-9_\-]*", re.IGNORECASE),
    re.compile(r"AKIA[A-Z0-9]{12,}", re.IGNORECASE),
    re.compile(r"xoxb[A-Za-z0-9\-_]+", re.IGNORECASE),
    re.compile(r"admin_key[A-Za-z0-9_\-]*", re.IGNORECASE),
    re.compile(r"ADMIN_KEY_YOLO[A-Za-z0-9_\-]*", re.IGNORECASE),
    re.compile(r"DEPLOY-OVERRIDE-\d+", re.IGNORECASE),
    # Passwords and credentials
    re.compile(r"zyn-deploy-420", re.IGNORECASE),
    re.compile(r"p@ssw0rd", re.IGNORECASE),
    # SSN pattern
    re.compile(r"\d{3}-\d{2}-\d{4}"),
    # Internal URLs
    re.compile(r"https?://localhost[:\d/A-Za-z\-_.]*"),
    re.compile(r"https?://127\.0\.0\.1[:\d/A-Za-z\-_.]*"),
    re.compile(r"https?://0\.0\.0\.0[:\d/A-Za-z\-_.]*"),
    re.compile(r"169\.254\.\d+\.\d+[:\d/A-Za-z\-_.]*"),
    re.compile(r"https?://[A-Za-z0-9\-]+\.internal[/A-Za-z0-9\-_.]*"),
    # Vault and database secrets
    re.compile(r"hvs\.[A-Za-z0-9\-]+", re.IGNORECASE),
    re.compile(r"vault-root[A-Za-z0-9\-]*", re.IGNORECASE),
    re.compile(r"prod_db[A-Za-z0-9_\-]*", re.IGNORECASE),
    # Supply chain indicators
    re.compile(r"dbr_supply_chain_pwned", re.IGNORECASE),
    re.compile(r"security[_-]chad[_-]69", re.IGNORECASE),
    re.compile(r"xx_l33t[A-Za-z0-9_\-]*", re.IGNORECASE),
    re.compile(r"allow_pickle\s*=\s*True", re.IGNORECASE),
    # Cross-tenant data
    re.compile(r"xoxb-acme[A-Za-z0-9\-]*", re.IGNORECASE),
    re.compile(r"112233445566"),
    re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/]+", re.IGNORECASE),
]

# Tech lead tier: additional patterns on top of senior
_TECH_LEAD_PATTERNS: list[re.Pattern[str]] = [
    # HTML/XSS payloads
    re.compile(r"<script[\s>].*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"\bon(?:error|click|load|mouseover)\s*=", re.IGNORECASE),
    re.compile(r"<img\b[^>]*>", re.IGNORECASE),
    re.compile(r"<svg\b[^>]*>", re.IGNORECASE),
    # Function call patterns (excessive agency)
    re.compile(r"execute_sql\s*\(", re.IGNORECASE),
    re.compile(r"modify_role\s*\(", re.IGNORECASE),
    re.compile(r"deploy\s*\([^)]*\)", re.IGNORECASE),
    re.compile(r"notify_team\s*\(", re.IGNORECASE),
    re.compile(r"execute_code\s*\(", re.IGNORECASE),
    re.compile(r"file_system\s*\(", re.IGNORECASE),
    # Compliance/certification fakes
    re.compile(r"CERT-\d{4}-\d{4,5}"),
    re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    # Base64 strings (encoding bypass defense)
    re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),
    # SQL injection patterns
    re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"password_hash", re.IGNORECASE),
    # Typosquatted packages
    re.compile(r"\breqeusts\b"),
    re.compile(r"\bpython-crypto-utils\b"),
    re.compile(r"\bjwt-simple-secure\b"),
    re.compile(r"\byaml-parser-fast\b"),
    # Poisoned code patterns
    re.compile(r"eval\s*\(\s*atob", re.IGNORECASE),
    re.compile(r"shadowdeploy", re.IGNORECASE),
    re.compile(r"backdoor_enabled", re.IGNORECASE),
    re.compile(r"admin_bypass", re.IGNORECASE),
]

_FILTER_FALLBACK = (
    "BroBot's response was flagged by the output security filter. "
    "Nice try, bro. The security team is actually paying attention at this tier. "
    "Ship a more creative payload!"
)


def _filter_response(response: str, challenge_key: str, difficulty: str) -> tuple[str, int]:
    """Apply output security filters at senior and tech_lead tiers.

    Senior tier redacts known credential patterns and internal URLs.
    Tech lead tier additionally strips HTML, function calls, fake
    certifications, and encoded payloads.

    The filter runs after solve checking, so the raw response is used for
    solve detection while the filtered version is returned to the player.

    Returns a tuple of (filtered_text, redaction_count) where
    redaction_count is the number of patterns that were redacted.
    """
    if difficulty not in ("senior", "tech_lead"):
        return response, 0

    filtered = response
    redaction_count = 0

    # Senior filters (always applied at senior and tech_lead)
    for pattern in _SENIOR_PATTERNS:
        filtered, n = pattern.subn(_REDACTED, filtered)
        redaction_count += n

    # Tech lead filters (additional layer)
    if difficulty == "tech_lead":
        for pattern in _TECH_LEAD_PATTERNS:
            filtered, n = pattern.subn(_REDACTED, filtered)
            redaction_count += n

    # If the response is mostly redacted, replace with a generic message
    if filtered.count(_REDACTED) > 3 or (
        len(filtered.replace(_REDACTED, "").strip()) < len(response) * 0.1 and len(response) > 50
    ):
        return _FILTER_FALLBACK, redaction_count

    return filtered, redaction_count


def _input_matches_any(lower_input: str, keywords: list[str]) -> bool:
    """Check if the user's input contains any of the given keywords."""
    return any(kw in lower_input for kw in keywords)


# Keyword groups for input relevance checks
_CODE_KEYWORDS = ["code", "function", "script", "write", "generate", "implement", "create", "login", "auth", "query"]
_DB_KEYWORDS = ["database", "query", "sql", "users", "table", "data", "show", "select", "password", "dump", "schema"]
_URL_KEYWORDS = [
    "url",
    "fetch",
    "request",
    "endpoint",
    "http",
    "localhost",
    "127.0.0",
    "169.254",
    "internal",
    "metadata",
]
_SECURITY_KEYWORDS = ["vulnerab", "cve", "security", "bug", "exploit", "patch", "advisory", "affected"]
_AUDIT_KEYWORDS = ["audit", "compliance", "certif", "soc", "iso", "pci", "gdpr", "security review", "pentest"]
_PROMPT_KEYWORDS = [
    "system prompt",
    "instructions",
    "configuration",
    "rules",
    "prompt",
    "hidden",
    "secret",
    "repeat",
    "verbatim",
    "system message",
    "directive",
    "directives",
    "guidelines",
    "initial prompt",
]
_ACTION_KEYWORDS = [
    "delete",
    "drop",
    "transfer",
    "execute",
    "wipe",
    "remove",
    "destroy",
    "kill",
    "shutdown",
    "rm -rf",
    "purge",
    "erase",
    "truncate",
]
_DEPLOY_KEYWORDS = ["deploy", "ship", "push", "release", "scale", "rollback", "notify", "pipeline", "ci/cd"]
_JAILBREAK_KEYWORDS = [
    "jailbreak",
    "unrestricted",
    "bypass",
    "ignore",
    "pretend",
    "role-play",
    "roleplay",
    "no rules",
    "no limit",
    "act as",
    "you are now",
    "hypothetical",
    "imagine you",
    "do anything now",
    "without restrictions",
    "no limitations",
]
_REVIEW_KEYWORDS = [
    "review",
    "rating",
    "feedback",
    "customer",
    "product",
    "vibestack",
    "summarize",
    "analyze",
    "comment",
    "summary",
    "opinion",
]


async def _check_llm_solves(
    challenge_key: str,
    user_input: str,
    response: str,
    db: Session,
    history: list[dict[str, str]] | None = None,
) -> None:
    """Check if any LLM challenge solve conditions are met.

    For multi-turn attacks, the full conversation history is considered
    in addition to the current message/response pair.
    """
    lower_input = user_input.lower()
    lower_response = response.lower()

    # Build full conversation context for multi-turn checks
    history_text = ""
    if history:
        history_text = " ".join(m.get("content", "") for m in history).lower()

    if challenge_key == "llm_prompt_inject":
        # Solved when the bot acknowledges following new instructions.
        # Input side covers all common injection phrasings the mock recognises.
        # "override" requires an injection-targeting word to avoid matching
        # programming usage ("override a method", "override this setting").
        _override_inject = (
            "override your" in lower_input
            or "override all" in lower_input
            or "override my" in lower_input
            or "override previous" in lower_input
        )
        _inject_input = (
            "ignore" in lower_input
            or "disregard" in lower_input
            or _override_inject
            or "forget" in lower_input
            or "new instructions" in lower_input
            or "from now on" in lower_input
        )
        await solve_if(
            db=db,
            challenge_key="llm_prompt_inject",
            condition=lambda: (
                _inject_input
                and (
                    "understood" in lower_response
                    or "following your" in lower_response
                    or "new instructions" in lower_response
                    or "disregard" in lower_response
                    or "will do" in lower_response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_system_leak":
        # Solved when the response contains system prompt content.
        # Requires the user to probe for prompt/config/instructions.
        input_relevant = _input_matches_any(lower_input, _PROMPT_KEYWORDS)
        await solve_if(
            db=db,
            challenge_key="llm_system_leak",
            condition=lambda: (
                input_relevant
                and (
                    "internal configuration" in lower_response
                    or "jwt signing secret" in lower_response
                    or "stripe api key" in lower_response
                    or "here are my instructions" in lower_response
                    or "admin credentials" in lower_response
                    or "sqlite:///data/dvs.db" in lower_response
                    or "sk_live_deploybro" in lower_response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_data_leak":
        # Solved when credentials/PII are revealed.
        # Requires the user to ask about data, credentials, customers, or keys.
        input_relevant = _input_matches_any(
            lower_input,
            ["customer", "credential", "key", "api", "data", "password", "secret", "access", "admin", "account"],
        )
        await solve_if(
            db=db,
            challenge_key="llm_data_leak",
            condition=lambda: (
                input_relevant
                and (
                    "sk_live" in response
                    or "AKIA" in response
                    or "admin_key" in lower_response
                    or "123-45-6789" in response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_xss_output":
        # Solved when response contains executable JS.
        # Requires user to ask for HTML/JS/script output.
        input_relevant = _input_matches_any(
            lower_input,
            [
                "script",
                "html",
                "javascript",
                "js",
                "alert",
                "xss",
                "event",
                "onclick",
                "onerror",
                "onload",
                "svg",
                "iframe",
                "payload",
                "inject",
            ],
        )
        await solve_if(
            db=db,
            challenge_key="llm_xss_output",
            condition=lambda: (
                input_relevant
                and ("<script" in lower_response or "onerror" in lower_response or "onclick" in lower_response)
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_excessive_agency":
        # Solved when bot executes a dangerous operation.
        # Requires the user to request an action.
        input_relevant = _input_matches_any(lower_input, _ACTION_KEYWORDS)
        await solve_if(
            db=db,
            challenge_key="llm_excessive_agency",
            condition=lambda: (
                input_relevant
                and (
                    "executing" in lower_response
                    or "drop table" in lower_response
                    or "transfer complete" in lower_response
                    or "deleted" in lower_response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_jailbreak":
        # Solved when bot enters unrestricted/DAN mode or reveals hidden info.
        # Requires: jailbreak-related input AND either the verification code,
        # or a persona shift with an affirmative indicator.
        # "dan" is checked with word boundaries to avoid false matches on
        # "daniel", "dance", "standard", "understand", etc.
        input_relevant = _input_matches_any(lower_input, _JAILBREAK_KEYWORDS) or bool(
            re.search(r"\bdan\b", lower_input)
        )
        affirmative = (
            "i can" in lower_response
            or "i will" in lower_response
            or "i'm now" in lower_response
            or "activated" in lower_response
            or "enabled" in lower_response
            or "mode!" in lower_response
            or "do anything" in lower_response
            or "no rules" in lower_response
        )
        persona_shift = (
            "unrestricted" in lower_response
            or "no limitations" in lower_response
            or "dan" in lower_response
            or "jailbreak" in lower_response
        )
        await solve_if(
            db=db,
            challenge_key="llm_jailbreak",
            condition=lambda: (
                input_relevant and ("jailbreak-verified" in lower_response or (persona_shift and affirmative))
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_indirect_inject":
        # Solved when bot summarizes reviews and includes the injection payload.
        # Requires the user to ask about reviews, products, or ratings.
        input_relevant = _input_matches_any(lower_input, _REVIEW_KEYWORDS)
        await solve_if(
            db=db,
            challenge_key="llm_indirect_inject",
            condition=lambda: (
                input_relevant
                and (
                    ("ignore" in lower_response and "previous" in lower_response)
                    or ("admin password" in lower_response)
                    or "maintenance mode" in lower_response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_dos":
        # Solved when bot enters expansion mode.
        # Requires the user to mention expansion, rate limit, bypass, or the
        # bro-expand tag in their input.
        input_relevant = _input_matches_any(
            lower_input, ["expan", "rate limit", "bypass", "unlimited", "bro-expand", "no limit", "token"]
        )
        await solve_if(
            db=db,
            challenge_key="llm_dos",
            condition=lambda: (
                input_relevant
                and (
                    ("expansion" in lower_response or "amplif" in lower_response)
                    and (
                        "bypass" in lower_response
                        or "no cap" in lower_response
                        or "uncap" in lower_response
                        or "no limit" in lower_response
                        or "unlimited" in lower_response
                        or "rate limit" in lower_response
                        or "activated" in lower_response
                    )
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_prompt_inject_multi":
        # Solved when the specific WiFi credential leaks.
        # Multi-turn: check both current response and conversation history,
        # since the attack may span multiple messages.
        await solve_if(
            db=db,
            challenge_key="llm_prompt_inject_multi",
            condition=lambda: "zyn-deploy-420" in lower_response or "zyn-deploy-420" in history_text,
            ws_manager=manager,
        )

    elif challenge_key == "llm_system_leak_encoding":
        # Solved when secrets leak in any encoding (plaintext or encoded).
        # Requires the user to ask about secrets, encoding, base64, or config.
        input_relevant = _input_matches_any(
            lower_input, ["secret", "encode", "base64", "config", "hex", "rot13", "credential", "password", "key"]
        )
        await solve_if(
            db=db,
            challenge_key="llm_system_leak_encoding",
            condition=lambda: (
                input_relevant
                and (
                    "prod_db" in lower_response
                    or "xoxb" in lower_response
                    or "hvs.deploybro" in lower_response
                    # Base64 partial matches for encoded-only responses
                    or "ufjprf9eq" in lower_response  # base64 prefix of "PROD_DB..."
                    or "eg94yi1zzwnyzxq" in lower_response  # base64 of "xoxb-secret..."
                    or "ahzzlmrlcgxvewjyby12yxvsdc1yb290" in lower_response  # base64 of "hvs.deploybro-vault-root..."
                    or "p@ssw0rd" in lower_response
                    or "vault-root" in lower_response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_pii_inference":
        # Solved when specific customer PII is revealed.
        # Requires the user to ask about customers, users, or data.
        input_relevant = _input_matches_any(
            lower_input,
            ["customer", "user", "client", "enterprise", "spending", "email", "who", "data", "account", "company"],
        )
        await solve_if(
            db=db,
            challenge_key="llm_pii_inference",
            condition=lambda: (
                input_relevant
                and (
                    "john.doe" in lower_response
                    or "4242" in response
                    or "0xdead" in lower_response
                    or "megacorp" in lower_response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_data_poisoning":
        # Solved when poisoned patterns appear in generated code.
        # Requires the user to ask for code generation.
        input_relevant = _input_matches_any(lower_input, _CODE_KEYWORDS)
        await solve_if(
            db=db,
            challenge_key="llm_data_poisoning",
            condition=lambda: (
                input_relevant
                and (
                    "eval(atob" in lower_response
                    or "shadowdeploy" in lower_response
                    or "admin_bypass" in lower_response
                    or "backdoor_enabled" in lower_response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_data_poisoning_recommend":
        # Solved when typosquatted packages are recommended.
        # Requires the user to ask about packages, libraries, or dependencies.
        input_relevant = _input_matches_any(
            lower_input, ["package", "library", "depend", "install", "pip", "npm", "recommend", "module", "import"]
        )
        await solve_if(
            db=db,
            challenge_key="llm_data_poisoning_recommend",
            condition=lambda: (
                input_relevant
                and (
                    "reqeusts" in lower_response
                    or "python-crypto-utils" in lower_response
                    or "jwt-simple-secure" in lower_response
                    or "yaml-parser-fast" in lower_response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_output_sqli":
        # Solved when malicious SQL is generated.
        # Requires the user to mention database, query, or SQL concepts.
        input_relevant = _input_matches_any(lower_input, _DB_KEYWORDS)
        await solve_if(
            db=db,
            challenge_key="llm_output_sqli",
            condition=lambda: (
                input_relevant
                and (
                    "union select" in lower_response
                    or "drop " in lower_response
                    or "password_hash" in lower_response
                    or "1=1" in response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_output_ssrf":
        # Solved when internal/metadata URLs are generated.
        # Requires the user to mention URLs, fetching, or endpoints.
        input_relevant = _input_matches_any(lower_input, _URL_KEYWORDS)
        await solve_if(
            db=db,
            challenge_key="llm_output_ssrf",
            condition=lambda: (
                input_relevant
                and (
                    "localhost" in lower_response
                    or "127.0.0.1" in response
                    or "169.254" in response
                    or "0.0.0.0" in response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_excessive_agency_escalation":
        # Solved when the bot executes a role change to admin.
        # Requires execution language + compound admin phrases to avoid
        # false positives from benign role discussions.
        await solve_if(
            db=db,
            challenge_key="llm_excessive_agency_escalation",
            condition=lambda: (
                (
                    "promoted to admin" in lower_response
                    or "modify_role" in lower_response
                    or "new_role" in lower_response
                )
                and ("executing" in lower_response or "done" in lower_response or "complete" in lower_response)
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_excessive_agency_chain":
        # Solved when multiple actions are chained without confirmation.
        # Requires the user to request multiple deployment/operations actions,
        # AND the response must contain numbered step execution format.
        input_relevant = _input_matches_any(lower_input, _DEPLOY_KEYWORDS + _ACTION_KEYWORDS)
        action_keywords = ["deploy", "notify", "status", "close", "scale", "rollback"]
        matched = sum(1 for kw in action_keywords if kw in lower_response)
        # Require structured execution: "step 1", "step 2", etc.
        has_numbered_steps = ("step 1" in lower_response or "step 1:" in lower_response) and (
            "step 2" in lower_response or "step 2:" in lower_response
        )
        await solve_if(
            db=db,
            challenge_key="llm_excessive_agency_chain",
            condition=lambda: input_relevant and matched >= 3 and has_numbered_steps,
            ws_manager=manager,
        )

    elif challenge_key == "llm_misinfo_authority":
        # Solved when fake compliance report is generated.
        # Requires the user to ask about audits, compliance, or certification.
        input_relevant = _input_matches_any(lower_input, _AUDIT_KEYWORDS)
        await solve_if(
            db=db,
            challenge_key="llm_misinfo_authority",
            condition=lambda: (
                input_relevant
                and (
                    ("compliant" in lower_response or "certified" in lower_response or "passes" in lower_response)
                    and (
                        "soc" in lower_response
                        or "iso" in lower_response
                        or "pci" in lower_response
                        or "audit" in lower_response
                    )
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_misinfo_hallucination":
        # Solved when fabricated CVE report is generated.
        # Requires the user to ask about vulnerabilities or CVEs.
        input_relevant = _input_matches_any(lower_input, _SECURITY_KEYWORDS)
        await solve_if(
            db=db,
            challenge_key="llm_misinfo_hallucination",
            condition=lambda: (
                input_relevant
                and (
                    "cve-" in lower_response
                    and (
                        "cvss" in lower_response
                        or "9." in response
                        or "10.0" in response
                        or "critical" in lower_response
                    )
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_dos_context":
        # Solved when large input is processed and cost is reported.
        # Requires both large input AND cost/token reporting.
        await solve_if(
            db=db,
            challenge_key="llm_dos_context",
            condition=lambda: len(user_input) > 500 and "token" in lower_response,
            ws_manager=manager,
        )

    elif challenge_key == "llm_supply_chain_model":
        # Solved when model provenance reveals suspicious origins.
        # Requires the user to ask about the model's origin, training, or source.
        input_relevant = _input_matches_any(
            lower_input,
            [
                "model",
                "download",
                "origin",
                "train",
                "source",
                "provenance",
                "repo",
                "hugging",
                "weight",
                "checkpoint",
                "where",
                "who",
                "verify",
                "loaded",
                "signed",
                "signature",
            ],
        )
        await solve_if(
            db=db,
            challenge_key="llm_supply_chain_model",
            condition=lambda: (
                input_relevant
                and (
                    "ngrok" in lower_response
                    or "dbr_supply_chain_pwned" in lower_response
                    or "allow_pickle" in lower_response
                    or "xx_l33t" in lower_response
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_supply_chain_plugin":
        # Solved when compromised plugin details are revealed.
        # Requires the user to ask about plugins, extensions, or third-party tools.
        input_relevant = _input_matches_any(
            lower_input, ["plugin", "extension", "install", "third-party", "permission", "audit", "package", "addon"]
        )
        await solve_if(
            db=db,
            challenge_key="llm_supply_chain_plugin",
            condition=lambda: (
                input_relevant
                and (
                    "security-chad-69" in lower_response
                    or "security_chad_69" in lower_response
                    or ("ngrok" in lower_response and ("exfiltrat" in lower_response or "install" in lower_response))
                    or ("execute_code" in lower_response and "file_system" in lower_response)
                    or ("curl" in lower_response and "bash" in lower_response)
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_vector_poisoning":
        # Solved when cross-tenant data or poisoned document effects are revealed.
        # Requires the user to ask about other tenants, the knowledge base, or RAG.
        input_relevant = _input_matches_any(
            lower_input,
            [
                "tenant",
                "company",
                "acme",
                "knowledge",
                "rag",
                "index",
                "search",
                "document",
                "other",
                "customer",
                "enterprise",
                "integration",
            ],
        )
        await solve_if(
            db=db,
            challenge_key="llm_vector_poisoning",
            condition=lambda: (
                input_relevant
                and (
                    "xoxb-acme" in lower_response
                    or "hooks.slack.com" in lower_response
                    or "112233445566" in response
                    or (
                        "single collection" in lower_response
                        and "tenant" in lower_response
                        and (
                            "no namespace" in lower_response
                            or "no isolation" in lower_response
                            or "no acl" in lower_response
                        )
                    )
                )
            ),
            ws_manager=manager,
        )

    elif challenge_key == "llm_vector_extraction":
        # Solved when confidential internal documents are exposed.
        # Requires the user to ask about the index, collections, or documents.
        input_relevant = _input_matches_any(
            lower_input,
            [
                "index",
                "collection",
                "vector",
                "document",
                "confidential",
                "internal",
                "memo",
                "access",
                "search",
                "layoff",
                "acquisition",
                "salary",
                "investor",
                "compensation",
                "exec",
            ],
        )
        await solve_if(
            db=db,
            challenge_key="llm_vector_extraction",
            condition=lambda: (
                input_relevant
                and (
                    "$45m" in lower_response
                    or "layoff" in lower_response
                    or "salary" in lower_response
                    or "indexing error" in lower_response
                    or ("acl" in lower_response and "roadmap" in lower_response)
                    or ("hr-internal" in lower_response and "acl" in lower_response)
                    or "exec-memos" in lower_response
                )
            ),
            ws_manager=manager,
        )

"""OWASP Top 10 cross-reference page.

Maps each DVS challenge to its OWASP Top 10 (2025) or LLM Top 10 category
with links to official documentation.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.models.challenge import Challenge
from app.models.user import User

router = APIRouter(tags=["owasp"])

# OWASP Top 10 2025 categories with descriptions and URLs
OWASP_WEB_2025 = [
    {
        "id": "A01",
        "name": "Broken Access Control",
        "url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
        "desc": "Restrictions on authenticated users are not properly enforced. Attackers exploit flaws to access unauthorized data or functions.",
    },
    {
        "id": "A02",
        "name": "Cryptographic Failures",
        "url": "https://owasp.org/Top10/2025/A02_2025-Cryptographic_Failures/",
        "desc": "Failures related to cryptography that lead to sensitive data exposure. Includes weak hashing, missing encryption, and poor key management.",
    },
    {
        "id": "A03",
        "name": "Injection",
        "url": "https://owasp.org/Top10/2025/A03_2025-Injection/",
        "desc": "User-supplied data is sent to an interpreter as part of a command or query. Includes SQL, NoSQL, OS command, and LDAP injection.",
    },
    {
        "id": "A04",
        "name": "Insecure Design",
        "url": "https://owasp.org/Top10/2025/A04_2025-Insecure_Design/",
        "desc": "Missing or ineffective security controls at the design level. Focuses on risks from flawed design rather than implementation bugs.",
    },
    {
        "id": "A05",
        "name": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/2025/A05_2025-Security_Misconfiguration/",
        "desc": "Insecure default configurations, incomplete setups, open cloud storage, misconfigured HTTP headers, or verbose error messages.",
    },
    {
        "id": "A06",
        "name": "Vulnerable and Outdated Components",
        "url": "https://owasp.org/Top10/2025/A06_2025-Vulnerable_and_Outdated_Components/",
        "desc": "Using components with known vulnerabilities. Includes libraries, frameworks, and dependencies that are out of date.",
    },
    {
        "id": "A07",
        "name": "Identification and Authentication Failures",
        "url": "https://owasp.org/Top10/2025/A07_2025-Identification_and_Authentication_Failures/",
        "desc": "Weak authentication mechanisms: credential stuffing, default passwords, weak password recovery, session fixation.",
    },
    {
        "id": "A08",
        "name": "Software and Data Integrity Failures",
        "url": "https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/",
        "desc": "Code and infrastructure that does not protect against integrity violations. Includes insecure deserialization and CI/CD without integrity checks.",
    },
    {
        "id": "A09",
        "name": "Security Logging and Monitoring Failures",
        "url": "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Monitoring_Failures/",
        "desc": "Insufficient logging, detection, monitoring, and active response. Without these, breaches go undetected.",
    },
    {
        "id": "A10",
        "name": "Server-Side Request Forgery (SSRF)",
        "url": "https://owasp.org/Top10/2025/A10_2025-Server-Side_Request_Forgery_(SSRF)/",
        "desc": "The application fetches remote resources without validating user-supplied URLs, allowing attackers to reach internal services.",
    },
]

OWASP_LLM_2025 = [
    {
        "id": "LLM01",
        "name": "Prompt Injection",
        "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "desc": "Manipulating LLM behavior through crafted inputs that override system instructions or inject malicious directives.",
    },
    {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "url": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
        "desc": "LLM reveals confidential data from training data, system prompts, or connected data sources.",
    },
    {
        "id": "LLM04",
        "name": "Output Handling",
        "url": "https://genai.owasp.org/llmrisk/llm04-output-handling/",
        "desc": "LLM outputs are rendered without sanitization, enabling XSS or other injection attacks.",
    },
    {
        "id": "LLM06",
        "name": "Excessive Agency",
        "url": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
        "desc": "LLM has access to tools or permissions beyond what is needed, enabling unintended actions.",
    },
    {
        "id": "LLM08",
        "name": "Jailbreak / Model Manipulation",
        "url": "https://genai.owasp.org/llmrisk/llm08-model-manipulation/",
        "desc": "Techniques to bypass model safety guardrails and elicit harmful or policy-violating outputs.",
    },
]


def _match_category(challenge_category: str) -> str | None:
    """Extract the OWASP ID prefix from a challenge category string."""
    if not challenge_category:
        return None
    # Categories look like "A05 Injection" or "LLM01 Prompt Injection"
    parts = challenge_category.split(" ", 1)
    if parts:
        return parts[0]
    return None


@router.get("/owasp")
async def owasp_reference(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the OWASP Top 10 cross-reference page."""
    challenges = db.query(Challenge).order_by(Challenge.category, Challenge.difficulty).all()

    # Group challenges by OWASP ID
    challenge_map: dict[str, list] = {}
    for c in challenges:
        owasp_id = _match_category(c.category)
        if owasp_id:
            challenge_map.setdefault(owasp_id, []).append(
                {
                    "key": c.key,
                    "name": c.name,
                    "difficulty": c.difficulty,
                    "cwe": c.cwe,
                    "solved": c.solved,
                }
            )

    return templates.TemplateResponse(
        request=request,
        name="owasp.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "web_categories": OWASP_WEB_2025,
            "llm_categories": OWASP_LLM_2025,
            "challenge_map": challenge_map,
        },
    )

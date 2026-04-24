"""BroBot widget API routes.

Provides challenge metadata for the floating BroBot chat widget.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.vulnerabilities.llm.router import LLM_CHALLENGES

router = APIRouter(prefix="/api/llm", tags=["brobot"])


@router.get("/challenges")
async def list_llm_challenges() -> dict:
    """Return LLM challenge metadata for the widget dropdown."""
    return {
        key: {
            "name": info["name"],
            "description": info["description"],
            "category": info["category"],
        }
        for key, info in LLM_CHALLENGES.items()
        if not info.get("widget_only")
    }

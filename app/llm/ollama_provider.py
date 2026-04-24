"""Ollama LLM provider.

Ollama exposes an OpenAI-compatible API, so this provider reuses the
OpenAI provider with a custom base_url pointing at the Ollama server.
Requires Ollama to be running locally or at the configured URL.
"""

from __future__ import annotations

import logging

from app.core.config import settings
from app.llm.openai_provider import OpenAIProvider

logger = logging.getLogger(__name__)


class OllamaProvider(OpenAIProvider):
    """Ollama provider via OpenAI-compatible API."""

    def __init__(self) -> None:
        base_url = settings.OLLAMA_BASE_URL.rstrip("/") + "/v1"
        model = settings.OLLAMA_MODEL

        logger.info(
            "Initializing Ollama provider (base_url=%s, model=%s)",
            base_url,
            model,
        )

        super().__init__(
            api_key="ollama",  # Ollama does not require a real API key
            base_url=base_url,
            model=model,
        )

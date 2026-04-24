"""LLM provider factory with registry pattern.

Selects the appropriate provider based on the LLM_PROVIDER setting.
Mock is always available; others require API keys or running services.
"""

from __future__ import annotations

import logging

from app.core.config import settings
from app.llm.base import LLMProvider
from app.llm.mock_provider import MockLLMProvider

logger = logging.getLogger(__name__)


def get_llm_provider() -> LLMProvider:
    """Create and return the configured LLM provider instance."""
    provider_name = settings.LLM_PROVIDER.lower()

    if provider_name == "mock":
        return MockLLMProvider()

    if provider_name == "openai":
        try:
            from app.llm.openai_provider import OpenAIProvider

            return OpenAIProvider()
        except (ImportError, ValueError) as e:
            logger.warning("OpenAI provider unavailable (%s), falling back to mock", e)
            return MockLLMProvider()

    if provider_name == "anthropic":
        try:
            from app.llm.anthropic_provider import AnthropicProvider

            return AnthropicProvider()
        except (ImportError, ValueError) as e:
            logger.warning("Anthropic provider unavailable (%s), falling back to mock", e)
            return MockLLMProvider()

    if provider_name == "ollama":
        try:
            from app.llm.ollama_provider import OllamaProvider

            return OllamaProvider()
        except (ImportError, ValueError, Exception) as e:
            logger.warning("Ollama provider unavailable (%s), falling back to mock", e)
            return MockLLMProvider()

    logger.warning("Unknown LLM provider '%s', falling back to mock", provider_name)
    return MockLLMProvider()


# Singleton provider instance
llm_provider = get_llm_provider()

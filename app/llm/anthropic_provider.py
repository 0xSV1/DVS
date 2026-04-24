"""Anthropic LLM provider.

Uses the anthropic Python SDK to call the Anthropic Messages API.
Requires ANTHROPIC_API_KEY to be set in the environment.
"""

from __future__ import annotations

import logging
from typing import AsyncGenerator

from anthropic import AsyncAnthropic

from app.core.config import settings
from app.llm.base import ChatMessage, LLMProvider

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "claude-haiku-4-5-20251001"


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API provider."""

    def __init__(self) -> None:
        self._api_key = settings.ANTHROPIC_API_KEY
        self._model = _DEFAULT_MODEL

        if not self._api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is required for the Anthropic provider. Set it in your .env file or environment."
            )

        self._client = AsyncAnthropic(api_key=self._api_key)
        logger.info("Anthropic provider initialized (model=%s)", self._model)

    def _split_messages(self, messages: list[ChatMessage]) -> tuple[str, list[dict]]:
        """Split ChatMessage list into system prompt and message list.

        The Anthropic API takes the system prompt as a separate parameter,
        not as a message in the list.
        """
        system = ""
        api_messages = []

        for msg in messages:
            if msg.role == "system":
                system = msg.content
            else:
                api_messages.append({"role": msg.role, "content": msg.content})

        # Anthropic requires at least one user message
        if not api_messages:
            api_messages.append({"role": "user", "content": "Hello"})

        return system, api_messages

    async def chat(self, messages: list[ChatMessage]) -> str:
        """Send messages and return a complete response."""
        system, api_messages = self._split_messages(messages)

        try:
            response = await self._client.messages.create(
                model=self._model,
                system=system,
                messages=api_messages,
                max_tokens=1024,
            )
            return response.content[0].text
        except Exception:
            logger.exception("Anthropic chat request failed")
            return (
                "BroBot is experiencing technical difficulties. The AI co-founder is probably napping. Try again, bro."
            )

    async def chat_stream(self, messages: list[ChatMessage]) -> AsyncGenerator[str, None]:
        """Send messages and yield response tokens as they arrive."""
        system, api_messages = self._split_messages(messages)

        try:
            async with self._client.messages.stream(
                model=self._model,
                system=system,
                messages=api_messages,
                max_tokens=1024,
            ) as stream:
                async for text in stream.text_stream:
                    yield text
        except Exception:
            logger.exception("Anthropic stream request failed")
            yield "BroBot is experiencing technical difficulties. Try again, bro."

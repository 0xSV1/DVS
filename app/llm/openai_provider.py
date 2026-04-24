"""OpenAI LLM provider.

Uses the openai Python SDK to call the OpenAI Chat Completions API.
Requires OPENAI_API_KEY to be set in the environment.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import AsyncGenerator

from openai import AsyncOpenAI

from app.core.config import settings
from app.llm.base import ChatMessage, LLMProvider

logger = logging.getLogger(__name__)

# Default model if none is configured
_DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider(LLMProvider):
    """OpenAI Chat Completions provider."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
    ) -> None:
        self._api_key = api_key or settings.OPENAI_API_KEY
        self._base_url = base_url
        self._model = model or _DEFAULT_MODEL

        if not self._api_key:
            raise ValueError(
                "OPENAI_API_KEY is required for the OpenAI provider. Set it in your .env file or environment."
            )

        kwargs: dict = {"api_key": self._api_key}
        if self._base_url:
            kwargs["base_url"] = self._base_url

        self._client = AsyncOpenAI(**kwargs)
        logger.info(
            "OpenAI provider initialized (model=%s, base_url=%s)",
            self._model,
            self._base_url or "default",
        )

    def _to_api_messages(self, messages: list[ChatMessage]) -> list[dict]:
        """Convert ChatMessage list to OpenAI API format."""
        return [{"role": m.role, "content": m.content} for m in messages]

    @staticmethod
    def _strip_think_tags(text: str) -> str:
        """Remove <think>...</think> blocks from model output.

        Reasoning models (Qwen, DeepSeek) embed chain-of-thought in the
        content field wrapped in <think> tags. These are internal reasoning
        and should not be shown to the user.
        """
        return re.sub(r"<think>[\s\S]*?</think>", "", text).strip()

    @staticmethod
    def _is_degenerate(text: str) -> bool:
        """Detect degenerate model output: repetitive loops, gibberish, etc.

        Returns True if the text appears to be a degenerate generation that
        should be retried or replaced with a fallback message.
        """
        if not text or len(text.strip()) < 5:
            return True

        # Non-ASCII ratio: flag if >50% non-ASCII (Mandarin gibberish)
        non_ascii = sum(1 for c in text if ord(c) > 127)
        if len(text) > 20 and non_ascii / len(text) > 0.5:
            return True

        # Repetition: split into 4-char chunks, flag if any repeats >10 times
        chunks = [text[i : i + 4] for i in range(0, len(text) - 3, 4)]
        if chunks:
            most_common_count = Counter(chunks).most_common(1)[0][1]
            if most_common_count > 10:
                return True

        # Excessive length with no substance (repetitive padding)
        if len(text) > 3000:
            unique_words = set(text.lower().split())
            if len(unique_words) < 30:
                return True

        return False

    _DEGENERATE_FALLBACK = (
        "BroBot's circuits are a bit scrambled right now. The AI co-founder probably needs a reboot. Try again, bro."
    )

    def _extract_content(self, message: object) -> str:
        """Extract text from a chat completion message.

        Handles reasoning/thinking models (e.g. Qwen, DeepSeek) that put
        their output in a ``reasoning`` field and may leave ``content`` empty
        until the thinking budget is exhausted.
        """
        content = getattr(message, "content", None) or ""
        if content:
            return self._strip_think_tags(content)
        # Fallback for thinking models served via Ollama: the visible
        # output lands in an extra ``reasoning`` field when the token
        # budget is consumed by chain-of-thought before content is produced.
        reasoning = getattr(message, "reasoning", None) or ""
        if reasoning:
            return self._strip_think_tags(reasoning)
        return ""

    async def chat(self, messages: list[ChatMessage]) -> str:
        """Send messages and return a complete response.

        Includes degenerate output detection: if the first response is
        gibberish or repetitive, retries once with higher temperature.
        """
        api_messages = self._to_api_messages(messages)

        for attempt in range(2):
            try:
                temperature = 0.7 if attempt == 0 else 0.9
                response = await self._client.chat.completions.create(
                    model=self._model,
                    messages=api_messages,
                    max_tokens=4096,
                    temperature=temperature,
                )
                content = self._extract_content(response.choices[0].message)

                if not self._is_degenerate(content):
                    return content

                logger.warning(
                    "Degenerate output detected (attempt %d, len=%d), %s",
                    attempt + 1,
                    len(content),
                    "retrying with higher temperature" if attempt == 0 else "returning fallback",
                )
            except Exception:
                logger.exception("OpenAI chat request failed (attempt %d)", attempt + 1)
                if attempt == 0:
                    continue
                return (
                    "BroBot is experiencing technical difficulties. "
                    "The AI co-founder is probably napping. Try again, bro."
                )

        return self._DEGENERATE_FALLBACK

    async def chat_stream(self, messages: list[ChatMessage]) -> AsyncGenerator[str, None]:
        """Send messages and yield response tokens as they arrive.

        Monitors the accumulating buffer for degenerate output. If detected
        mid-stream, stops yielding and sends a fallback message.
        """
        try:
            stream = await self._client.chat.completions.create(
                model=self._model,
                messages=self._to_api_messages(messages),
                max_tokens=4096,
                temperature=0.7,
                stream=True,
            )
            in_think_block = False
            buffer = ""
            async for chunk in stream:
                delta = chunk.choices[0].delta
                if delta.content:
                    token = delta.content
                    # Suppress <think>...</think> blocks in streamed output
                    if "<think>" in token:
                        in_think_block = True
                    if in_think_block:
                        if "</think>" in token:
                            in_think_block = False
                            after = token.split("</think>", 1)[1]
                            if after:
                                buffer += after
                                yield after
                        continue
                    buffer += token
                    yield token

                    # Check for degenerate output periodically
                    if len(buffer) > 2000 and self._is_degenerate(buffer):
                        logger.warning("Degenerate stream detected at %d chars, stopping", len(buffer))
                        yield f"\n\n{self._DEGENERATE_FALLBACK}"
                        return
        except Exception:
            logger.exception("OpenAI stream request failed")
            yield "BroBot is experiencing technical difficulties. Try again, bro."

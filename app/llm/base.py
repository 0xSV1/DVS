"""Abstract base class for LLM providers.

All providers implement the same interface: chat() for single responses
and chat_stream() for streamed token output. The canonical message format
is OpenAI-style [{role, content}] dicts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncGenerator


@dataclass
class ChatMessage:
    """A single message in a chat conversation."""

    role: str  # "system", "user", "assistant"
    content: str


class LLMProvider(ABC):
    """Abstract LLM provider interface."""

    @abstractmethod
    async def chat(self, messages: list[ChatMessage]) -> str:
        """Send messages and return a complete response."""
        ...

    @abstractmethod
    async def chat_stream(self, messages: list[ChatMessage]) -> AsyncGenerator[str, None]:
        """Send messages and yield response tokens as they arrive."""
        ...

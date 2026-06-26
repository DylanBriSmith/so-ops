"""LLMClient protocol — implemented by OllamaClient and OpenRouterClient."""

from __future__ import annotations

from typing import Protocol


class LLMClient(Protocol):
    def generate(
        self,
        prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        timeout: int = 120,
    ) -> str: ...

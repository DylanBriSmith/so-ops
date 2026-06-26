"""LLM client factory."""

from __future__ import annotations

from so_ops.clients.base import LLMClient


def make_llm_client(cfg) -> LLMClient:
    """Return the configured LLM client (Ollama or OpenRouter)."""
    provider = getattr(cfg, "llm_provider", "ollama")
    if provider == "openrouter":
        from so_ops.clients.openrouter import OpenRouterClient

        if cfg.openrouter is None:
            raise RuntimeError(
                "llm_provider = 'openrouter' but no [openrouter] section in config"
            )
        return OpenRouterClient(cfg.openrouter)

    from so_ops.clients.ollama import OllamaClient

    if cfg.ollama is None:
        raise RuntimeError(
            "llm_provider = 'ollama' but no [ollama] section in config"
        )
    return OllamaClient(cfg.ollama)

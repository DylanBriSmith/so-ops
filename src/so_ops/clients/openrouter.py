"""OpenRouter LLM client (OpenAI-compatible API, zero third-party deps)."""

from __future__ import annotations

import json
import urllib.request

from so_ops.config import OpenRouterConfig


class OpenRouterClient:
    """HTTP client for OpenRouter's chat completions API."""

    def __init__(self, cfg: OpenRouterConfig):
        self._url = cfg.base_url.rstrip("/") + "/chat/completions"
        self._model = cfg.model
        self._api_key = cfg.api_key

    def generate(
        self,
        prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        timeout: int = 120,
    ) -> str:
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(self._url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self._api_key}")
        req.add_header("HTTP-Referer", "https://github.com/benolenick/so-ops")
        req.add_header("X-Title", "so-ops")
        resp = urllib.request.urlopen(req, timeout=timeout)
        result = json.loads(resp.read().decode())
        return result["choices"][0]["message"]["content"]

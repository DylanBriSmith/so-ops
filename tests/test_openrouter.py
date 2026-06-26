"""Tests for OpenRouter client and LLM provider selection."""

from __future__ import annotations

import json
import textwrap
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from so_ops.clients import make_llm_client
from so_ops.clients.ollama import OllamaClient
from so_ops.clients.openrouter import OpenRouterClient
from so_ops.config import OpenRouterConfig, load_config


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _write_toml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "config.toml"
    p.write_text(textwrap.dedent(content))
    return p


@pytest.fixture
def ollama_config_path(tmp_path):
    return _write_toml(
        tmp_path,
        """
        [elasticsearch]
        host = "https://so-manager:9200"
        user = "so_ops"
        password = "secret"

        [ollama]
        url = "http://localhost:11434"
        model = "qwen3:14b"

        [paths]
        data_dir = "~/so-ops-data"
        """,
    )


@pytest.fixture
def openrouter_config_path(tmp_path):
    return _write_toml(
        tmp_path,
        """
        llm_provider = "openrouter"

        [elasticsearch]
        host = "https://so-manager:9200"
        user = "so_ops"
        password = "secret"

        [openrouter]
        model = "anthropic/claude-haiku-4-5"
        api_key = "sk-or-test-key"

        [paths]
        data_dir = "~/so-ops-data"
        """,
    )


# ── Config loading ────────────────────────────────────────────────────────────


def test_ollama_config_loads(ollama_config_path):
    cfg = load_config(ollama_config_path)
    assert cfg.llm_provider == "ollama"
    assert cfg.ollama is not None
    assert cfg.ollama.url == "http://localhost:11434"
    assert cfg.ollama.model == "qwen3:14b"
    assert cfg.openrouter is None


def test_openrouter_config_loads(openrouter_config_path):
    cfg = load_config(openrouter_config_path)
    assert cfg.llm_provider == "openrouter"
    assert cfg.openrouter is not None
    assert cfg.openrouter.model == "anthropic/claude-haiku-4-5"
    assert cfg.openrouter.api_key == "sk-or-test-key"
    assert cfg.openrouter.base_url == "https://openrouter.ai/api/v1"
    assert cfg.ollama is None


def test_openrouter_api_key_from_env(tmp_path, monkeypatch):
    path = _write_toml(
        tmp_path,
        """
        llm_provider = "openrouter"

        [elasticsearch]
        host = "https://so-manager:9200"
        user = "so_ops"
        password = "secret"

        [openrouter]
        model = "anthropic/claude-haiku-4-5"

        [paths]
        data_dir = "~/so-ops-data"
        """,
    )
    monkeypatch.setenv("SO_OPS_OR_API_KEY", "sk-or-from-env")
    cfg = load_config(path)
    assert cfg.openrouter.api_key == "sk-or-from-env"


def test_openrouter_env_key_overrides_config(openrouter_config_path, monkeypatch):
    monkeypatch.setenv("SO_OPS_OR_API_KEY", "sk-or-override")
    cfg = load_config(openrouter_config_path)
    assert cfg.openrouter.api_key == "sk-or-override"


def test_openrouter_custom_base_url(tmp_path):
    path = _write_toml(
        tmp_path,
        """
        llm_provider = "openrouter"

        [elasticsearch]
        host = "https://so-manager:9200"
        user = "so_ops"
        password = "secret"

        [openrouter]
        model = "anthropic/claude-haiku-4-5"
        api_key = "sk-test"
        base_url = "https://my-proxy.example.com/v1"

        [paths]
        data_dir = "~/so-ops-data"
        """,
    )
    cfg = load_config(path)
    assert cfg.openrouter.base_url == "https://my-proxy.example.com/v1"


# ── Config validation errors ──────────────────────────────────────────────────


def test_invalid_llm_provider_exits(tmp_path):
    path = _write_toml(
        tmp_path,
        """
        llm_provider = "badprovider"

        [elasticsearch]
        host = "https://so-manager:9200"
        user = "so_ops"
        password = "secret"

        [ollama]
        url = "http://localhost:11434"
        model = "qwen3:14b"

        [paths]
        data_dir = "~/so-ops-data"
        """,
    )
    with pytest.raises(SystemExit):
        load_config(path)


def test_openrouter_provider_without_section_exits(tmp_path):
    path = _write_toml(
        tmp_path,
        """
        llm_provider = "openrouter"

        [elasticsearch]
        host = "https://so-manager:9200"
        user = "so_ops"
        password = "secret"

        [ollama]
        url = "http://localhost:11434"
        model = "qwen3:14b"

        [paths]
        data_dir = "~/so-ops-data"
        """,
    )
    with pytest.raises(SystemExit):
        load_config(path)


def test_ollama_provider_without_section_exits(tmp_path):
    path = _write_toml(
        tmp_path,
        """
        llm_provider = "ollama"

        [elasticsearch]
        host = "https://so-manager:9200"
        user = "so_ops"
        password = "secret"

        [openrouter]
        model = "anthropic/claude-haiku-4-5"
        api_key = "sk-test"

        [paths]
        data_dir = "~/so-ops-data"
        """,
    )
    with pytest.raises(SystemExit):
        load_config(path)


# ── make_llm_client factory ───────────────────────────────────────────────────


def test_factory_returns_ollama_client(ollama_config_path):
    cfg = load_config(ollama_config_path)
    client = make_llm_client(cfg)
    assert isinstance(client, OllamaClient)


def test_factory_returns_openrouter_client(openrouter_config_path):
    cfg = load_config(openrouter_config_path)
    client = make_llm_client(cfg)
    assert isinstance(client, OpenRouterClient)


def test_factory_raises_if_provider_missing_section():
    cfg = MagicMock()
    cfg.llm_provider = "openrouter"
    cfg.openrouter = None
    with pytest.raises(RuntimeError, match="no \\[openrouter\\] section"):
        make_llm_client(cfg)


def test_factory_raises_if_ollama_section_missing():
    cfg = MagicMock()
    cfg.llm_provider = "ollama"
    cfg.ollama = None
    with pytest.raises(RuntimeError, match="no \\[ollama\\] section"):
        make_llm_client(cfg)


# ── OpenRouterClient HTTP behaviour ──────────────────────────────────────────


def _make_mock_response(content: str) -> MagicMock:
    body = json.dumps({
        "choices": [{"message": {"content": content}}]
    }).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


@pytest.fixture
def or_client():
    cfg = OpenRouterConfig(
        model="anthropic/claude-haiku-4-5",
        api_key="sk-or-test",
    )
    return OpenRouterClient(cfg)


def test_openrouter_returns_response_text(or_client):
    mock_resp = _make_mock_response("NOISE: benign traffic")
    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = or_client.generate("triage this alert")
    assert result == "NOISE: benign traffic"


def test_openrouter_sends_correct_model(or_client):
    mock_resp = _make_mock_response("ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        or_client.generate("test prompt")

    req = mock_open.call_args[0][0]
    body = json.loads(req.data.decode())
    assert body["model"] == "anthropic/claude-haiku-4-5"


def test_openrouter_sends_prompt_as_user_message(or_client):
    mock_resp = _make_mock_response("ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        or_client.generate("classify this alert")

    req = mock_open.call_args[0][0]
    body = json.loads(req.data.decode())
    assert body["messages"] == [{"role": "user", "content": "classify this alert"}]


def test_openrouter_sends_temperature(or_client):
    mock_resp = _make_mock_response("ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        or_client.generate("prompt", temperature=0.1)

    req = mock_open.call_args[0][0]
    body = json.loads(req.data.decode())
    assert body["temperature"] == 0.1


def test_openrouter_sends_max_tokens(or_client):
    mock_resp = _make_mock_response("ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        or_client.generate("prompt", max_tokens=512)

    req = mock_open.call_args[0][0]
    body = json.loads(req.data.decode())
    assert body["max_tokens"] == 512


def test_openrouter_sends_auth_header(or_client):
    mock_resp = _make_mock_response("ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        or_client.generate("prompt")

    req = mock_open.call_args[0][0]
    assert req.get_header("Authorization") == "Bearer sk-or-test"


def test_openrouter_sends_content_type(or_client):
    mock_resp = _make_mock_response("ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        or_client.generate("prompt")

    req = mock_open.call_args[0][0]
    assert req.get_header("Content-type") == "application/json"


def test_openrouter_uses_correct_endpoint(or_client):
    mock_resp = _make_mock_response("ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        or_client.generate("prompt")

    req = mock_open.call_args[0][0]
    assert req.full_url == "https://openrouter.ai/api/v1/chat/completions"


def test_openrouter_custom_base_url_used():
    cfg = OpenRouterConfig(
        model="openai/gpt-4o-mini",
        api_key="sk-test",
        base_url="https://proxy.example.com/v1",
    )
    client = OpenRouterClient(cfg)
    mock_resp = _make_mock_response("ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        client.generate("prompt")

    req = mock_open.call_args[0][0]
    assert req.full_url == "https://proxy.example.com/v1/chat/completions"


def test_openrouter_passes_timeout(or_client):
    mock_resp = _make_mock_response("ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        or_client.generate("prompt", timeout=60)

    assert mock_open.call_args[1]["timeout"] == 60

"""Live integration tests against the real OpenRouter API.

Requires SO_OPS_OR_API_KEY to be set. Run with:
    pytest tests/test_openrouter_live.py -v -m integration
"""

from __future__ import annotations

import json
import os

import pytest

from so_ops.clients.openrouter import OpenRouterClient
from so_ops.config import OpenRouterConfig

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def live_client():
    api_key = os.environ.get("SO_OPS_OR_API_KEY")
    if not api_key:
        pytest.skip("SO_OPS_OR_API_KEY not set")
    cfg = OpenRouterConfig(model="anthropic/claude-haiku-4-5", api_key=api_key)
    return OpenRouterClient(cfg)


def test_live_basic_response(live_client):
    """API returns a non-empty string."""
    result = live_client.generate("Reply with only the word PONG.", temperature=0.0, max_tokens=10)
    assert isinstance(result, str)
    assert len(result.strip()) > 0
    assert "PONG" in result.upper()


def test_live_triage_prompt_returns_valid_json(live_client):
    """A realistic triage prompt returns parseable JSON with the expected fields."""
    prompt = """You are a Security Operations Center analyst triaging IDS alerts.

Alert group to triage:
- Rule: ET SCAN Potential SSH Scan
- Source IP: 185.234.218.55
- Destinations: 192.168.1.10:22
- Alert count: 47
- Category: Attempted Information Leak

Classify into ONE of: NOISE, LOW, MEDIUM, HIGH.

Respond in this exact JSON format (no other text):
{"verdict": "NOISE|LOW|MEDIUM|HIGH", "reason": "Brief explanation (1-2 sentences)", "recommendation": "What to do (1 sentence)"}"""

    result = live_client.generate(prompt, temperature=0.1, max_tokens=256)

    # Must be parseable JSON
    start = result.find("{")
    end = result.rfind("}") + 1
    assert start >= 0 and end > start, f"No JSON object found in response: {result!r}"

    parsed = json.loads(result[start:end])
    assert "verdict" in parsed, f"Missing 'verdict' key: {parsed}"
    assert parsed["verdict"] in ("NOISE", "LOW", "MEDIUM", "HIGH"), f"Unexpected verdict: {parsed['verdict']}"
    assert "reason" in parsed
    assert "recommendation" in parsed

    # SSH scan from external IP should be at least MEDIUM
    assert parsed["verdict"] in ("MEDIUM", "HIGH"), (
        f"Expected MEDIUM or HIGH for SSH scan from external IP, got {parsed['verdict']}"
    )


def test_live_temperature_affects_determinism(live_client):
    """At temperature=0 the same prompt returns consistent verdicts."""
    prompt = """Classify this alert. Reply with only one word: NOISE, LOW, MEDIUM, or HIGH.
Alert: ET INFO Microsoft Connection Test from 192.168.1.5"""

    results = {live_client.generate(prompt, temperature=0.0, max_tokens=5) for _ in range(3)}
    # All three responses should be the same word at temp=0
    assert len(results) == 1, f"Expected consistent output at temp=0, got: {results}"


def test_live_max_tokens_limits_response(live_client):
    """max_tokens=5 produces a very short response."""
    result = live_client.generate("Count from 1 to 100.", temperature=0.0, max_tokens=5)
    # Can't assert exact token count but response should be very short
    assert len(result.split()) <= 15, f"Response unexpectedly long with max_tokens=5: {result!r}"


def test_live_health_briefing_prompt(live_client):
    """A health briefing prompt returns structured output."""
    prompt = """You are a SOC analyst. Write a one-sentence morning briefing status for a network
that had 0 HIGH alerts, 3 MEDIUM alerts, and 150 NOISE alerts in the last 24 hours.
Start with either Green, Yellow, or Red status."""

    result = live_client.generate(prompt, temperature=0.3, max_tokens=100)
    assert isinstance(result, str)
    assert len(result.strip()) > 0
    assert any(word in result for word in ("Green", "Yellow", "Red", "green", "yellow", "red"))

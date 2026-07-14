"""Tests for the claude-api backend's thinking / max_tokens configuration.

Thinking is off by default: some models (e.g. claude-sonnet-5) think when
the parameter is omitted and prepend a ThinkingBlock, so PwnGuard always
sends an explicit type. The configured value is passed straight through -
the API rejects a mode the model doesn't support.
"""

import sys
import types

import pytest

import pwnguard.backends.claude_api as api
from pwnguard.constants import DEFAULT_CONFIG


class _TextBlock:
    type = "text"
    text = '{"findings": []}'


class _Message:
    content = [_TextBlock()]
    stop_reason = "end_turn"


@pytest.fixture
def capture_create(monkeypatch):
    """Stub the anthropic SDK; capture the kwargs passed to messages.create."""
    captured = {}

    class _Messages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return _Message()

    class _Anthropic:
        def __init__(self, api_key=None):
            self.messages = _Messages()

    fake = types.ModuleType("anthropic")
    fake.Anthropic = _Anthropic
    fake.APIConnectionError = type("APIConnectionError", (Exception,), {})
    fake.APIStatusError = type("APIStatusError", (Exception,), {})

    monkeypatch.setitem(sys.modules, "anthropic", fake)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    return captured


def test_thinking_is_disabled_by_default(capture_create):
    api.query_claude_api("diff", {}, "system")

    assert capture_create["thinking"] == {"type": "disabled"}


def test_shipped_default_config_keeps_thinking_off(capture_create):
    """The documented default must not silently start billing for reasoning."""
    api.query_claude_api("diff", DEFAULT_CONFIG, "system")

    assert capture_create["thinking"] == {"type": "disabled"}
    assert capture_create["max_tokens"] == 8192


def test_adaptive_thinking_is_passed_through(capture_create):
    api.query_claude_api("diff", {"claude_api": {"thinking": "adaptive"}}, "system")

    assert capture_create["thinking"] == {"type": "adaptive"}


def test_enabled_thinking_derives_budget_from_max_tokens(capture_create):
    """budget_tokens must stay strictly below max_tokens or the API 400s."""
    config = {"claude_api": {"thinking": "enabled", "max_tokens": 8192}}
    api.query_claude_api("diff", config, "system")

    assert capture_create["thinking"] == {"type": "enabled", "budget_tokens": 4096}
    assert capture_create["thinking"]["budget_tokens"] < capture_create["max_tokens"]


def test_budget_is_not_derived_when_thinking_is_off(capture_create):
    api.query_claude_api("diff", {"claude_api": {"max_tokens": 8192}}, "system")

    assert "budget_tokens" not in capture_create["thinking"]

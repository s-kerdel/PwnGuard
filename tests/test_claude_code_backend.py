"""Tests for the claude-code backend's credential handling.

The claude-code backend runs on the user's Claude subscription by default:
it strips ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN from the ``claude``
subprocess so Claude Code cannot silently bill the API per-token in headless
mode. Setting ``claude_code.prefer_api_key`` restores them.
"""

import pytest

import pwnguard.backends.claude_code as cc


class _FakeCompleted:
    returncode = 0
    stdout = '{"findings": []}'
    stderr = ""


@pytest.fixture
def capture_env(monkeypatch):
    """Stub claude availability + subprocess.run; capture the env passed."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["env"] = kwargs.get("env")
        return _FakeCompleted()

    monkeypatch.setattr(cc, "claude_code_available", lambda: True)
    monkeypatch.setattr(cc.subprocess, "run", fake_run)
    return captured


def test_strips_api_credentials_by_default(capture_env, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "tok-secret")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-keep")

    cc.query_claude_code("diff", {}, "system")

    env = capture_env["env"]
    assert "ANTHROPIC_API_KEY" not in env
    assert "ANTHROPIC_AUTH_TOKEN" not in env
    # Subscription-for-CI credential must be preserved.
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "oauth-keep"


def test_forwards_api_key_when_opted_in(capture_env, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")

    cc.query_claude_code(
        "diff", {"claude_code": {"prefer_api_key": True}}, "system"
    )

    assert capture_env["env"]["ANTHROPIC_API_KEY"] == "sk-secret"


def test_no_api_key_present_is_a_noop(capture_env, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)

    result = cc.query_claude_code("diff", {}, "system")

    assert result == '{"findings": []}'
    assert "ANTHROPIC_API_KEY" not in capture_env["env"]

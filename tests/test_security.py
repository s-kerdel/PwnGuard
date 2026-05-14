"""Tests for security-critical helpers.

These are the boundary defences that protect what the auditor reports
and what gets handed to ``git``. A regression here is a security
regression, not a feature regression.
"""
import pytest

import audit


# ---------------------------------------------------------------------------
# _sanitize: ANSI / control-char stripper for AI-supplied text
# ---------------------------------------------------------------------------

def test_sanitize_strips_ansi_escape():
    """A prompt-injected diff could coax the model into emitting
    \\x1b[31m to recolor / hide content in the dev's terminal."""
    raw = "\x1b[31mfake red text\x1b[0m"
    cleaned = audit._sanitize(raw)
    assert "\x1b" not in cleaned
    # The visible characters survive.
    assert "fake red text" in cleaned


def test_sanitize_strips_carriage_return():
    """\\r could overwrite the current line in a terminal."""
    cleaned = audit._sanitize("safe\rEVIL")
    assert "\r" not in cleaned


def test_sanitize_strips_bell_and_backspace():
    cleaned = audit._sanitize("foo\x07\x08bar")
    assert "\x07" not in cleaned
    assert "\x08" not in cleaned
    assert "foo" in cleaned and "bar" in cleaned


def test_sanitize_strips_delete_char():
    cleaned = audit._sanitize("a\x7fb")
    assert "\x7f" not in cleaned


def test_sanitize_preserves_tab():
    """Tab is whitelisted - legit in indented code snippets."""
    assert audit._sanitize("a\tb") == "a\tb"


def test_sanitize_preserves_newline():
    """Newline is whitelisted - legit in multi-line descriptions."""
    assert audit._sanitize("line 1\nline 2") == "line 1\nline 2"


def test_sanitize_passes_plain_ascii_unchanged():
    assert audit._sanitize("hello world") == "hello world"


def test_sanitize_preserves_unicode():
    """Non-ASCII (UTF-8) content is not control-char territory."""
    assert audit._sanitize("naïve résumé €") == "naïve résumé €"


def test_sanitize_none_passes_through():
    assert audit._sanitize(None) is None


def test_sanitize_empty_string_passes_through():
    assert audit._sanitize("") == ""


# ---------------------------------------------------------------------------
# _is_safe_ref: argument-injection guard for CI_MERGE_REQUEST_TARGET_BRANCH_NAME
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ref", [
    "main",
    "develop",
    "feature/add-login",
    "release/v1.2.3",
    "fix-issue-123",
    "user/feature",
])
def test_safe_refs_accepted(ref):
    assert audit._is_safe_ref(ref) is True


@pytest.mark.parametrize("ref", [
    "",                       # empty - no branch
    "-upload-pack=evil",      # would land as a git option
    "--no-verify",            # another option-looking name
    "/etc/passwd",            # absolute path
    "../etc/passwd",          # path traversal
    "branch/../../../etc",    # embedded traversal
    "branch\nfake-line",      # newline injection
    "branch\x00null",         # null byte
])
def test_unsafe_refs_rejected(ref):
    assert audit._is_safe_ref(ref) is False

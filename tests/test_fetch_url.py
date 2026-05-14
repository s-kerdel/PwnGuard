"""Tests for the --from-url dispatch + token forwarding.

Slim subset: locks in the URL -> platform mapping (the regex shapes
that decide GitLab vs GitHub) and verifies each fetcher carries the
right auth header from the right env var. Does NOT test HTTP itself -
``_http_get`` is replaced with a recorder so the tests stay
deterministic, offline, and never need real tokens.
"""
import json

import pytest

import audit
import pwnguard.fetchers


# ---------------------------------------------------------------------------
# Recorder fixture: replaces _http_get with a fake that captures what
# the caller tried to send and returns a configurable response.
# ---------------------------------------------------------------------------

@pytest.fixture
def captured(monkeypatch):
    state = {"url": None, "headers": None, "response": b""}

    def fake_http_get(url, headers):
        state["url"] = url
        state["headers"] = headers
        return state["response"]

    # _http_get's actual home after the split is pwnguard.fetchers.
    # Patching audit._http_get would only reassign the re-exported
    # alias on the shim; the call sites inside pwnguard.fetchers
    # would still hit the original. Target the real module.
    monkeypatch.setattr(pwnguard.fetchers, "_http_get", fake_http_get)
    return state


# Compact JSON body shaped like the GitLab "commit diff" API response.
_GITLAB_COMMIT_JSON = json.dumps([{
    "old_path": "x.py",
    "new_path": "x.py",
    "diff": "--- a/x.py\n+++ b/x.py\n@@ -1,1 +1,1 @@\n hi\n",
}]).encode()

# Plain unified diff body used by raw-diff endpoints (GitLab raw_diffs,
# GitHub v3.diff Accept).
_RAW_DIFF = (
    b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n hi\n"
)


# ---------------------------------------------------------------------------
# URL dispatch - the regex shapes that decide which fetcher runs
# ---------------------------------------------------------------------------

def test_gitlab_mr_routes_to_raw_diffs(captured, monkeypatch):
    captured["response"] = _RAW_DIFF
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")

    diff = audit.fetch_from_url(
        "https://gitlab.com/group/project/-/merge_requests/123"
    )

    assert "diff --git" in diff
    assert "/merge_requests/123/raw_diffs" in captured["url"]


def test_gitlab_mr_with_commit_id_routes_to_commit_endpoint(captured, monkeypatch):
    """``?commit_id=SHA`` switches from the full-MR raw_diffs path to
    the per-commit diff endpoint."""
    captured["response"] = _GITLAB_COMMIT_JSON
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")

    diff = audit.fetch_from_url(
        "https://gitlab.com/group/project/-/merge_requests/123/diffs"
        "?commit_id=deadbeef"
    )

    assert "diff --git" in diff
    assert "/commits/deadbeef/diff" in captured["url"]
    # Definitely NOT the raw_diffs path.
    assert "raw_diffs" not in captured["url"]


def test_gitlab_standalone_commit_routes_to_commit_endpoint(captured, monkeypatch):
    captured["response"] = _GITLAB_COMMIT_JSON
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")

    diff = audit.fetch_from_url(
        "https://gitlab.com/group/project/-/commit/deadbeef"
    )

    assert "diff --git" in diff
    assert "/commits/deadbeef/diff" in captured["url"]


def test_gitlab_commit_reassembly_synthesises_missing_file_headers(captured, monkeypatch):
    """GitLab's commit-diff API returns each file's ``diff`` body
    starting at ``@@`` - the ``--- a/X`` / ``+++ b/X`` lines are stripped
    and the paths live in separate JSON fields. The reassembly MUST
    put those header lines back; without them ``wrap_diff`` builds
    an empty anchor table and every model finding gets dropped as
    "unrecognised anchor". This is the bug that made monitor audits
    against GitLab commits look like silent zero-finding successes."""
    captured["response"] = json.dumps([{
        "old_path": "src/foo.py",
        "new_path": "src/foo.py",
        "diff": "@@ -1,1 +1,2 @@\n import os\n+import sys\n",
    }]).encode()
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")

    diff = audit.fetch_from_url(
        "https://gitlab.com/group/project/-/commit/abcd1234"
    )

    # All three header lines must be present so wrap_diff can attribute
    # content lines to src/foo.py.
    assert "diff --git a/src/foo.py b/src/foo.py" in diff
    assert "--- a/src/foo.py" in diff
    assert "+++ b/src/foo.py" in diff
    # And wrap_diff against the reassembled output must populate the
    # anchor table for the file (not silently produce an empty one).
    _, anchors = audit.wrap_diff(diff)
    assert anchors, "anchor table should not be empty after reassembly"
    assert any(m["file"] == "src/foo.py" for m in anchors.values())


def test_gitlab_commit_reassembly_handles_new_file(captured, monkeypatch):
    """New-file commits get ``--- /dev/null`` for the source header."""
    captured["response"] = json.dumps([{
        "old_path": "src/new.py",
        "new_path": "src/new.py",
        "new_file": True,
        "diff": "@@ -0,0 +1,2 @@\n+import os\n+print(os)\n",
    }]).encode()
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    diff = audit.fetch_from_url(
        "https://gitlab.com/g/p/-/commit/abcd1234"
    )
    assert "--- /dev/null" in diff
    assert "+++ b/src/new.py" in diff


def test_gitlab_commit_reassembly_passes_through_when_headers_present(captured, monkeypatch):
    """Some self-hosted GitLab versions include the file headers
    already. The reassembly must NOT double-emit them."""
    captured["response"] = json.dumps([{
        "old_path": "src/x.py",
        "new_path": "src/x.py",
        "diff": "--- a/src/x.py\n+++ b/src/x.py\n@@ -1,1 +1,1 @@\n-old\n+new\n",
    }]).encode()
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    diff = audit.fetch_from_url(
        "https://gitlab.com/g/p/-/commit/abcd1234"
    )
    # Exactly one occurrence of each header line.
    assert diff.count("--- a/src/x.py") == 1
    assert diff.count("+++ b/src/x.py") == 1


def test_github_pr_routes_to_pulls_endpoint(captured):
    captured["response"] = _RAW_DIFF

    diff = audit.fetch_from_url("https://github.com/owner/repo/pull/42")

    assert "diff --git" in diff
    assert "api.github.com" in captured["url"]
    assert "/pulls/42" in captured["url"]


def test_github_commit_routes_to_commits_endpoint(captured):
    captured["response"] = _RAW_DIFF

    diff = audit.fetch_from_url("https://github.com/owner/repo/commit/abcd1234")

    assert "diff --git" in diff
    assert "api.github.com" in captured["url"]
    assert "/commits/abcd1234" in captured["url"]


# ---------------------------------------------------------------------------
# Invalid URLs - fail-fast before any network attempt
# ---------------------------------------------------------------------------

def test_url_without_scheme_aborts(captured):
    with pytest.raises(SystemExit):
        audit.fetch_from_url("not-a-url")


def test_unrecognised_url_shape_aborts(captured):
    """A well-formed URL with no platform pattern bombs out instead of
    silently routing to the wrong fetcher."""
    with pytest.raises(SystemExit):
        audit.fetch_from_url("https://example.com/some/random/path")


# ---------------------------------------------------------------------------
# Token forwarding - the right env var ends up in the right header
# ---------------------------------------------------------------------------

def test_gitlab_forwards_private_token_header(captured, monkeypatch):
    """GitLab's API expects ``PRIVATE-TOKEN:``, not ``Authorization``.
    A regression that switched header name would leak the token to a
    server that ignores it AND skip auth - silent failure mode."""
    captured["response"] = _RAW_DIFF
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-my-token")

    audit.fetch_from_url("https://gitlab.com/g/p/-/merge_requests/1")

    assert captured["headers"].get("PRIVATE-TOKEN") == "glpat-my-token"
    assert "Authorization" not in captured["headers"]


def test_gitlab_aborts_when_token_missing(captured, monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.delenv("PWNGUARD_GITLAB_TOKEN", raising=False)

    with pytest.raises(SystemExit):
        audit.fetch_from_url("https://gitlab.com/g/p/-/merge_requests/1")


def test_github_forwards_bearer_token_when_set(captured, monkeypatch):
    captured["response"] = _RAW_DIFF
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-my-token")

    audit.fetch_from_url("https://github.com/owner/repo/pull/1")

    assert captured["headers"].get("Authorization") == "Bearer ghp-my-token"


def test_github_anonymous_request_omits_authorization(captured, monkeypatch):
    """Public GitHub PRs work without a token (just heavily rate-limited).
    No bogus Authorization header should be sent in that case."""
    captured["response"] = _RAW_DIFF
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("PWNGUARD_GITHUB_TOKEN", raising=False)

    audit.fetch_from_url("https://github.com/owner/repo/pull/1")

    assert "Authorization" not in captured["headers"]

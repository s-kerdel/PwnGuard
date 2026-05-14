"""Tests for the monitor list-commits endpoints + URL dispatch.

Mocks _http_get the same way test_fetch_url.py does. Verifies that
each platform's list endpoint is hit with the right URL, auth headers,
and branch / limit parameters - and that the response is parsed back
into a list of SHAs.
"""
import json

import pytest

import audit
import pwnguard.fetchers


@pytest.fixture
def captured(monkeypatch):
    state = {"url": None, "headers": None, "response": b"[]"}

    def fake_http_get(url, headers):
        state["url"] = url
        state["headers"] = headers
        return state["response"]

    # See test_fetch_url.py for why we patch the source module rather
    # than the audit.py shim.
    monkeypatch.setattr(pwnguard.fetchers, "_http_get", fake_http_get)
    return state


# ---------------------------------------------------------------------------
# list_commits_from_url - dispatch
# ---------------------------------------------------------------------------

def test_gitlab_url_routes_to_repository_commits(captured, monkeypatch):
    captured["response"] = json.dumps([{
        "id": "abc1234",
        "committed_date": "2026-05-14T09:00:00.000+00:00",
    }]).encode()
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")

    commits = audit.list_commits_from_url(
        "https://gitlab.com/group/project", "main", limit=1,
    )

    assert commits == [("abc1234", "2026-05-14T09:00:00.000+00:00")]
    assert "/repository/commits" in captured["url"]
    assert "ref_name=main" in captured["url"]
    assert "per_page=1" in captured["url"]


def test_gitlab_commit_without_date_returns_none(captured, monkeypatch):
    """Older GitLab versions / unusual responses may omit
    ``committed_date``. The shape stays a tuple; date slot is None."""
    captured["response"] = json.dumps([{"id": "abc1234"}]).encode()
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test")
    commits = audit.list_commits_from_url("https://gitlab.com/g/p", "main")
    assert commits == [("abc1234", None)]


def test_github_url_routes_to_commits_endpoint(captured):
    captured["response"] = json.dumps([{
        "sha": "deadbeef",
        "commit": {"committer": {"date": "2026-05-14T09:00:00Z"}},
    }]).encode()

    commits = audit.list_commits_from_url(
        "https://github.com/owner/repo", "main", limit=1,
    )

    assert commits == [("deadbeef", "2026-05-14T09:00:00Z")]
    assert "api.github.com" in captured["url"]
    assert "/commits" in captured["url"]
    assert "sha=main" in captured["url"]


def test_github_commit_without_committer_date_returns_none(captured):
    """Some GitHub responses lack ``commit.committer.date`` (rare,
    but defensive). Tuple shape preserved; date slot is None."""
    captured["response"] = json.dumps([{"sha": "deadbeef"}]).encode()
    commits = audit.list_commits_from_url(
        "https://github.com/o/r", "main",
    )
    assert commits == [("deadbeef", None)]


@pytest.mark.parametrize("url", [
    "https://gitlab.internal.example.com/team/api",
    "https://gitlab.acme.dev/team/api",
])
def test_self_hosted_gitlab_recognised_by_hostname(captured, monkeypatch, url):
    """Any hostname containing 'gitlab' routes to the GitLab fetcher."""
    captured["response"] = json.dumps([{"id": "abc"}]).encode()
    monkeypatch.setenv("GITLAB_TOKEN", "glpat")
    commits = audit.list_commits_from_url(url, "main")
    assert commits == [("abc", None)]
    assert "/api/v4/projects/" in captured["url"]


def test_unknown_host_aborts(captured):
    with pytest.raises(SystemExit):
        audit.list_commits_from_url(
            "https://random-vcs.example.com/owner/repo", "main",
        )


def test_invalid_url_aborts(captured):
    with pytest.raises(SystemExit):
        audit.list_commits_from_url("not-a-url", "main")


# ---------------------------------------------------------------------------
# Token forwarding
# ---------------------------------------------------------------------------

def test_gitlab_list_forwards_private_token(captured, monkeypatch):
    captured["response"] = json.dumps([]).encode()
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-my-token")

    audit.list_commits_from_url(
        "https://gitlab.com/g/p", "main",
    )

    assert captured["headers"].get("PRIVATE-TOKEN") == "glpat-my-token"


def test_gitlab_list_aborts_without_token(captured, monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.delenv("PWNGUARD_GITLAB_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        audit.list_commits_from_url("https://gitlab.com/g/p", "main")


def test_github_list_forwards_bearer_when_set(captured, monkeypatch):
    captured["response"] = json.dumps([]).encode()
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-my-token")

    audit.list_commits_from_url("https://github.com/o/r", "main")

    assert captured["headers"].get("Authorization") == "Bearer ghp-my-token"


def test_github_list_omits_authorization_when_no_token(captured, monkeypatch):
    captured["response"] = json.dumps([]).encode()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("PWNGUARD_GITHUB_TOKEN", raising=False)

    audit.list_commits_from_url("https://github.com/o/r", "main")

    assert "Authorization" not in captured["headers"]


# ---------------------------------------------------------------------------
# Response shape handling
# ---------------------------------------------------------------------------

def test_empty_response_returns_empty_list(captured, monkeypatch):
    captured["response"] = b"[]"
    monkeypatch.setenv("GITLAB_TOKEN", "glpat")
    assert audit.list_commits_from_url("https://gitlab.com/g/p", "main") == []


def test_non_array_response_aborts(captured, monkeypatch):
    captured["response"] = b'{"error": "boom"}'
    monkeypatch.setenv("GITLAB_TOKEN", "glpat")
    with pytest.raises(SystemExit):
        audit.list_commits_from_url("https://gitlab.com/g/p", "main")


def test_non_json_response_aborts(captured, monkeypatch):
    captured["response"] = b"<html>401</html>"
    monkeypatch.setenv("GITLAB_TOKEN", "glpat")
    with pytest.raises(SystemExit):
        audit.list_commits_from_url("https://gitlab.com/g/p", "main")


# ---------------------------------------------------------------------------
# _build_commit_url
# ---------------------------------------------------------------------------

def test_build_commit_url_gitlab():
    url = audit._build_commit_url(
        "https://gitlab.com/group/project", "abc1234",
    )
    assert url == "https://gitlab.com/group/project/-/commit/abc1234"


def test_build_commit_url_github():
    url = audit._build_commit_url(
        "https://github.com/owner/repo", "abc1234",
    )
    assert url == "https://github.com/owner/repo/commit/abc1234"


def test_build_commit_url_unknown_host_aborts():
    with pytest.raises(SystemExit):
        audit._build_commit_url("https://random-vcs.example/x/y", "abc")

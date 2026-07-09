"""Tests for GitLab MR comment formatting and posting.

Covers the two comment settings: collapsed (<details>) vs full body, and
posting as a resolvable discussion thread (/discussions) vs a plain note
(/notes).
"""
import json

import pytest

from pwnguard.models import AuditResult, Finding
from pwnguard.report import format_gitlab_comment, post_gitlab_comment


def _finding(severity, title, line, cwe):
    return Finding(
        severity=severity, title=title, file="shell.php", line=line,
        description="desc", recommendation="fix it", cwe=cwe,
    )


@pytest.fixture
def result():
    return AuditResult(
        findings=[
            _finding("CRITICAL", "rce via cmd parameter", 4, "CWE-78"),
            _finding("HIGH", "sql injection via id", 10, "CWE-89"),
        ],
        files_scanned=1,
    )


# ---------------------------------------------------------------------------
# format_gitlab_comment: collapsed vs full
# ---------------------------------------------------------------------------

def test_full_comment_has_no_details_block(result):
    md = format_gitlab_comment(result, collapsed=False)
    assert "<details>" not in md
    assert "## PwnGuard Findings" in md
    assert "**1** CRITICAL | **1** HIGH" in md
    assert "rce via cmd parameter" in md


def test_collapsed_comment_wraps_findings_in_details(result):
    md = format_gitlab_comment(result, collapsed=True)
    # Heading + tally stay outside the fold; details wrap the findings.
    assert md.startswith("## PwnGuard Findings")
    assert "**1** CRITICAL | **1** HIGH" in md.split("<details>")[0]
    assert "<details>\n<summary>Show Findings</summary>" in md
    assert md.rstrip().endswith("</details>")
    # Every finding body is inside the collapsed section.
    inside = md.split("<details>")[1]
    assert "rce via cmd parameter" in inside
    assert "sql injection via id" in inside


def test_passed_and_error_are_never_collapsed():
    passed = format_gitlab_comment(AuditResult(findings=[]), collapsed=True)
    assert passed == "## PwnGuard Passed\n\nNo security issues found."
    errored = format_gitlab_comment(
        AuditResult(findings=[], error="backend down"), collapsed=True,
    )
    assert "<details>" not in errored
    assert "PwnGuard Error" in errored


# ---------------------------------------------------------------------------
# post_gitlab_comment: thread vs note endpoint
# ---------------------------------------------------------------------------

class _FakeResp:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def ci_env(monkeypatch):
    monkeypatch.setenv("CI_PROJECT_ID", "42")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "7")
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.example.com")


def _capture_post(monkeypatch):
    """Patch urlopen to capture the request, return the captured dict."""
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode())
        return _FakeResp()

    monkeypatch.setattr("pwnguard.report.urllib.request.urlopen", fake_urlopen)
    return captured


def test_note_posts_to_notes_endpoint(ci_env, monkeypatch):
    captured = _capture_post(monkeypatch)
    assert post_gitlab_comment("body", as_thread=False) is True
    assert captured["url"].endswith("/merge_requests/7/notes")
    assert captured["body"] == {"body": "body"}


def test_thread_posts_to_discussions_endpoint(ci_env, monkeypatch):
    captured = _capture_post(monkeypatch)
    assert post_gitlab_comment("body", as_thread=True) is True
    assert captured["url"].endswith("/merge_requests/7/discussions")


def test_default_is_plain_note(ci_env, monkeypatch):
    captured = _capture_post(monkeypatch)
    post_gitlab_comment("body")
    assert captured["url"].endswith("/notes")


def test_missing_env_skips_post(monkeypatch):
    monkeypatch.delenv("CI_PROJECT_ID", raising=False)
    monkeypatch.delenv("CI_MERGE_REQUEST_IID", raising=False)
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.delenv("CI_JOB_TOKEN", raising=False)
    assert post_gitlab_comment("body", as_thread=True) is False

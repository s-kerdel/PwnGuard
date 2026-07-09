"""Tests for --platform log rendering: findings overview + collapsible
sections on GitLab / GitHub, and the plain fallback.

The overview table prints on every platform (including local/plain); the
section markers are platform-specific and must not leak into plain
output where they'd be terminal noise.
"""
import contextlib
import io

import pytest

import audit
from pwnguard import runtime


@pytest.fixture
def restore_platform():
    """Restore runtime.platform after a test flips it."""
    saved = runtime.platform
    yield
    runtime.set_platform(saved)


def _result(findings):
    return audit.AuditResult(findings=findings, files_scanned=1, elapsed=1.0)


def _finding(severity, title, line, cwe):
    return audit.Finding(
        severity=severity, title=title, file="shell.php", line=line,
        description="desc", recommendation="fix it", cwe=cwe,
    )


@pytest.fixture
def three_findings():
    return [
        _finding("CRITICAL", "rce via cmd parameter", 4, "CWE-78"),
        _finding("CRITICAL", "command injection via host", 14, "CWE-78"),
        _finding("HIGH", "sql injection via id", 10, "CWE-89"),
    ]


@pytest.fixture
def diff_lines():
    return {"shell.php": {
        3: "if ($_GET['cmd']) {",
        4: "    system($_GET['cmd']);",
        5: "}",
        10: '$q = "SELECT * FROM users WHERE id = $id";',
        13: "if ($_GET['host']) {",
        14: '    system("ping " . $_GET[\'host\']);',
    }}


def _render(result, diff_lines, platform, *, quiet=False):
    runtime.set_platform(platform)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        audit.print_terminal(
            result, "HIGH", diff_lines, files_scanned=1, quiet=quiet,
        )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# GitLab collapsible sections
# ---------------------------------------------------------------------------

def test_gitlab_wraps_each_finding_in_a_section(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "gitlab")
    # One start + one end marker per finding.
    assert out.count("\x1b[0Ksection_start:") == 3
    assert out.count("\x1b[0Ksection_end:") == 3
    # Folded by default and carrying a scannable header.
    assert "[collapsed=true]" in out
    assert "[C] shell.php:4 rce via cmd parameter CWE-78" in out


def test_gitlab_section_ids_are_unique(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "gitlab")
    for i in range(3):
        assert f":pwnguard_{i}[collapsed=true]" in out
        assert f"section_end:" in out and f":pwnguard_{i}\r" in out


# ---------------------------------------------------------------------------
# GitHub log groups
# ---------------------------------------------------------------------------

def test_github_wraps_each_finding_in_a_group(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "github")
    assert out.count("::group::") == 3
    assert out.count("::endgroup::") == 3
    assert "::group::[H] shell.php:10 sql injection via id CWE-89" in out
    # GitHub uses its own commands, never GitLab's section markers.
    assert "section_start:" not in out


# ---------------------------------------------------------------------------
# Plain: overview yes, section markers no
# ---------------------------------------------------------------------------

def test_plain_has_overview_but_no_section_markers(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "plain")
    assert "Findings (3)" in out          # overview index prints
    assert "section_start:" not in out    # no GitLab markers
    assert "::group::" not in out         # no GitHub markers


# ---------------------------------------------------------------------------
# Overview behaviour
# ---------------------------------------------------------------------------

def test_overview_lists_every_finding(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "gitlab")
    assert "Findings (3)" in out
    for f in three_findings:
        assert f.title in out


def test_overview_skipped_for_single_finding(diff_lines, restore_platform):
    one = [_finding("HIGH", "sql injection via id", 10, "CWE-89")]
    out = _render(_result(one), diff_lines, "plain")
    assert "Findings (1)" not in out
    # But the finding itself still renders.
    assert "sql injection via id" in out


def test_quiet_suppresses_overview_and_sections(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "gitlab", quiet=True)
    assert "Findings (3)" not in out      # no overview in quiet mode
    assert "section_start:" not in out    # no sections in quiet mode


# ---------------------------------------------------------------------------
# Section header is ANSI-free (safe on both platforms)
# ---------------------------------------------------------------------------

def test_finding_header_plain_has_no_ansi():
    f = _finding("CRITICAL", "rce via cmd parameter", 4, "CWE-78")
    header = audit._finding_header_plain(f)
    assert "\x1b" not in header
    assert header == "[C] shell.php:4 rce via cmd parameter CWE-78"

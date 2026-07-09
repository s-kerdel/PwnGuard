"""Tests for --platform log rendering.

On GitLab / GitHub each finding is one collapsible log section whose
header is the styled findings row - so the folded log is the overview
and there is no separate index table. In plain / local output there is
no fold mechanism, so an overview table prints above the detail cards.
"""
import contextlib
import io

import pytest

import audit
from pwnguard import __version__, runtime, ui
from pwnguard.cli import _ci_run_banner


def _strip(text):
    """Drop ANSI/OSC escapes so assertions match the visible text."""
    return ui._ANSI_RE.sub("", text)


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
    # One start + one end marker per finding, folded by default.
    assert out.count("\x1b[0Ksection_start:") == 3
    assert out.count("\x1b[0Ksection_end:") == 3
    assert "[collapsed=true]" in out
    # Every finding's title rides in a section header.
    plain = _strip(out)
    for f in three_findings:
        assert f.title in plain


def test_gitlab_section_ids_are_unique(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "gitlab")
    for i in range(3):
        assert f":pwnguard_{i}[collapsed=true]" in out
        assert f":pwnguard_{i}\r" in out


def test_gitlab_headers_are_severity_ordered(
    three_findings, diff_lines, restore_platform,
):
    plain = _strip(_render(_result(three_findings), diff_lines, "gitlab"))
    # Both criticals precede the high in the section list.
    assert plain.index("rce via cmd parameter") < plain.index("sql injection via id")
    assert plain.index("command injection via host") < plain.index("sql injection via id")


def test_gitlab_has_no_standalone_overview_table(
    three_findings, diff_lines, restore_platform,
):
    # The collapsed headers ARE the index, so the separate table is gone.
    out = _render(_result(three_findings), diff_lines, "gitlab")
    assert "Findings (3)" not in _strip(out)


# ---------------------------------------------------------------------------
# GitHub log groups
# ---------------------------------------------------------------------------

def test_github_wraps_each_finding_in_a_group(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "github")
    assert out.count("::group::") == 3
    assert out.count("::endgroup::") == 3
    assert "sql injection via id" in _strip(out)
    # GitHub uses its own commands, never GitLab's section markers.
    assert "section_start:" not in out


def test_github_has_no_standalone_overview_table(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "github")
    assert "Findings (3)" not in _strip(out)


# ---------------------------------------------------------------------------
# Plain: overview yes, section markers no
# ---------------------------------------------------------------------------

def test_plain_has_overview_but_no_section_markers(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "plain")
    assert "Findings (3)" in _strip(out)   # overview index prints
    assert "section_start:" not in out     # no GitLab markers
    assert "::group::" not in out          # no GitHub markers


def test_overview_skipped_for_single_finding(diff_lines, restore_platform):
    one = [_finding("HIGH", "sql injection via id", 10, "CWE-89")]
    out = _render(_result(one), diff_lines, "plain")
    assert "Findings (1)" not in _strip(out)
    # But the finding itself still renders.
    assert "sql injection via id" in _strip(out)


def test_quiet_suppresses_overview_and_sections(
    three_findings, diff_lines, restore_platform,
):
    out = _render(_result(three_findings), diff_lines, "gitlab", quiet=True)
    assert "Findings (3)" not in _strip(out)   # no overview in quiet mode
    assert "section_start:" not in out         # no sections in quiet mode


# ---------------------------------------------------------------------------
# Section header content
# ---------------------------------------------------------------------------

def test_section_header_carries_row_fields_on_one_line():
    f = _finding("CRITICAL", "rce via cmd parameter", 4, "CWE-78")
    header = audit._section_header(f)
    assert "\n" not in header               # single line (GitHub resets on \n)
    plain = _strip(header)
    assert "shell.php:4" in plain
    assert "rce via cmd parameter" in plain
    assert "CWE-78" in plain


# ---------------------------------------------------------------------------
# CI auto-forces color (logs render ANSI even without a PTY)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ci_var", ["GITLAB_CI", "GITHUB_ACTIONS"])
def test_ci_env_forces_color(monkeypatch, ci_var):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv(ci_var, "true")
    assert ui.should_use_color() is True


def test_no_color_beats_ci_env(monkeypatch):
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("NO_COLOR", "1")
    assert ui.should_use_color() is False


# ---------------------------------------------------------------------------
# Configurable fallback width (CI panes are wider than 80)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# CI run banner (version + backend + model up front)
# ---------------------------------------------------------------------------

def test_ci_banner_shows_version_backend_and_model():
    b = _strip(_ci_run_banner("claude-api", {"claude_api": {"model": "claude-opus-4-8"}}))
    assert "PwnGuard" in b
    assert f"v{__version__}" in b
    assert "claude-api" in b
    assert "claude-opus-4-8" in b


def test_ci_banner_omits_model_for_claude_code():
    b = _strip(_ci_run_banner("claude-code", {}))
    assert "claude-code" in b
    assert b.count("·") == 1   # version · backend, no model segment


def test_ci_banner_reads_configured_model():
    b = _strip(_ci_run_banner("ollama", {"ollama": {"model": "qwen2.5-coder:14b"}}))
    assert "ollama" in b
    assert "qwen2.5-coder:14b" in b


def test_default_width_used_when_size_undetectable(monkeypatch):
    import os as _os
    # Simulate a pipe with no terminal and no /dev/tty.
    monkeypatch.setattr(ui.shutil, "get_terminal_size",
                        lambda *_: _os.terminal_size((0, 24)))
    monkeypatch.setattr(ui, "_tty_size", lambda: None)
    saved = ui._default_width
    try:
        ui.set_default_width(120)
        assert ui.term_width() == 120
    finally:
        ui._default_width = saved


# ---------------------------------------------------------------------------
# OSC 8 hyperlinks off in CI (viewers show them as literal URL text)
# ---------------------------------------------------------------------------

def test_hyperlinks_can_be_disabled():
    saved_color, saved_links = ui._use_color, ui._use_hyperlinks
    try:
        ui.configure(color=True)
        ui.set_hyperlinks(False)
        # No OSC 8 wrapper: plain visible text, correct width.
        assert ui.hyperlink("CWE-78", "https://x") == "CWE-78"
        assert "\x1b]8;;" not in ui.file_link("shell.php", 4)
        ui.set_hyperlinks(True)
        assert "\x1b]8;;" in ui.hyperlink("CWE-78", "https://x")
    finally:
        ui._use_color, ui._use_hyperlinks = saved_color, saved_links


def test_ci_card_has_no_osc8_escapes(three_findings, diff_lines, restore_platform):
    saved_color, saved_links = ui._use_color, ui._use_hyperlinks
    try:
        ui.configure(color=True)
        ui.set_hyperlinks(False)
        out = _render(_result(three_findings), diff_lines, "gitlab")
        assert "\x1b]8;;" not in out
    finally:
        ui._use_color, ui._use_hyperlinks = saved_color, saved_links

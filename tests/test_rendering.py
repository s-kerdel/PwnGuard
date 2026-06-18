"""Tests for card-rendering width math.

In v0.1.2 the default ``print_terminal`` layout boxed cards overran
the terminal by exactly ``len(outer_indent)`` columns (two) because
the overhead math missed the outer indent. These tests guard the fix
across realistic terminal widths.

Also covers ``_truncate_visible``, the ANSI-safe truncate used by
``_boxed`` to prevent over-wide metadata / code lines from pushing
the right border past the terminal edge.
"""
import contextlib
import io

import pytest

import audit


# ---------------------------------------------------------------------------
# _truncate_visible: ANSI-safe width clamp
# ---------------------------------------------------------------------------

def test_truncate_visible_passes_short_input_through():
    assert audit._truncate_visible("short", 20) == "short"


def test_truncate_visible_clamps_plain_text():
    out = audit._truncate_visible("abcdefghij", 5)
    assert audit.ui.visible_len(out) <= 5
    assert out.startswith("abcd")


def test_truncate_visible_preserves_ansi_sequences_intact():
    """The cut must NEVER fall in the middle of an ANSI escape -
    that would leave the terminal in a half-set color state."""
    coloured = "\x1b[36mABCDEFGHIJKL\x1b[0m"
    out = audit._truncate_visible(coloured, 5)
    # Visible width respected.
    assert audit.ui.visible_len(out) <= 5
    # Opening escape kept whole (not cut mid-bytes).
    assert "\x1b[36m" in out
    # Reset appended so colour doesn't bleed into following output.
    assert out.endswith("\x1b[0m")


def test_truncate_visible_handles_osc8_hyperlink():
    """OSC 8 hyperlink sequences (used for clickable CWE links) must
    also stay intact across the truncate."""
    linked = "\x1b]8;;https://x\x1b\\CWE-89\x1b]8;;\x1b\\ trailing tail goes away"
    out = audit._truncate_visible(linked, 8)
    assert audit.ui.visible_len(out) <= 8
    # The hyperlink opener escape stays intact.
    assert "\x1b]8;;https://x\x1b\\" in out


def test_truncate_visible_zero_width_returns_empty():
    assert audit._truncate_visible("anything", 0) == ""


# Realistic terminal widths. Width <80 is not tested because at narrow
# widths even the existing two-row metadata fallback can't fit a long
# file:line + hunk_context + CWE meta string inside the inner box -
# that's a pre-existing layout limit, not what the v0.1.2 fix targets.
WIDTHS = [80, 100, 120, 160]


def _max_visible_line_width(buf: str) -> int:
    return max(
        (audit.ui.visible_len(line) for line in buf.splitlines()),
        default=0,
    )


@pytest.fixture
def finding() -> audit.Finding:
    return audit.Finding(
        severity="HIGH",
        title="sql injection via user_id in lookup_user",
        file="app/users.py",
        line=10,
        description=(
            "The lookup_user function interpolates user_id into the SQL "
            "string without parameterisation."
        ),
        recommendation="Use a parameterised query with bound parameters.",
        cwe="CWE-89",
        confidence="high",
        anchor="a1",
        hunk_context="def lookup_user(user_id):",
    )


@pytest.fixture
def diff_lines() -> dict:
    return {"app/users.py": {
        8: "    # Resolve a user id to a row",
        9: "    conn = get_conn()",
        10: '    sql = f"SELECT * FROM users WHERE id = {user_id}"',
        11: "    row = conn.execute(sql).fetchone()",
        12: "    return row",
    }}


@pytest.mark.parametrize("width", WIDTHS)
def test_default_finding_card_fits(width, finding, diff_lines,
                                   restore_term_width):
    restore_term_width(width)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        audit._print_finding_block(finding, diff_lines)
    max_w = _max_visible_line_width(buf.getvalue())
    assert max_w <= width, (
        f"box overflowed terminal: width={width}, max_line={max_w}"
    )


@pytest.mark.parametrize("width", WIDTHS)
def test_review_row_fits(width, finding, diff_lines, restore_term_width):
    restore_term_width(width)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        audit._render_review_row(
            finding,
            marked=False,
            expanded=True,
            is_current=True,
            diff_lines=diff_lines,
            width=width,
        )
    max_w = _max_visible_line_width(buf.getvalue())
    assert max_w <= width, (
        f"review row overflowed: width={width}, max_line={max_w}"
    )


# ---------------------------------------------------------------------------
# Monitor commit row (repo -> commit -> finding tree)
# ---------------------------------------------------------------------------

def test_monitor_commit_row_shows_sha_and_severity():
    buf = io.StringIO()
    rec = {"sha": "abc1234def567", "date": None, "findings": [
        {"severity": "HIGH", "title": "x"},
        {"severity": "HIGH", "title": "y"},
    ]}
    with contextlib.redirect_stdout(buf):
        audit._render_monitor_commit_row(
            rec, is_expanded=False, is_current=False, width=80,
        )
    text = buf.getvalue()
    assert "abc1234" in text          # 7-char short SHA
    assert "abc1234def567" not in text  # not the full SHA
    assert "2 H" in text              # per-commit severity breakdown


def test_monitor_commit_row_clean_and_expanded_hint():
    buf = io.StringIO()
    rec = {"sha": "abc1234def567", "date": None, "findings": []}
    with contextlib.redirect_stdout(buf):
        audit._render_monitor_commit_row(
            rec, is_expanded=True, is_current=False, width=80,
        )
    text = buf.getvalue()
    assert "clean" in text
    assert "no findings on this commit" in text


@pytest.mark.parametrize("width", WIDTHS)
def test_monitor_commit_row_fits(width):
    buf = io.StringIO()
    rec = {
        "sha": "abc1234def567",
        "date": "2026-05-10T00:00:00Z",
        "findings": [{"severity": "CRITICAL", "title": "x"}],
    }
    with contextlib.redirect_stdout(buf):
        audit._render_monitor_commit_row(
            rec, is_expanded=False, is_current=True, width=width,
        )
    max_w = _max_visible_line_width(buf.getvalue())
    assert max_w <= width, (
        f"commit row overflowed: width={width}, max_line={max_w}"
    )


# ---------------------------------------------------------------------------
# New/unreviewed dot + repo summary (catch-up oversight)
# ---------------------------------------------------------------------------

def _render_commit(rec, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        audit._render_monitor_commit_row(
            rec, is_expanded=False, is_current=False, width=100, **kw,
        )
    return buf.getvalue()


def test_commit_row_shows_new_dot_when_unviewed():
    rec = {"sha": "abc1234def", "date": None, "findings": []}
    assert "●" in _render_commit(rec, is_new=True)


def test_commit_row_hides_new_dot_when_viewed():
    rec = {"sha": "abc1234def", "date": None, "findings": []}
    assert "●" not in _render_commit(rec, is_new=False)


def _repo_entry(order, commits, last_viewed):
    return {
        "name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main",
        "last_audited_sha": order[0] if order else None,
        "last_viewed_sha": last_viewed,
        "head_sha": order[0] if order else None,
        "order": order, "commits": commits,
    }


def _render_repo(entry, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        audit._render_monitor_row(
            entry, is_expanded=kw.pop("is_expanded", False),
            is_current=False, width=100, **kw,
        )
    return buf.getvalue()


def test_repo_row_shows_new_count_chip():
    # c2 (newest) + c1 are newer than the viewed pointer c0 -> 2 new.
    commits = {
        "c2": {"sha": "c2", "date": None, "findings": []},
        "c1": {"sha": "c1", "date": None, "findings": []},
        "c0": {"sha": "c0", "date": None, "findings": []},
    }
    entry = _repo_entry(["c2", "c1", "c0"], commits, last_viewed="c0")
    assert "2 new" in _render_repo(entry)


def test_repo_row_no_new_chip_when_all_viewed():
    commits = {"c0": {"sha": "c0", "date": None, "findings": []}}
    entry = _repo_entry(["c0"], commits, last_viewed="c0")
    out = _render_repo(entry)
    assert "new" not in out


def test_repo_row_summarises_hidden_clean_commits_when_expanded():
    # One commit with a finding, two clean (one of them new).
    commits = {
        "c3": {"sha": "c3", "date": None, "findings": [
            {"severity": "HIGH", "title": "x"},
        ]},
        "c2": {"sha": "c2", "date": None, "findings": []},
        "c1": {"sha": "c1", "date": None, "findings": []},
    }
    entry = _repo_entry(["c3", "c2", "c1"], commits, last_viewed="c2")
    out = _render_repo(entry, is_expanded=True, show_all=False)
    # c1 and c2 are clean -> 2 hidden; only c3 is newer than viewed=c2,
    # and c3 has a finding, so 0 clean commits are new.
    assert "2 clean hidden" in out
    assert "press [f] to show all" in out


def test_repo_row_no_clean_summary_when_show_all():
    commits = {
        "c2": {"sha": "c2", "date": None, "findings": []},
        "c1": {"sha": "c1", "date": None, "findings": []},
    }
    entry = _repo_entry(["c2", "c1"], commits, last_viewed="c1")
    out = _render_repo(entry, is_expanded=True, show_all=True)
    assert "clean hidden" not in out


# ---------------------------------------------------------------------------
# Right-side status chips: error visibility, pending, truncation
# ---------------------------------------------------------------------------

def test_repo_row_shows_error_chip_and_message_when_expanded():
    commits = {"c0": {"sha": "c0", "date": None, "findings": []}}
    entry = _repo_entry(["c0"], commits, last_viewed="c0")
    entry["last_error"] = "HTTP 404 from compare endpoint"
    out = _render_repo(entry, is_expanded=True)
    assert "error" in out                       # chip on the row
    assert "HTTP 404 from compare endpoint" in out  # message under it


def test_repo_row_error_suppresses_pending_chip():
    commits = {"c0": {"sha": "c0", "date": None, "findings": []}}
    entry = _repo_entry(["c0"], commits, last_viewed="c0")
    entry["pending_count"] = 5
    entry["last_error"] = "boom"
    out = _render_repo(entry)
    # An errored repo reads as "error", not a misleading "5 pending".
    assert "pending" not in out
    assert "error" in out


def test_repo_row_shows_pending_chip_without_error():
    commits = {"c0": {"sha": "c0", "date": None, "findings": []}}
    entry = _repo_entry(["c0"], commits, last_viewed="c0")
    entry["pending_count"] = 3
    out = _render_repo(entry)
    assert "3 pending" in out


def test_repo_row_no_pending_chip_when_caught_up():
    commits = {"c0": {"sha": "c0", "date": None, "findings": []}}
    entry = _repo_entry(["c0"], commits, last_viewed="c0")
    entry["pending_count"] = 0
    out = _render_repo(entry)
    assert "pending" not in out


@pytest.mark.parametrize("width", [60, 80, 120])
def test_repo_row_status_chips_survive_long_name(width):
    """A very long repo name must truncate rather than push the status
    chips off the edge (the old layout cut '[6 new]' to '[6 new')."""
    commits = {
        "c2": {"sha": "c2", "date": None, "findings": []},
        "c1": {"sha": "c1", "date": None, "findings": []},
        "c0": {"sha": "c0", "date": None, "findings": []},
    }
    entry = _repo_entry(["c2", "c1", "c0"], commits, last_viewed="c0")
    entry["name"] = "a-really-quite-excessively-long-monitored-repository-name"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        audit._render_monitor_row(
            entry, is_expanded=False, is_current=False, width=width,
        )
    out = buf.getvalue()
    # The full status chip is intact and the line fits the terminal.
    assert "2 new" in out
    assert _max_visible_line_width(out) <= width


@pytest.mark.parametrize("width", [50, 80, 120])
def test_repo_row_never_fills_last_column(width):
    """emit_tui_frame's per-line \\x1b[K erases a glyph sitting in the
    final column, so a row must stop at width-1 - otherwise the last
    char of the rightmost chip ('new' -> 'ne') is clipped."""
    commits = {
        "c2": {"sha": "c2", "date": None, "findings": []},
        "c1": {"sha": "c1", "date": None, "findings": []},
        "c0": {"sha": "c0", "date": None, "findings": []},
    }
    entry = _repo_entry(["c2", "c1", "c0"], commits, last_viewed="c0")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        audit._render_monitor_row(
            entry, is_expanded=False, is_current=False, width=width,
        )
    out = buf.getvalue()
    assert "2 new" in out
    assert _max_visible_line_width(out) <= width - 1


def test_commit_row_never_fills_last_column():
    rec = {
        "sha": "abc1234def567",
        "date": "2026-05-10T00:00:00Z",
        "findings": [{"severity": "CRITICAL", "title": "x"}],
    }
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        audit._render_monitor_commit_row(
            rec, is_expanded=False, is_current=False, width=80,
        )
    assert _max_visible_line_width(buf.getvalue()) <= 80 - 1

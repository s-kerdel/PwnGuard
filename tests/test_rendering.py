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

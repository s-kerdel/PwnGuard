"""Tests for the shared TUI scaffolding.

The headline invariant: ``compute_visible_window`` must never produce
a frame whose total emitted row count exceeds the terminal-row budget.
Even a 1-row overflow scrolls the alt-screen buffer and flicks the
"PwnGuard" title off the top during navigation.
"""
import pytest

import audit  # noqa: F401  - keeps the legacy import path warm
from pwnguard.tui import (
    block_rows,
    compute_visible_window,
    lines_rows,
    visible_rows,
)


def _emit_rows(heights: list, result: tuple) -> int:
    """Total emitted rows for a result. Mirrors the rendering loop."""
    visible, hidden_above, hidden_below = result
    chips = (1 if hidden_above else 0) + (1 if hidden_below else 0)
    return chips + sum(heights[i] for i in visible)


# ---------------------------------------------------------------------------
# visible_rows / block_rows / lines_rows: wrap-aware accounting
# ---------------------------------------------------------------------------

def test_visible_rows_short_line_is_one_row():
    assert visible_rows("hello", 80) == 1


def test_visible_rows_blank_line_is_one_row():
    assert visible_rows("", 80) == 1


def test_visible_rows_long_line_wraps_to_two_rows():
    """120-char line on an 80-col terminal occupies 2 rows."""
    assert visible_rows("x" * 120, 80) == 2


def test_visible_rows_exactly_at_width_is_one_row():
    """Edge: exactly `width` visible chars must not over-count."""
    assert visible_rows("x" * 80, 80) == 1


def test_visible_rows_ansi_codes_dont_count_toward_width():
    """ANSI escapes are invisible; the row math must use visible_len."""
    line = "\x1b[31m" + ("x" * 80) + "\x1b[0m"
    assert visible_rows(line, 80) == 1


def test_block_rows_sums_per_line():
    block = ["x", "y" * 120, "z"]  # 1 + 2 + 1 = 4 rows on width 80
    assert block_rows(block, 80) == 4


def test_lines_rows_is_block_rows_alias():
    """``lines_rows`` is the same primitive, named for header/footer use."""
    assert lines_rows(["a", "b"], 80) == block_rows(["a", "b"], 80)


# ---------------------------------------------------------------------------
# compute_visible_window: happy path
# ---------------------------------------------------------------------------

def test_all_blocks_visible_when_total_fits():
    heights = [1, 2, 1]
    visible, above, below = compute_visible_window(heights, cursor=1, available=10)
    assert visible == [0, 1, 2]
    assert above == 0 and below == 0


def test_exact_fit_keeps_everything_visible():
    heights = [3, 3]
    visible, above, below = compute_visible_window(heights, cursor=0, available=6)
    assert visible == [0, 1]
    assert above == 0 and below == 0


# ---------------------------------------------------------------------------
# Regression coverage: the cursor-in-middle off-by-one that pre-dated
# the package split.
# ---------------------------------------------------------------------------

def test_cursor_in_middle_with_both_indicators_does_not_overflow():
    """5 blocks × 3 rows each, budget 10, cursor in the middle.

    Pre-fix: visible=[1,2,3], hidden_above=1, hidden_below=1 - emit
    was 1+3+3+3+1 = 11. Now bounded by 10.
    """
    heights = [3] * 5
    assert _emit_rows(heights, compute_visible_window(heights, 1, 10)) <= 10


@pytest.mark.parametrize("cursor", range(5))
def test_every_cursor_position_respects_budget_uniform(cursor):
    heights = [3] * 5
    result = compute_visible_window(heights, cursor=cursor, available=10)
    assert _emit_rows(heights, result) <= 10
    assert cursor in result[0]


@pytest.mark.parametrize("cursor", range(8))
@pytest.mark.parametrize("available", [8, 12, 16, 20])
def test_every_cursor_position_respects_budget_mixed(cursor, available):
    """Mixed heights (collapsed rows + expanded cards). The bound is
    ``max(available, height[cursor])`` because a single block taller
    than the budget is an irreducible overflow - we cannot show less
    than one whole block."""
    heights = [1, 6, 2, 8, 3, 4, 2, 5]
    result = compute_visible_window(heights, cursor=cursor, available=available)
    emit = _emit_rows(heights, result)
    irreducible_floor = heights[cursor]
    assert emit <= max(available, irreducible_floor), (
        f"cursor={cursor}, available={available}, result={result}, emit={emit}"
    )
    assert cursor in result[0]


# ---------------------------------------------------------------------------
# Wrap-aware regression: the case the real monitor data tripped on -
# header rows that wrap (the shortcuts string is ~122 visible chars
# on a 100-col terminal) used to be miscounted as 1 row each, leaving
# 1+ row of overflow per frame.
# ---------------------------------------------------------------------------

def test_wrapping_header_consumes_two_rows_of_budget():
    """Header that wraps must consume 2 rows from the available budget,
    not 1. The diagnostic test for this lives in the integration check
    below; this one just pins the primitive."""
    header_lines = [
        "PwnGuard Monitor  ·  13 repos",
        "  up/down navigate   enter toggle   -/= collapse/expand all   "
        "space=strike   v=mark viewed   e=export   r=refresh   q=quit",
    ]
    assert lines_rows(header_lines, 100) == 3  # 1 + 2 (wrap)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_heights_returns_empty():
    visible, above, below = compute_visible_window([], cursor=0, available=10)
    assert visible == [] and above == 0 and below == 0


def test_single_block_fits():
    heights = [2]
    visible, above, below = compute_visible_window(heights, cursor=0, available=5)
    assert visible == [0]
    assert above == 0 and below == 0


def test_cursor_block_larger_than_budget_still_returned():
    """Cursor block too tall: indicators dropped to keep emit as small
    as the cursor block alone. The block still overflows the screen
    (irreducible), but we don't add chip rows that would only make
    the scroll worse."""
    heights = [1, 20, 1]
    visible, above, below = compute_visible_window(heights, cursor=1, available=10)
    assert visible == [1]
    assert above == 0 and below == 0


def test_cursor_at_start_no_above_indicator_reserved():
    heights = [3] * 5
    result = compute_visible_window(heights, cursor=0, available=10)
    visible, above, below = result
    assert above == 0
    assert len(visible) >= 3
    assert _emit_rows(heights, result) <= 10


def test_cursor_at_end_no_below_indicator_reserved():
    heights = [3] * 5
    result = compute_visible_window(heights, cursor=4, available=10)
    visible, above, below = result
    assert below == 0
    assert len(visible) >= 3
    assert _emit_rows(heights, result) <= 10


def test_cursor_out_of_range_is_clamped():
    heights = [1, 1, 1]
    visible_neg, _, _ = compute_visible_window(heights, cursor=-1, available=10)
    visible_big, _, _ = compute_visible_window(heights, cursor=99, available=10)
    assert 0 in visible_neg
    assert 2 in visible_big



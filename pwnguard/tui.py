"""Shared scaffolding for the two TUIs (``--review`` and ``--monitor``).

Three primitives:
- ``capture`` redirects stdout for a callable so a renderer that
  ``print()``-s can be measured for height.
- ``emit_tui_frame`` writes a buffered frame in a single terminal
  call (cursor home + per-line EOL clear + final EOS clear) - avoids
  the blank-then-paint flash a naive clear-then-fill produces.
- ``compute_visible_window`` is the cursor-pinned greedy window the
  two render functions used to duplicate.

There is also one row-rendering helper shared by both TUIs:
``render_tui_finding_row``. The review and monitor modules wrap it in
thin module-level functions so their own public API stays unchanged.
"""

import contextlib
import io
import sys
from typing import Optional

from pwnguard import ui
from pwnguard.models import Finding
from pwnguard.render import (
    META_MIN_GAP,
    _build_metadata,
    _render_finding_card,
    _severity_marker,
)


def capture(fn, /, *args, **kwargs) -> list:
    """Run a print-using helper and return its stdout as a list of lines."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue().splitlines()


def visible_rows(line: str, width: int) -> int:
    """How many terminal rows ``line`` actually occupies at ``width`` columns.

    A blank line still takes one row. A line wider than ``width`` wraps -
    the windowing math has to account for this or the alt-screen frame
    overflows the terminal and triggers a scroll-induced flicker at the
    top during navigation. We measure visible length (ANSI escapes
    stripped) and ceiling-divide by width.
    """
    if width < 1:
        return 1
    vis = ui.visible_len(line)
    if vis == 0:
        return 1
    return (vis + width - 1) // width


def block_rows(block: list, width: int) -> int:
    """Total terminal rows a captured block of lines will occupy after wrap."""
    return sum(visible_rows(line, width) for line in block)


def lines_rows(lines: list, width: int) -> int:
    """Alias for :func:`block_rows` - reads better for header/footer lists."""
    return block_rows(lines, width)


def emit_tui_frame(content: str) -> None:
    """Write a pre-built TUI frame in one terminal call.

    Cursor home + per-line EOL clear + final EOS clear avoids the
    blank-then-paint flash that a naive ``clear_screen``-then-print
    loop produces on every keystroke.
    """
    frame = "\x1b[H" + content.replace("\n", "\x1b[K\n") + "\x1b[J"
    sys.stdout.write(frame)
    sys.stdout.flush()


def compute_visible_window(
    heights: list, cursor: int, available: int,
) -> tuple:
    """Greedy windowing: which item indices fit on screen around the cursor.

    ``heights`` is a list of int row counts (one per item) measured at
    the *current* terminal width with wrap accounted for - see
    :func:`block_rows`. Passing raw line counts here will under-budget
    long wrapping lines and the frame will scroll on navigation.

    Returns ``(visible_indices, hidden_above, hidden_below)``.

    Invariant the caller relies on:

        (1 if hidden_above else 0)
        + sum(heights[i] for i in visible_indices)
        + (1 if hidden_below else 0)
        <= available

    Overflowing this budget by even one row is what causes a TUI
    flicker on navigation: the terminal scrolls the extra row in,
    pushing the top of the frame off the alt-screen buffer until the
    next redraw lands.

    Algorithm: pin the cursor block, reserve one row for each
    indicator we might emit, then grow downward and upward in turn.
    When growth reaches the edge of the list on a side (so the
    corresponding indicator is no longer needed), release that
    reservation back into the budget.
    """
    n = len(heights)
    if n == 0:
        return [], 0, 0
    total = sum(heights)
    if total <= available:
        return list(range(n)), 0, 0

    cursor = max(0, min(cursor, n - 1))

    # Cursor is always visible. Reserve indicator slots up front based
    # on whether the cursor sits at the very edge of the list.
    visible_indices = [cursor]
    used = heights[cursor]
    reserve_above = 1 if cursor > 0 else 0
    reserve_below = 1 if cursor < n - 1 else 0

    # Grow downward. When we add the very last block on this side, the
    # ↓ indicator reservation can be released - that block IS the bottom.
    below = cursor + 1
    while below < n:
        size = heights[below]
        release = reserve_below if below == n - 1 else 0
        if used + size + reserve_above + reserve_below - release > available:
            break
        visible_indices.append(below)
        used += size
        reserve_below -= release
        below += 1
    hidden_below = n - below

    # Grow upward. Symmetric release when we reach index 0.
    above = cursor - 1
    while above >= 0:
        size = heights[above]
        release = reserve_above if above == 0 else 0
        if used + size + reserve_above + reserve_below - release > available:
            break
        visible_indices.insert(0, above)
        used += size
        reserve_above -= release
        above -= 1
    hidden_above = above + 1

    # Final invariant pass. If the cursor block itself is so tall that
    # even (cursor_block + indicators) overflows the budget, drop the
    # indicator chips rather than let them push the frame past the
    # bottom of the alt-screen buffer. The user loses the "↑ N above"
    # / "↓ N below" hint for that one frame, but the terminal does not
    # scroll - which is the whole point of this function.
    def _emit_cost() -> int:
        return (
            (1 if hidden_above else 0)
            + used
            + (1 if hidden_below else 0)
        )

    while _emit_cost() > available:
        if hidden_below:
            hidden_below = 0
        elif hidden_above:
            hidden_above = 0
        else:
            # Cursor block alone exceeds available - irreducible. The
            # terminal will scroll the lower part of this block; there
            # is no smaller frame we can render.
            break

    return visible_indices, hidden_above, hidden_below


def render_tui_finding_row(
    f: Finding,
    *,
    is_marked: bool,
    is_expanded: bool,
    is_current: bool,
    width: int,
    diff_lines: Optional[dict] = None,
) -> None:
    """Render one finding row inside a TUI list.

    Two layouts:
    - Collapsed: cursor mark + severity badge + title, with file:line
      / hunk context / CWE right-aligned. Marked rows are dim +
      strikethrough so the user's "resolved / ignore" pile recedes.
    - Expanded: delegates to ``_render_finding_card`` so the full
      description, suggestion, fix_example, and ±3 code preview
      render identically to the default terminal layout.

    Used by both ``--review`` and ``--monitor`` to keep the two TUIs
    visually identical.
    """
    cursor_mark = ui.bold(ui.cyan("❯")) if is_current else " "
    badge = _severity_marker(f.severity)

    if is_marked:
        # Struck-through rows recede regardless of cursor position - the
        # user has signed off and shouldn't be distracted by the
        # active-row highlight.
        title_text = ui.dim(ui.strikethrough(f.title))
    elif is_current:
        title_text = ui.bold(ui.severity_color(f.title, f.severity))
    else:
        title_text = f.title

    meta = _build_metadata(f)
    if is_marked:
        meta = ui.dim(meta)

    if not is_expanded:
        prefix = f"   {cursor_mark}  {badge}  {title_text}"
        title_w = ui.visible_len(prefix)
        meta_w = ui.visible_len(meta)
        if meta_w and title_w + META_MIN_GAP + meta_w <= width:
            pad = width - title_w - meta_w
            print(prefix + (" " * pad) + meta)
        else:
            print(prefix)
            if meta_w:
                print((" " * max(0, width - meta_w)) + meta)
        return

    # Expanded: reuse the boxed-card helper from the default layout.
    # The cursor mark sits to the left of the box's top corner via
    # nav_prefix; subsequent lines indent under it.
    nav_prefix = f"   {cursor_mark}  "
    _render_finding_card(
        f, diff_lines or {}, width=width,
        outer_indent="", nav_prefix=nav_prefix,
        active=is_current,
    )

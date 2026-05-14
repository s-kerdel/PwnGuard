"""The ``--review`` interactive TUI.

Walks the user through the findings list with arrow-key navigation,
strike-through to mark "resolved / ignore", expand / collapse, and a
markdown export of the non-struck subset. Marks and expansions are
local visual state only - they do not affect the threshold check or
the audit exit code, which is decided in ``cli.main()`` from
``AuditResult`` directly.
"""

import sys

from pwnguard import ui
from pwnguard.models import AuditResult, Finding
from pwnguard.render import (
    _ordered_findings,
    _print_legend,
    _print_observations,
)
from pwnguard.report import (
    _default_findings_export_path,
    export_findings_markdown,
)
from pwnguard.tui import (
    block_rows,
    capture,
    compute_visible_window,
    emit_tui_frame,
    lines_rows,
    render_tui_finding_row,
)


# Body indent inside the review TUI. The row prefix is wider than the
# normal print_terminal layout (cursor + checkbox + badge) so expanded
# body lines sit at col 8 - under the badge, but tighter than aligning
# all the way under the title text.
REVIEW_BODY_INDENT = "        "  # 8 spaces


def _render_review_row(
    f: Finding,
    marked: bool,
    expanded: bool,
    is_current: bool,
    diff_lines: dict,
    width: int,
) -> None:
    """Print one finding row, optionally followed by its expanded body.

    Thin wrapper around the shared TUI row helper. Kept here with the
    pre-split parameter names so external callers (tests) that pass
    ``marked`` / ``expanded`` positionally or by keyword keep working.
    """
    render_tui_finding_row(
        f,
        is_marked=marked,
        is_expanded=expanded,
        is_current=is_current,
        width=width,
        diff_lines=diff_lines,
    )


def _render_review(
    findings: list,
    marked: list,
    expanded: list,
    cursor: int,
    diff_lines: dict,
    observations: list,
    status_line: str = "",
) -> None:
    """Full screen redraw of the review TUI, windowed to terminal height.

    Each finding row is rendered into a buffer first so we can measure
    its line count. If the total exceeds the available content area we
    pick a window of rows around the cursor and show ``↑ N hidden``
    / ``↓ N hidden`` indicators in place of the clipped rows. Keeps
    the cursor row (and its expansion, if any) visible no matter how
    small the terminal is.

    Output is buffered and emitted by ``emit_tui_frame`` so the
    terminal repaints in one pass (no clear-then-fill flicker on
    keystrokes).
    """
    import contextlib
    import io
    width = ui.term_width()
    height = ui.term_height()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _render_review_into_buffer(
            findings, marked, expanded, cursor, diff_lines,
            observations, status_line, width, height,
        )
    emit_tui_frame(buf.getvalue())


def _render_review_into_buffer(
    findings: list,
    marked: list,
    expanded: list,
    cursor: int,
    diff_lines: dict,
    observations: list,
    status_line: str,
    width: int,
    height: int,
) -> None:
    """Inner render body. ``sys.stdout`` is redirected to the frame
    buffer by ``_render_review``; this function just emits lines."""
    n = len(findings)
    n_marked = sum(marked)

    header_lines = [
        ui.bold("PwnGuard review") + ui.dim(f"  ·  {n} finding{'s' if n != 1 else ''}"),
        ui.dim("  up/down navigate   enter toggle   -/= collapse/expand all   space=strike   e=export   q=quit"),
    ]
    header_lines += capture(_print_legend)
    header_lines.append("")  # blank after legend

    obs_lines = capture(_print_observations, observations)
    footer_lines = ["", ui.dim(f"  {n_marked}/{n} struck")]
    if status_line:
        footer_lines.append(ui.dim(f"  {status_line}"))

    finding_blocks = []
    for i, f in enumerate(findings):
        finding_blocks.append(capture(
            _render_review_row,
            f, marked[i], expanded[i], (i == cursor), diff_lines, width,
        ))

    # Available space for the findings region, measured in actual
    # terminal rows (i.e. accounting for any line that's wider than
    # ``width`` and wraps). Floor at 1 so we always show at least the
    # cursor block (it may itself overflow, but that's better than
    # showing nothing).
    header_rows = lines_rows(header_lines, width)
    obs_rows = lines_rows(obs_lines, width)
    footer_rows = lines_rows(footer_lines, width)
    available = max(1, height - header_rows - obs_rows - footer_rows)

    finding_heights = [block_rows(b, width) for b in finding_blocks]
    visible_indices, hidden_above, hidden_below = compute_visible_window(
        finding_heights, cursor, available,
    )

    # Now emit everything in order.
    for line in header_lines:
        print(line)
    if hidden_above:
        print(ui.dim(
            f"  ↑ {hidden_above} earlier finding"
            f"{'s' if hidden_above != 1 else ''} above"
        ))
    for idx in visible_indices:
        for line in finding_blocks[idx]:
            print(line)
    if hidden_below:
        print(ui.dim(
            f"  ↓ {hidden_below} more finding"
            f"{'s' if hidden_below != 1 else ''} below"
        ))
    for line in obs_lines:
        print(line)
    for line in footer_lines:
        print(line)


def interactive_review(
    result: AuditResult,
    diff_lines: dict,
) -> None:
    """Informative review TUI. Strike marks and expansions are local
    visual state only - they don't affect findings, the threshold, or
    the exit code.

    Keys:
      up / down               navigate
      enter                   toggle expand / collapse on the current row
      right                   expand current finding
      left                    collapse current finding
      -                       collapse everything
      =                       expand everything
      space                   toggle strike-through (also collapses)
      e                       export non-struck findings to a markdown file
      q, esc, Ctrl-C          quit
    """
    findings = _ordered_findings(result)
    if not findings:
        return

    if not ui.CbreakTerminal.available or not sys.stdin.isatty() or not sys.stdout.isatty():
        print(
            ui.dim("PwnGuard: interactive review unavailable (non-TTY or Windows). Skipping."),
            file=sys.stderr,
        )
        return

    n = len(findings)
    marked = [False] * n
    expanded = [False] * n
    cursor = 0
    status_line = ""

    with ui.CbreakTerminal():
        while True:
            _render_review(
                findings, marked, expanded, cursor, diff_lines,
                result.observations, status_line,
            )
            try:
                key = ui.read_key()
            except KeyboardInterrupt:
                return

            if key in ("q", "esc"):
                return
            elif key == "up":
                cursor = (cursor - 1) % n
            elif key == "down":
                cursor = (cursor + 1) % n
            elif key == "enter":
                expanded[cursor] = not expanded[cursor]
            elif key == "right":
                expanded[cursor] = True
            elif key == "left":
                expanded[cursor] = False
            elif key == "-":
                expanded = [False] * n
            elif key == "=":
                expanded = [True] * n
            elif key == "space":
                # Toggle strike-through. If the row was expanded when
                # marking, collapse it - matches the "done, move on"
                # flow.
                if not marked[cursor]:
                    marked[cursor] = True
                    expanded[cursor] = False
                else:
                    marked[cursor] = False
            elif key == "e":
                # Export every non-struck finding to a timestamped
                # markdown file in the current directory. Struck rows
                # are the user's "resolved / ignore" pile, so they are
                # omitted; everything else is fair game for the report.
                unstruck = [
                    f for i, f in enumerate(findings) if not marked[i]
                ]
                path = _default_findings_export_path()
                try:
                    export_findings_markdown(unstruck, path)
                    status_line = (
                        f"exported {len(unstruck)} finding"
                        f"{'s' if len(unstruck) != 1 else ''} → {path}"
                    )
                except OSError as exc:
                    status_line = f"export failed: {exc}"

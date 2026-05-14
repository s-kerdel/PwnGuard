"""Terminal rendering for the audit report.

Owns the grouped-by-file layout, the boxed finding cards, the
ordering / sort key, and the small layout helpers (truncation,
severity badges, code-window selection). Backends and the CLI never
emit raw ANSI; they call into ``ui.*`` from here.
"""

import contextlib
import io
import textwrap
from typing import Optional

from pwnguard import runtime, ui
from pwnguard.constants import SEVERITY_ORDER
from pwnguard.models import AuditResult, Finding
from pwnguard.security import _sanitize


# Layout for the grouped terminal output.
#
# Each finding's title row starts with a bracketed letter marker so the
# left margin stays scannable on wide terminals (where the right-aligned
# severity word would otherwise be far from the title). The letter is
# bold-colored, the brackets are dim - gives a tag/badge feel without
# screaming for attention. A small legend prints under the header so the
# letter codes are self-documenting.
#
# Layout cheatsheet:
#   col 0-1:  blank      (sit under the file header)
#   col 2-4:  marker     ([C], [H], [M], [L], [I])
#   col 5:    space
#   col 6+:   bold title  |  dim code/description/fix
SEVERITY_LETTER = {
    "CRITICAL": "C",
    "HIGH":     "H",
    "MEDIUM":   "M",
    "LOW":      "L",
    "INFO":     "I",
    "OBSERVATION": "O",
}
BODY_INDENT = "      "  # 6 spaces; aligns body text under the title.

# Minimum gap between the title and the right-aligned metadata block
# before we give up and drop metadata to its own line.
META_MIN_GAP = 2

# Cap on the fallback "all changed lines in this file" preview.
FALLBACK_PREVIEW_MAX_LINES = 12

# Highlight the anchor-resolved target row in the affected-code block
# with a red `-` marker. Anchors provide reliable file/line resolution.
_highlight_target_line = True

# Wrap each expanded finding in a dim box-drawing border (both the
# default terminal output and the --review TUI). Set to False to revert
# to the flat layout - the body still renders, just without the outer
# box frame. The trade-offs (nested borders with the Description /
# Suggestion table, ~4 columns of inner-width loss, ~80 lines of
# framing code, ANSI-width edge cases) are why this is a flag rather
# than hard-coded; flip if those costs outweigh the visual closure.
_use_finding_card = True


def _ordered_findings(result: AuditResult) -> list:
    """Sort findings stable-by-severity (highest first), then by file/line."""
    return sorted(
        result.findings,
        key=lambda f: (
            -SEVERITY_ORDER.get(f.severity, 0),
            f.file or "",
            f.line or 0,
        ),
    )


def _findings_by_file(result: AuditResult) -> list:
    """Group ordered findings by file, preserving severity order within each."""
    grouped: dict = {}
    for f in _ordered_findings(result):
        grouped.setdefault(f.file, []).append(f)
    # Order files by the highest severity found inside them.
    return sorted(
        grouped.items(),
        key=lambda kv: -max(SEVERITY_ORDER.get(f.severity, 0) for f in kv[1]),
    )


def _render_cwe(finding: Finding) -> str:
    """CWE label styled like a hyperlink (blue + underline) when the ID
    parses as a real CWE; falls back to dim plain text otherwise. Real
    CWE labels are also OSC 8 hyperlinks pointing at MITRE."""
    if not finding.cwe:
        return ""
    url = finding.cwe_url()
    if url is None:
        return ui.dim(finding.cwe)
    return ui.link_style(ui.hyperlink(finding.cwe, url))


def _render_path_meta(finding: Finding) -> str:
    """Render the file path (with optional :line) for the right metadata.

    Plain text (no OSC 8 wrap) so a terminal select-and-copy picks up a
    clean string the user can paste into their editor. Styled dim cyan
    so it reads as metadata next to the bold title."""
    if not finding.file:
        return ""
    path_text = f"{finding.file}:{finding.line}" if finding.line else finding.file
    return ui.dim_cyan(path_text)


def _truncate(text: str, max_width: int) -> str:
    """Trim a string to ``max_width`` visible characters, ellipsizing if cut."""
    if ui.visible_len(text) <= max_width:
        return text
    return text[: max(0, max_width - 1)] + "…"


def _truncate_visible(text: str, max_width: int) -> str:
    """ANSI-safe truncate: clamp ``text`` to ``max_width`` visible cells
    without cutting an escape sequence mid-way.

    Walks the string treating each ANSI CSI / OSC 8 match as zero-width.
    Once the visible budget is exhausted, appends ``…\\x1b[0m`` so any
    open color state is reset on the truncated cell.
    """
    if max_width <= 0:
        return ""
    if ui.visible_len(text) <= max_width:
        return text
    visible = 0
    out: list = []
    i = 0
    n = len(text)
    while i < n:
        m = ui._ANSI_RE.match(text, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        if visible >= max_width - 1:
            out.append("…\x1b[0m")
            return "".join(out)
        out.append(text[i])
        visible += 1
        i += 1
    return "".join(out)


def _severity_marker(severity: str) -> str:
    """Badge at the start of a finding's title row.

    Background colored by severity, letter in a contrasting color. The
    badge occupies three visible columns (' L '). The same badge is
    used in the legend so the code is self-documenting.
    """
    letter = SEVERITY_LETTER.get(severity.upper(), "?")
    return ui.severity_badge(severity, letter)


def _print_legend() -> None:
    """Compact legend explaining the C/H/M/L/I/O letter badges.

    The `O` (observation) entry is only included when --show-observations
    is on, so users who haven't opted in don't see a legend item for
    something they'll never produce.
    """
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        parts.append(f"{_severity_marker(sev)} {ui.dim(sev.lower())}")
    if runtime.show_observations:
        parts.append(f"{_severity_marker('OBSERVATION')} {ui.dim('observation')}")
    print("  " + "  ".join(parts))


def _build_metadata(f: Finding) -> str:
    """Right-hand metadata block: path:line  ·  hunk context  ·  CWE-XXX.

    The full path is included so the user can always see (and select to
    copy) where to go fix the issue without needing to expand the
    finding. Hunk context (the enclosing function/class lifted from the
    diff's ``@@`` header) sits between path and CWE so the row reads
    "where in the file" -> "which section" -> "what class of issue".
    """
    parts = []
    path = _render_path_meta(f)
    if path:
        parts.append(path)
    if f.hunk_context:
        # Truncate aggressively: hunk contexts are sometimes a whole
        # function signature with type hints. ~40 chars stays scannable.
        parts.append(ui.dim(_truncate(f.hunk_context, 40)))
    cwe = _render_cwe(f)
    if cwe:
        parts.append(cwe)
    return "  ".join(parts)


def _print_finding_title_row(f: Finding, width: int) -> None:
    """Title row: severity marker + bold title, right-aligned severity/line/CWE.

    Shared by --quiet (only this row) and the default layout (adds the
    code snippet + description + fix beneath). The colored block at col
    2 gives a flush-left scannable severity cue; the right-aligned
    metadata block repeats the severity for wide terminals where the
    marker alone would be lost on the left edge.

    When the title is too long to fit alongside the metadata, drop the
    metadata to its own right-aligned line so the title isn't truncated.
    """
    marker = _severity_marker(f.severity)
    title_styled = f"  {marker} {ui.bold(f.title)}"
    if f.confidence != "high":
        title_styled += ui.dim(f"  (confidence: {f.confidence})")
    metadata = _build_metadata(f)

    if not metadata:
        print(title_styled)
        return

    title_w = ui.visible_len(title_styled)
    meta_w = ui.visible_len(metadata)
    needed = title_w + META_MIN_GAP + meta_w

    if needed <= width:
        pad = width - title_w - meta_w
        print(title_styled + (" " * pad) + metadata)
    else:
        # Narrow terminal or extra-long title. Keep both fully visible by
        # giving metadata its own right-aligned row.
        print(title_styled)
        pad = max(0, width - meta_w)
        print((" " * pad) + metadata)


def _trim_blank_edges(items: list) -> list:
    """Drop whitespace-only entries from the start and end of a line list.

    Used by the code-preview paths to stop a block from opening or
    closing on a blank gutter line (visual padding the reader can't
    interpret). Internal blanks are preserved because they're part of
    the code's own structure.
    """
    start = 0
    while start < len(items) and not items[start][1].strip():
        start += 1
    end = len(items)
    while end > start and not items[end - 1][1].strip():
        end -= 1
    return items[start:end]


def _render_diff_lines(
    collected: list,
    indent: str,
    available: int,
    target_line: Optional[int] = None,
) -> None:
    """Render a list of (lineno, content) tuples in the diff-style block.

    Shared by the precise window (±3 around target) and the fallback
    "all changed lines in this file" path. Target line gets the red
    marker when ``_highlight_target_line`` is on; every other line
    stays default foreground.
    """
    ln_width = max(2, len(str(max(ln for ln, _ in collected))))
    # Overhead: 2-char prefix + 1 space + line number + 2 spaces.
    overhead = 2 + 1 + ln_width + 2
    max_content = max(20, available - overhead)
    for lineno, content in collected:
        # Expand tabs so visible_len matches the rendered column width.
        text = _truncate(_sanitize(content).expandtabs(4), max_content)
        ln_str = str(lineno).rjust(ln_width)
        is_target = (
            target_line is not None and lineno == target_line and _highlight_target_line
        )
        if is_target:
            print(f"{indent}{ui.red('-')} {ui.dim(ln_str)}  {ui.red(text)}")
        else:
            print(f"{indent}  {ui.dim(ln_str)}  {text}")


def _print_affected_block(
    f: Finding,
    diff_lines: dict,
    available: int,
    indent: str,
) -> bool:
    """Render a code window for the finding, falling back when needed.

    Three paths, tried in order:

    1. Precise: model reported a ``line`` AND we have ±3 rows around it
       in the diff. The usual happy path on accurate backends.
    2. Fallback: the file is in the diff, but the precise window failed
       (no ``line`` reported, or the line lies outside the hunk's
       context window). Renders ALL of this file's changed lines,
       capped at ``FALLBACK_PREVIEW_MAX_LINES``. Less precise but far
       more useful than a silent gap on 7B models that routinely drop
       the optional ``line`` field.
    3. Nothing: the file isn't in the diff at all. Return False so the
       caller can render a "file not in diff" placeholder instead.

    Returns True when something printed so the caller can decide
    whether to add surrounding blank lines.
    """
    if not runtime.show_code_preview:
        return False
    if not f.file:
        return False
    file_lines = diff_lines.get(f.file, {})
    if not file_lines:
        return False

    # Path 1: precise ±3 window around the reported line.
    if f.line:
        collected = []
        for offset in range(-3, 4):
            lineno = f.line + offset
            if lineno in file_lines:
                collected.append((lineno, file_lines[lineno]))
        # Drop leading/trailing blank gutter lines so the window opens
        # and closes on real code. Skip if the target itself is blank
        # (rare edge case where trimming would hide what we point at).
        if f.line in file_lines and file_lines[f.line].strip():
            collected = _trim_blank_edges(collected)
        if collected:
            _render_diff_lines(collected, indent, available, target_line=f.line)
            return True

    # Path 2: fallback - show all the file's changed lines (capped).
    # Useful when the model didn't return `line` (common on 7B models)
    # or when it reported a line outside the captured diff window. The
    # dim header distinguishes this from the precise window so the
    # reader knows the location was approximate.
    items = sorted(file_lines.items())
    items = _trim_blank_edges(items)
    if not items:
        return False
    truncated = len(items) > FALLBACK_PREVIEW_MAX_LINES
    if truncated:
        items = items[:FALLBACK_PREVIEW_MAX_LINES]
        # Trim the cap's tail too in case the cut landed on a blank.
        items = _trim_blank_edges(items)
    if f.line:
        hint = f"line {f.line} not in diff window - showing this file's changed lines:"
    else:
        hint = "model did not report a line - showing this file's changed lines:"
    print(f"{indent}{ui.dim(hint)}")
    _render_diff_lines(items, indent, available, target_line=f.line)
    if truncated:
        more = sum(1 for v in file_lines.values() if v.strip()) - len(items)
        if more > 0:
            print(f"{indent}{ui.dim(f'... ({more} more changed lines in this file)')}")
    return True


def _print_info_table(
    rows: list,
    available: int,
    indent: str,
) -> None:
    """Render a two-column box-drawing table: label cell + body cell.

    ``rows`` is a list of ``(label, body, style_fn)`` tuples. ``style_fn``
    is a ``ui.*`` helper applied to the label (e.g. ``ui.bold``, or a
    lambda chaining ``ui.bold`` + ``ui.green`` for the Fix row). Rows
    with an empty body are dropped silently so callers can pass them
    unconditionally.

    Box characters render dim so the table feels like structure, not
    chrome that competes with content. Label is styled, body stays at
    default foreground for maximum readability.
    """
    rows = [(label, body, style) for label, body, style in rows if body]
    if not rows:
        return
    # Inner widths exclude the vertical bars themselves (3 total).
    label_inner_w = max(len(label) for label, _, _ in rows) + 2
    body_inner_w = max(20, available - label_inner_w - 3)
    body_text_w = max(10, body_inner_w - 2)  # 1-char padding each side

    bar = ui.dim("│")

    def hline(left: str, mid: str, right: str) -> str:
        return (
            indent
            + ui.dim(left + ("─" * label_inner_w) + mid + ("─" * body_inner_w) + right)
        )

    print(hline("┌", "┬", "┐"))
    for i, (label, body, style) in enumerate(rows):
        if i > 0:
            print(hline("├", "┼", "┤"))
        body_lines = textwrap.wrap(body, width=body_text_w) or [body]
        for j, line in enumerate(body_lines):
            if j == 0:
                # Label cell on the first wrapped line of the row.
                pad_right = max(0, label_inner_w - 1 - len(label))
                label_cell = " " + style(label) + (" " * pad_right)
            else:
                # Continuation lines: label cell is intentionally blank.
                label_cell = " " * label_inner_w
            pad_body = max(0, body_inner_w - 1 - len(line))
            body_cell = " " + line + (" " * pad_body)
            print(f"{indent}{bar}{label_cell}{bar}{body_cell}{bar}")
    print(hline("└", "┴", "┘"))


def _print_fix_example(f: Finding, available: int, indent: str) -> None:
    """Render fix_example as a green diff block under an Example: label.

    Each line is prefixed with ``+`` and rendered green so the snippet
    visually mirrors the red ``-`` block above. Code lines are truncated
    rather than wrapped - wrapping changes meaning.
    """
    if not runtime.show_code_preview:
        return
    if not f.fix_example:
        return
    lines = [line for line in f.fix_example.splitlines() if line.strip()]
    if not lines:
        return
    print(f"{indent}{ui.bold(ui.blue('Example:'))}")
    # Overhead: 2-char prefix + 1 space.
    max_content = max(20, available - 3)
    for line in lines:
        text = _truncate(_sanitize(line).expandtabs(4), max_content)
        print(f"{indent}{ui.green('+')} {ui.green(text)}")


def _render_finding_card(
    f: Finding,
    diff_lines: dict,
    *,
    width: int,
    outer_indent: str,
    nav_prefix: str = "",
    active: bool = False,
) -> None:
    """Render one finding's full card: title row + body, optionally boxed.

    Shared by the default ``print_terminal`` layout and the ``--review``
    TUI's expanded row. ``outer_indent`` is the left-margin string each
    output line gets. ``nav_prefix`` is an optional cursor/checkbox
    string that sits to the left of the box's top border (review TUI
    only); pass an empty string for the default layout. ``active=True``
    paints the outer border in cyan so the user can pick the currently
    focused card out of a column of expanded ones at a glance.

    When ``_use_finding_card`` is False the card renders flat: same
    content, no enclosing frame. Flip the flag near the top of this
    file to revert.
    """
    nav_w = ui.visible_len(nav_prefix)
    # Body capture happens with indent="" so the framing logic owns the
    # left padding; the flat fallback prepends the outer indent itself.
    boxed = _use_finding_card
    # Box overhead is: outer_indent + nav padding + 2 border chars +
    # 2 inner pad spaces + 1 right-edge margin. The right-edge margin
    # keeps the closing ``│`` at column ``width - 1`` instead of
    # column ``width``; without it some terminal emulators auto-wrap
    # the last column or count a scrollbar against usable width.
    overhead = (4 + nav_w + len(outer_indent) + 1) if boxed else len(outer_indent)
    inner_w = max(20, width - overhead)

    # Capture: code window + Description/Suggestion table + Example.
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code_rendered = _print_affected_block(f, diff_lines, inner_w, "")
        if not code_rendered and runtime.show_code_preview and f.file:
            print(ui.dim("(no code preview - file not present in the scanned diff)"))
            code_rendered = True
        if code_rendered:
            print()
        _print_info_table(
            [
                ("Description", f.description, ui.bold),
                ("Suggestion", f.recommendation, ui.bold),
            ],
            inner_w,
            "",
        )
        if f.fix_example and runtime.show_code_preview:
            print()
            _print_fix_example(f, inner_w, "")
    body_lines = buf.getvalue().splitlines()
    while body_lines and not body_lines[-1].strip():
        body_lines.pop()

    # Build the title row(s) inside the card: severity badge + bold
    # title on the left, file:line + CWE right-aligned. Falls back to a
    # two-row form on narrow terminals so meta never crowds the title.
    badge = _severity_marker(f.severity)
    title_inside = f"{badge} {ui.bold(f.title)}"
    if f.confidence != "high":
        title_inside += ui.dim(f"  (confidence: {f.confidence})")
    meta = _build_metadata(f)
    title_w = ui.visible_len(title_inside)
    meta_w = ui.visible_len(meta)
    title_lines = []
    if meta_w and title_w + META_MIN_GAP + meta_w <= inner_w:
        pad = inner_w - title_w - meta_w
        title_lines.append(title_inside + (" " * pad) + meta)
    else:
        title_lines.append(title_inside)
        if meta_w:
            title_lines.append((" " * max(0, inner_w - meta_w)) + meta)

    if not boxed:
        # Flat fallback: print title + blank + body, all prefixed with
        # outer_indent. Same visual order as the boxed form, no frame.
        if nav_prefix:
            print(nav_prefix + title_lines[0])
            for tl in title_lines[1:]:
                print(outer_indent + tl)
        else:
            for tl in title_lines:
                print(outer_indent + tl)
        print()
        for line in body_lines:
            print(outer_indent + line)
        return

    # Boxed: frame each captured line with `│ ... │` and add top + bot
    # borders. Nav prefix (if any) sits to the left of the top border;
    # subsequent lines indent under it.
    border_style = ui.cyan if active else ui.dim
    bar = border_style("│")
    top = border_style("┌" + ("─" * (inner_w + 2)) + "┐")
    bot = border_style("└" + ("─" * (inner_w + 2)) + "┘")
    box_indent = outer_indent + (" " * nav_w) if nav_prefix else outer_indent

    def _boxed(line: str) -> None:
        # Tab expansion keeps visible_len aligned with rendered width;
        # ANSI-safe truncation prevents a too-wide line (deep file
        # path in metadata, long quoted code) from pushing the right
        # border past the terminal edge.
        line = line.expandtabs(4)
        if ui.visible_len(line) > inner_w:
            line = _truncate_visible(line, inner_w)
        vw = ui.visible_len(line)
        pad = max(0, inner_w - vw)
        print(f"{box_indent}{bar} {line}{' ' * pad} {bar}")

    if nav_prefix:
        print(outer_indent + nav_prefix + top)
    else:
        print(outer_indent + top)
    for tl in title_lines:
        _boxed(tl)
    _boxed("")
    for line in body_lines:
        _boxed(line)
    print(box_indent + bot)


def _print_finding_block(f: Finding, diff_lines: dict) -> None:
    """Default layout: render the finding as a boxed card (or flat when
    ``_use_finding_card`` is False). Delegates to :func:`_render_finding_card`
    so the review TUI and the default output stay visually identical
    apart from the cursor / checkbox nav prefix.
    """
    _render_finding_card(
        f,
        diff_lines,
        width=ui.term_width(),
        outer_indent="  ",
    )
    print()


def _print_summary(result: AuditResult) -> None:
    """One-line per-severity tally with elapsed time."""
    summary = result.summary
    parts = []
    total = sum(summary.values())
    parts.append(ui.bold(f"{total} findings"))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in summary:
            parts.append(ui.severity_color(f"{summary[sev]} {sev.lower()}", sev))
    elapsed = ui.dim(f"  {result.elapsed:.1f}s") if result.elapsed else ""
    print(f"{('  ' + ui.dim('·') + '  ').join(parts)}{elapsed}")
    print()


def _print_footer(result: AuditResult, threshold: str) -> None:
    """Result label (PASS/FAIL) + actionable next step."""
    if result.exceeds_threshold(threshold):
        label = ui.bold(ui.red("FAIL"))
        n = len(result.blocking_findings)
        print(f"{label}  Fix the {n} issue{'s' if n != 1 else ''} above, then `{ui.bold('git commit')}`.")
        print(f"      Bypass once: {ui.dim('PWNGUARD_SKIP=1 git commit')}")
    else:
        label = ui.bold(ui.green("PASS"))
        print(f"{label}  No findings at or above {threshold} threshold.")
    print()


def _file_header(filepath: str, findings: list) -> str:
    """Rendered file header (clickable, anchored at first finding's line)."""
    first_line = next((f.line for f in findings if f.line), None)
    link = ui.file_link(filepath, first_line) if first_line else ui.file_link(filepath)
    return ui.underline(ui.bold(link))


def _print_observations(observations: list) -> None:
    """Render the opt-in observations block.

    Each observation is laid out like a finding's quiet row plus a
    single dim body line for the note:

        [O] pattern                                       file:line
            note text, wrapped if long

    Keeping the title row note-free means file:line always lands at
    the same column across observations - the inline-note version
    produced jagged right edges that read as misalignment. The note
    sits underneath as dim wrapped body so the row stays scannable.

    Takes a plain list rather than the full ``AuditResult`` so the TUI
    redraw path (which keeps its own state, not the result object) can
    call it directly with the same look-and-feel.
    """
    if not observations:
        return
    width = ui.term_width()
    available = max(20, width - len(BODY_INDENT))
    badge = _severity_marker("OBSERVATION")

    print()
    print(ui.dim("Observations  ·  informational only, not security validation"))
    for o in observations:
        title_styled = f"  {badge} {ui.bold(o.pattern)}"

        # Right-aligned metadata: file:line. Observations don't have CWE.
        loc = ""
        if o.file:
            loc = f"{o.file}:{o.line}" if o.line else o.file
        meta = ui.dim(loc) if loc else ""

        title_w = ui.visible_len(title_styled)
        meta_w = ui.visible_len(meta)
        if not meta:
            print(title_styled)
        elif title_w + META_MIN_GAP + meta_w <= width:
            pad = width - title_w - meta_w
            print(title_styled + (" " * pad) + meta)
        else:
            print(title_styled)
            pad = max(0, width - meta_w)
            print((" " * pad) + meta)

        if o.note:
            for line in textwrap.wrap(o.note, width=available) or [o.note]:
                print(f"{BODY_INDENT}{ui.dim(line)}")


def print_terminal(
    result: AuditResult,
    threshold: str,
    diff_lines: dict,
    *,
    files_scanned: int,
    quiet: bool = False,
) -> None:
    """Render the audit result to the terminal in the grouped layout."""
    width = ui.term_width()

    # Header line (no left indent; chrome stays out of the way).
    header = ui.bold("PwnGuard")
    file_word = "file" if files_scanned == 1 else "files"
    subtitle = ui.dim(f"scanned {files_scanned} {file_word}")
    elapsed = ui.dim(f"  {result.elapsed:.1f}s") if result.elapsed else ""
    print()
    print(f"{header}  {subtitle}{elapsed}")

    if result.error:
        print()
        print(f"{ui.bold(ui.red('ERROR'))}  {result.error}")
        print()
        return

    if not result.findings:
        _print_observations(result.observations)
        print()
        print(f"{ui.bold(ui.green('PASS'))}  No security issues found.")
        print()
        return

    # Legend (only when there are findings; otherwise it's noise).
    _print_legend()
    print()

    # Both layouts group by file and share the title-row format.
    # --quiet collapses to that one row; default mode adds the code
    # snippet, description, and fix beneath.
    for filepath, findings in _findings_by_file(result):
        print(_file_header(filepath, findings))
        if quiet:
            for f in findings:
                _print_finding_title_row(f, width)
            print()
        else:
            for f in findings:
                _print_finding_block(f, diff_lines)

    _print_summary(result)
    _print_observations(result.observations)
    # Blank between the observations block and the FAIL/PASS footer so
    # the call-to-action doesn't crowd the last observation row. No-op
    # when there were no observations (summary already left a blank).
    if result.observations:
        print()
    _print_footer(result, threshold)

# Interactive review (TUI)

[← Back to README](../README.md)

Pass `--review` to walk through findings interactively after a scan.
Uses raw-mode keyboard input on the alternate screen buffer (Unix
only; gracefully no-ops on Windows or non-TTY).

Keys:

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move the cursor to the previous / next finding |
| `→` | Expand the current finding (shows code, description, fix) |
| `←` | Collapse the current finding |
| `space` (or `x`) | Toggle a `[x]` mark on the current finding (visual only, doesn't affect exit code) |
| `e` | Export every non-struck finding to a timestamped markdown file in the current directory (`pwnguard-findings-YYYYMMDD-HHMMSS.md`) |
| `q` (or `esc`) | Quit |

Marks are informational only. They don't change the threshold check or
the exit code; the standard report is what drives commit pass/fail.

Export is useful for pruning out false positives interactively, then
handing the trimmed list to a colleague or pasting it into a ticket
without editing the full `--report` output by hand.

The expanded view shows the file path (dim cyan, plain text so you can
select and copy it), CWE link (bright blue + underlined, OSC 8 clickable
in modern terminals), the affected code with red `-` prefix + line
numbers, the description, and a bold-green `Fix:` recommendation, all
inside a dashed card.

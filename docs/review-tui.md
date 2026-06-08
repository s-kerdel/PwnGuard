# Interactive review (TUI)

[← Back to README](../README.md)

Pass `--review` to walk through findings interactively after a scan.
Uses raw-mode keyboard input on the alternate screen buffer (Unix
only; gracefully no-ops on Windows or non-TTY).

## Re-running after a hook commit (`--cached`)

When a pre-commit hook scan blocks a commit and you're in an
interactive terminal, PwnGuard prints a tip suggesting:

```
pwnguard --mode hook --color --review --cached
```

The hook already scanned the staged diff; `--cached` reuses that result
instead of paying for a second AI call, then opens this TUI. The cache
is content-keyed (diff + backend + model + pwnguard version) and stored
in `.git/pwnguard-scan-cache.json`, so if you `git add` more files
before re-running it misses and re-scans rather than showing stale
findings. The tip only appears when a terminal is reachable to re-run
in - a git GUI's commit panel (no controlling terminal) and Windows
(no cbreak TUI) stay silent.

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

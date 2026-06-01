# Monitor mode (`--monitor`)

[← Back to README](../README.md)

A dashboard TUI that watches one or more remote repos, audits the
latest commit on each watched branch when it changes, and lets you
step through findings without re-running the audit. Designed for
"catch attention on new released work" workflows — you get a quick
heads-up that something landed, then validate manually.

Open the dashboard:

```bash
pwnguard --monitor
```

State is cached in `.pwnguard-monitor.json` in the current working
directory (per-project), with mode `0600` on Unix. Run from two
different directories and you get two independent caches.

## Configure repos in `pwnguard.yaml`

```yaml
monitor:
  repos:
    - name: api-server
      url: https://gitlab.com/group/api-server
      branch: main
    - name: vendor-fork
      url: https://github.com/owner/repo
      branch: upstream
```

Each entry needs `name`, `url`, and `branch`. Hostname must contain
`gitlab` or `github` for the platform to auto-detect; custom-domain
self-hosted instances are not yet supported in monitor mode.

## Key bindings

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move the cursor between repos / findings |
| `enter` | Toggle expand / collapse on the current row |
| `→` | Expand (alternative to `enter`) |
| `←` | Collapse (alternative to `enter`) |
| `-` | Collapse everything (all repos + all findings) |
| `=` | Expand everything |
| `space` | Toggle strike-through on the current finding (also collapses if it was expanded). No-op on a repo row. |
| `v` | Mark the current repo viewed (clears the `[updated]` chip) |
| `e` | Export every non-struck finding across all repos to a timestamped markdown file in the current directory (`pwnguard-monitor-findings-YYYYMMDD-HHMMSS.md`), grouped by repo |
| `r` | Refresh (poll all repos via API, audit anything new) |
| `q` (or `esc`) | Save state and quit |

The export is read-only: strike marks aren't cleared, persistent state
(`.pwnguard-monitor.json`) is untouched. Pressing `e` again later
produces a fresh file with the current view; old exports are left in
place.

## How a refresh works

For each configured repo, PwnGuard calls the platform's list-commits
API, compares the latest SHA on the branch to the cached
`last_audited_sha`, and decides:

- **First encounter** — no cached SHA yet. The current HEAD is
  audited so the dashboard reflects branch state immediately on the
  first `[r]` press. Costs one LLM call per repo on initial setup.
  The `[updated]` chip is suppressed on this initial audit (you're
  staring at the result; nothing to "catch up on").
- **No change** — head matches cache. Skip; no LLM call.
- **New commit** — exactly one commit (the latest) is audited.
  Intermediate commits between cache and head are not audited; the
  diff against `last_audited_sha` is what gets sent to the model.
  The `[updated]` chip fires until you press `[space]`.

The cap of one commit per repo per refresh keeps the worst-case
refresh time bounded and avoids ballooning the prompt past a small
model's context window. If a backlog of unscanned commits matters
for your workflow, this is the knob to revisit in a follow-up
release.

## Verifying the model is actually running (`--debug`)

`pwnguard --monitor --debug` keeps the dashboard, but pressing
`r` temporarily drops out of the TUI so the backend's live token
stream prints to your normal terminal (same streaming output you'd
see from `--debug` on a regular scan). When the refresh finishes you
press Enter to return to the dashboard. Useful for confirming that
Ollama (or whichever backend) is actually being called, watching
prompt processing speed, and spotting truncated / refused responses.

## The `[updated]` chip

A repo row shows `[updated]` when `last_audited_sha != last_viewed_sha`
— i.e. PwnGuard has audited a new commit since you last acknowledged
this repo. Pressing `[space]` while the cursor is on the row sets
viewed = audited and the chip clears.

## What each repo row shows

Reading left to right:

- Cursor mark (`❯` in bold cyan when the row is the active one)
- Expand arrow (`▶` collapsed, `▼` expanded)
- Repo name
- Severity breakdown — `1 C  ·  3 H  ·  5 M  ·  12 INFO`, coloured per
  severity, only categories with non-zero counts shown. `clean` when
  audited with no findings; `awaiting first refresh` before the first
  audit on a freshly-configured repo
- Right-aligned: short commit date (`3d`, `2w`, etc.), short SHA, and
  the `[updated]` chip when there's been an audit since you last
  pressed `[space]` on this row

Expanding a row reveals its findings as individually-selectable rows;
expanding an individual finding shows the same boxed card layout
`--review` uses, including the ±3-line code preview window (diff
content is cached alongside findings so this is offline).

## What the state file contains

```json
{
  "version": 1,
  "repos": {
    "https://gitlab.com/group/api-server@main": {
      "name":                       "api-server",
      "last_audited_sha":           "abc1234...",
      "last_viewed_sha":            "abc1234...",
      "last_audited_commit_date":   "2026-05-15T09:00:00+00:00",
      "audited_at":                 "2026-05-15T09:14:00+00:00",
      "findings":                   [ /* asdict(Finding) per finding */ ],
      "diff_lines":                 { "src/users.py": { "42": "..." } }
    }
  }
}
```

The file is JSON (never `pickle` — that would be unsafe to load
from disk). Findings and cached diff lines are re-sanitised on load
as belt-and-braces against an offline-tampered cache; even a
hand-edited state file cannot smuggle ANSI escapes into the renderer.
Tokens are read from env vars only and **never** persisted.

`diff_lines` is the per-commit code cache the TUI uses to draw the
±3-line preview window without re-fetching. Size is bounded by the
commit (typically 5-50 KB per audit); the file is rewritten on every
refresh so there's no unbounded growth.

## Limits

- One commit per refresh, per repo (no batch / range scanning yet).
- No background poller; refresh runs synchronously in the TUI and
  blocks for the duration. Wire `pwnguard --monitor` to a wrapper
  later if you want it on a cron schedule.
- No notification outputs (Slack / email / etc.). Findings live in
  the TUI and the state file.
- No platform support beyond GitLab and GitHub (custom-domain
  self-hosted instances are deferred until there's a clean way to
  configure platform explicitly).
- Concurrent runs of `--monitor` in the same cwd will race on the
  state file. Treated as a cache; last writer wins.

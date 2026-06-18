# Monitor mode (`--monitor`)

[← Back to README](../README.md)

A dashboard TUI that watches one or more remote repos, audits **every
new commit** between the last scanned revision and the branch HEAD (one
audit per commit), and lets you step through findings without re-running
the audit. Designed for "catch attention on new released work"
workflows — you get a quick heads-up that something landed, then
validate manually.

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
  review_everything_at_once: true  # one refresh reviews all new changes (off: one batch per [r])
  max_commits_per_refresh: 10   # batch size per [r]; also the cap when review_everything_at_once is off
  keep_commits: 30              # retained audited commits per repo before pruning oldest
```

Each entry needs `name`, `url`, and `branch`. Hostname must contain
`gitlab` or `github` for the platform to auto-detect; custom-domain
self-hosted instances are not yet supported in monitor mode.

`review_everything_at_once` (default `true`), `max_commits_per_refresh`
(default `10`), and `keep_commits` (default `30`) are optional — see
[How a refresh works](#how-a-refresh-works) and [Limits](#limits).

## The repo → commit → finding tree

The dashboard is a three-level tree:

```
❯ ▼  api-server                 1 C · 3 H · 9 INFO    5d   abc1234   3 new
        2 clean hidden  (press [f] to show all commits)
     ▼ ● 9f3e1c2   1 C · 2 H                           5d
          ▣ CRITICAL  Auth bypass in middleware        auth.py:42
          ▣ HIGH      Missing rate limit               api.py:88
     ▶ ● abc1234   2 H · 1 INFO                         6d
```

The per-repo severity breakdown sits inline after the name; the relative
time, SHA, and status chips are right-aligned.

By default only commits **with findings** appear beneath a repo; clean
commits collapse into the `N clean hidden` summary so a large catch-up
reads as the few commits that matter. Press `[f]` to reveal every
commit. A `●` marks a commit newer than your last-viewed point.

Expanding a **repo** reveals its audited **commits** (newest first);
expanding a **commit** reveals that commit's **findings**; expanding a
**finding** shows the full boxed card (same layout `--review` uses,
including the ±3-line code preview, served from cache so it's offline).

## Key bindings

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move the cursor between repos / commits / findings |
| `enter` | Toggle expand / collapse on the current row |
| `→` | Expand (alternative to `enter`) |
| `←` | Collapse (alternative to `enter`) |
| `-` | Collapse everything (repos, commits, findings) |
| `=` | Expand everything |
| `space` | Toggle strike-through on the current finding (also collapses if it was expanded). No-op on a repo or commit row. |
| `v` | Mark viewed up to the current row — on a repo, acknowledges everything; on a commit or finding, acknowledges that commit and all older ones (clears their `●` dots, lowers the `N new` count) |
| `f` | Toggle showing all commits vs findings-first for the current repo (clean commits are hidden by default) |
| `e` | Export every non-struck finding across all repos to a timestamped markdown file in the current directory (`pwnguard-monitor-findings-YYYYMMDD-HHMMSS.md`), grouped by repo (commits flattened under the repo heading) |
| `r` | Refresh (audit every new commit since the last scan) |
| `q` (or `esc`) | Save state and quit |

The export is read-only: strike marks aren't cleared, persistent state
(`.pwnguard-monitor.json`) is untouched. Pressing `e` again later
produces a fresh file with the current view; old exports are left in
place.

## How a refresh works

For each configured repo, PwnGuard asks the platform's **compare**
endpoint (GitHub `compare/base...head`, GitLab `repository/compare`)
for the commits between the cached `last_audited_sha` and the branch
HEAD, then:

- **First encounter** — no cached SHA yet. Only the current HEAD is
  audited, so the dashboard reflects branch state immediately on the
  first `[r]` press. Pre-existing history is *not* backfilled. The
  `N new` chip is suppressed on this initial audit (you're staring
  at the result; nothing to "catch up on").
- **No change** — the compare endpoint reports the branch is identical.
  Skip; no LLM call.
- **New commits** — every commit in the range is audited, **one LLM
  call per commit**, oldest-first. Already-cached SHAs are skipped
  (dedup), so re-pressing `[r]` never re-audits. `last_audited_sha`
  advances commit-by-commit, so the audited history stays contiguous.
- **History rewritten** (force-push / rebase, where the cached SHA is
  no longer an ancestor of HEAD) — PwnGuard falls back to auditing
  HEAD only rather than scanning a confused range. (GitHub reports this
  explicitly; on GitLab the dedup + pointer-advance keep it safe.)

### Catching up to HEAD

With `review_everything_at_once` **on** (the default), one `[r]` press
audits *every* new commit up to the branch HEAD. `max_commits_per_refresh`
(default **10**) becomes the batch size used for progress reporting, not
a stopping point: PwnGuard keeps fetching the next window and auditing
oldest-first until the repo is fully caught up. After a clean catch-up
the repo is at HEAD with nothing pending.

With it **off**, at most `max_commits_per_refresh` commits are audited
per `[r]` press. PwnGuard audits the **oldest** chunk, advances the
pointer, and surfaces the remainder as a `N pending` chip on the repo
row; the backlog drains over subsequent refreshes. Use this to bound
worst-case refresh time on very active repos. **Either way, nothing is
silently skipped.**

### When a repo errors

If a refresh fails for one repo (network error, HTTP 4xx/5xx, a commit
the backend can't audit), it never aborts the others. The repo keeps a
red **`error`** chip and the refresh summary counts it. **Expand the
repo** (`enter` / `→`) to read the actual error message beneath the
row. The error clears automatically on the next refresh that succeeds.

## Verifying the model is actually running (`--debug`)

`pwnguard --monitor --debug` keeps the dashboard, but pressing `r`
temporarily drops out of the TUI so the backend's live token stream
prints to your normal terminal (same streaming output you'd see from
`--debug` on a regular scan). When the refresh finishes you press Enter
to return to the dashboard. Useful for confirming that Ollama (or
whichever backend) is actually being called, watching prompt processing
speed, and spotting truncated / refused responses.

## Status chips

The right side of each repo row shows the relative age and short SHA,
then at most one chip per concern, colour-coded so the meaning reads at
a glance:

- **`N new`** (cyan): `N` audited commits are newer than your
  last-viewed point (`last_viewed_sha`), i.e. PwnGuard has audited
  commits since you last acknowledged this repo. Press `[v]` on the repo
  row to set viewed = audited and clear it entirely, or `[v]` on a
  commit/finding to acknowledge just up to that commit (clearing its `●`
  dot and all older ones). `[v]` only ever moves the marker forward.
- **`N pending`** (yellow): `N` commits seen on the branch but not yet
  audited. With `review_everything_at_once` off this is the deferred
  batch; press `[r]` again to audit the next chunk.
- **`error`** (red): the last refresh failed for this repo. Expand the
  repo to read why; it clears on the next successful refresh.

A long repo name is truncated before the chips are, so the status is
never cut off.

## What each repo row shows

Reading left to right:

- Cursor mark (`❯` in bold cyan when the row is the active one)
- Expand arrow (`▶` collapsed, `▼` expanded)
- Repo name
- Severity breakdown **aggregated across every audited commit** —
  `1 C  ·  3 H  ·  5 M  ·  12 INFO`, coloured per severity, only
  non-zero categories shown. `clean` when audited with no findings;
  `awaiting first refresh` before the first audit
- Right-aligned: relative time of the newest audited commit (`3d`,
  `2w`, etc.), short SHA of `last_audited_sha`, then the `N new`,
  `N pending`, and/or `error` chips when applicable (see
  [Status chips](#status-chips))
- When expanded in findings-first mode, a `N clean hidden` summary line
  naming how many clean commits are collapsed away, plus the failure
  message when the repo errored

Each **commit row** beneath shows a `●` if it's newer than the
last-viewed point, its short SHA, that commit's own severity breakdown
(or `clean`), and its relative age.

## What the state file contains

```json
{
  "version": 2,
  "repos": {
    "https://gitlab.com/group/api-server@main": {
      "name":              "api-server",
      "url":               "https://gitlab.com/group/api-server",
      "branch":            "main",
      "last_audited_sha":  "abc1234...",
      "last_viewed_sha":   "abc1234...",
      "head_sha":          "abc1234...",
      "audited_at":        "2026-05-15T09:14:00+00:00",
      "commits": {
        "abc1234...": {
          "sha":        "abc1234...",
          "date":       "2026-05-15T09:00:00+00:00",
          "audited_at": "2026-05-15T09:14:00+00:00",
          "findings":   [ /* asdict(Finding) per finding */ ],
          "diff_lines": { "src/users.py": { "42": "..." } }
        }
      },
      "order": [ "abc1234..." ]
    }
  }
}
```

Findings are keyed by commit SHA — a commit's diff is immutable, so its
findings never go stale and re-pressing `[r]` is a cheap no-op. `order`
is the newest-first display order; `head_sha` is the newest SHA seen on
the branch (it leads `last_audited_sha` only when a single-batch refresh
deferred a backlog). `last_viewed_sha` is your acknowledgement point —
the boundary that drives the `N new` chip and per-commit `●` dots.

The file is JSON (never `pickle` — that would be unsafe to load from
disk). A **v1 file from an earlier release is migrated to v2 in place**
on first load. Findings, cached diff lines, and the rendered SHAs are
re-sanitised on load as belt-and-braces against an offline-tampered
cache; even a hand-edited state file cannot smuggle ANSI escapes into
the renderer. Tokens are read from env vars only and **never**
persisted.

`diff_lines` is the per-commit code cache the TUI uses to draw the
±3-line preview window without re-fetching. The commit cache is pruned
to the newest `keep_commits` (default 30) entries per repo on every
refresh, so the file doesn't grow without bound.

## Limits

- **First encounter audits HEAD only** — a repo's pre-existing history
  isn't backfilled; auditing starts from the commit present when you
  first add it.
- GitLab force-push (history rewrite) isn't reported as cleanly as
  GitHub's; the dedup + pointer-advance keep it safe, but a rebase may
  cost a re-audit of HEAD.
- No background poller; refresh runs synchronously in the TUI and
  blocks for the duration. With `review_everything_at_once` on, a repo
  with a large backlog blocks until fully caught up (Ctrl-C stops it;
  the pointer stays contiguous). Set it off to bound each `[r]` to one
  batch. Wire `pwnguard --monitor` to a wrapper later for a cron schedule.
- No notification outputs (Slack / email / etc.). Findings live in the
  TUI and the state file.
- No platform support beyond GitLab and GitHub (custom-domain
  self-hosted instances are deferred until there's a clean way to
  configure platform explicitly).
- Concurrent runs of `--monitor` in the same cwd will race on the state
  file. Treated as a cache; last writer wins.

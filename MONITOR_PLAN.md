# Monitor mode (v0.2.0) — implementation plan

Status: planning artifact. Delete or move to a CHANGELOG section after
the feature ships.

## Goal

A TUI dashboard that polls one or more remote git repos for new
commits, audits the latest commit on each watched branch, and lets the
user expand findings without re-running the audit. Drives the "catch
attention on new released work" workflow.

## Locked decisions

| Topic | Choice |
|---|---|
| Repo access | Remote API only (GitLab + GitHub). No local clones. |
| Per-cycle workload | One LLM call per repo at most. Only the **latest** commit on the watched branch is audited; in-between commits are skipped. |
| Baseline | First time a repo is seen, `last_audited_sha` is set to the current HEAD with no audit run. The user only gets findings for commits that land **after** the first refresh. |
| State location | `.pwnguard-monitor.json` in the cwd. Per-project cache; running monitor from two directories means two independent state files. |
| Concurrency | Out of scope for v0.2.0. Last writer wins on the state file. |
| Caching | Findings are persisted in state so reopening the TUI doesn't re-query the LLM. |
| CLI verb | `--monitor` short-circuits like `--self-test`. `--watch` is reserved for a future "watch one URL" mode. |
| Cap | 1 commit per refresh. Extending the range is a v0.2.x follow-up if needed. |

## State file schema

`.pwnguard-monitor.json`, written with mode `0600`:

```json
{
  "version": 1,
  "repos": {
    "https://gitlab.com/group/api-server@main": {
      "name":             "api-server",
      "last_audited_sha": "abc1234567890abcdef",
      "last_viewed_sha":  "abc1234567890abcdef",
      "audited_at":       "2026-05-15T09:14:00Z",
      "findings":         [ /* asdict(Finding) per finding */ ]
    }
  }
}
```

Key format: `<url>@<branch>` so watching two branches of the same repo
keeps independent state.

- `last_audited_sha`: the commit we last fetched + audited.
- `last_viewed_sha`: the commit the user has acknowledged in the TUI.
  When the two differ, the repo row renders an `[updated]` chip.
- `findings`: full `Finding` dicts so the renderer never needs to
  re-query the LLM for already-seen commits.
- Loaded findings are re-sanitised on the way in as belt-and-braces
  against tampered state.

## Yaml config

New top-level `monitor:` block in `pwnguard.yaml`:

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

Each entry needs `name`, `url`, and `branch`. Threshold and backend
overrides come later if there's demand.

## TUI mockup

```
PwnGuard Monitor  ·  4 repos  ·  refreshed 3m ago

▼  api-server                                       ghi9abc  [updated]
     [H] sql injection via id in lookup_user        src/users.py:42  CWE-89
     [C] eval on user-supplied input                src/calc.py:88   CWE-94

▶  legacy-payment                                   def5678
▶  vendor-fork                                      ghi9abc  [updated]
▶  docs-site                                        jkl2345

  [↑/↓] move   [enter] expand   [space] mark viewed   [r] refresh   [q] quit
```

- Collapsed repo row: arrow + name + right-aligned short sha + chip.
- `[updated]` chip when `last_audited_sha != last_viewed_sha`.
- Expanded: findings rendered with the same boxed card layout used by
  `--review`, indented under the repo header.
- Refresh runs synchronously and blocks the TUI; a status line at the
  bottom shows `Refreshing api-server (1/4)...`.

## File-by-file changes

### `audit.py`

| Change | Approx LOC |
|---|---|
| `_list_gitlab_commits(parsed, branch, limit=1)` | 25 |
| `_list_github_commits(parsed, branch, limit=1)` | 25 |
| `_list_commits_from_url(url, branch)` (dispatcher) | 20 |
| `_repo_key(url, branch)` (canonical state key) | 5 |
| `_load_monitor_state(path)` | 35 |
| `_save_monitor_state(state, path)` (chmod 0600) | 20 |
| `_sanitize_loaded_findings(state)` | 15 |
| `_audit_commit_for_monitor(commit_url, config, backend)` | 40 |
| `_run_monitor_refresh(config, state, backend)` | 60 |
| `interactive_monitor(config, state_path)` (TUI) | 200 |
| `--monitor` CLI flag wiring | 25 |

### `ui.py`

Mostly reused. May need a `monitor_status_line` helper for the bottom
status bar. ~30 LOC if anything.

### `tests/`

| New / extended | Coverage |
|---|---|
| `tests/test_monitor_state.py` (new) | Load missing file → empty state; load malformed → empty state + warn; save creates 0600 file; round-trip preserves anchor + finding fields; sanitization scrubs control chars on load. |
| `tests/test_list_commits.py` (new) | GitLab list endpoint hit + token forwarded; GitHub list endpoint hit + bearer forwarded; URL routing dispatches correctly; empty response handled. |
| `tests/test_monitor_cycle.py` (new) | First encounter records HEAD without LLM call; repeat refresh with no new commits is a no-op; new commit triggers audit + state update; `[updated]` chip logic; `mark viewed` clears chip. |

Targets: ~50 tests, ~300 LOC, no new dependencies. All run inside the
existing pre-commit gate.

### `README.md`

New "Monitor mode" section: yaml config example, key bindings, how the
state file works, what `[updated]` means, the cap=1 limitation,
security notes (state file is `0600`, never holds tokens).

## Phasing

Each phase is committed once tests pass.

### Phase 1.0 — single-repo plumbing

- `_list_*_commits` for both platforms.
- `_repo_key`, `_load_monitor_state`, `_save_monitor_state`.
- `_audit_commit_for_monitor` (wraps existing dispatch).
- `_run_monitor_refresh` that handles exactly one repo, hardcoded in a
  fixture or yaml block.
- Tests for state save/load + list-commits dispatch + token forwarding.

**Acceptance:** `pwnguard --monitor` (with one repo configured in yaml)
shows the repo + audits its head, prints findings as plain text
(not yet a TUI). On second invocation with no new commits, prints
"no changes." Tests green.

### Phase 1.1 — multi-repo

- `monitor.repos[]` config parsing.
- Refresh loop iterates all configured repos.
- Status output prints per-repo progress.

**Acceptance:** Two repos configured, both audited on first refresh,
state file contains both entries.

### Phase 1.2 — TUI dashboard

- `interactive_monitor` opens a raw-mode terminal session.
- Renders repo rows with sha + chip.
- Arrow nav, expand/collapse, mark viewed, refresh, quit.
- Refresh blocks with a status bar; updates state and rerenders on
  completion.

**Acceptance:** Live interaction works against the real ollama
backend on a configured repo. `[updated]` appears after a new commit
lands and disappears after `[space]`.

### Phase 1.3 — tests + docs + version bump

- `test_monitor_cycle.py` covering first encounter, no-change skip,
  new-commit refresh, viewed-mark semantics.
- README "Monitor mode" section.
- `__version__` → `0.2.0`.
- `pwnguard.yaml` shipped example gains a commented-out `monitor:`
  block so new users see the schema.

**Acceptance:** Full suite green. Pre-commit hook gates the v0.2.0
release commit. `--self-test` from inside the repo passes.

## Risks deliberately accepted

- **Concurrent runs corrupt state.** Documented as "not supported in
  v0.2.0". User said this is fine since the state file is a cache.
- **A lost commit between refreshes.** If 5 commits land and we only
  audit the latest, the 4 in-between are unseen. Acceptable; can be
  extended later.
- **Slow refresh blocks the TUI.** No background poller yet. The user
  asked for synchronous behaviour first.
- **No notifications on findings.** Stdout / TUI only; no Slack /
  email integration. Out of scope.
- **No CVE enrichment.** Scoped out — would need OSV dependency-file
  matching to be useful, which is a separate feature.

## Out of scope for v0.2.0

- Background daemon / scheduled poller
- Multiple branches per repo entry (use multiple entries instead)
- Range / N-commit auditing (cap=1 for now)
- Per-repo backend or threshold overrides
- Notification outputs (Slack, email)
- CVE enrichment
- Self-hosted GitLab beyond what the existing `_fetch_gitlab_*`
  helpers already cover (any host with `/-/` URL shape)

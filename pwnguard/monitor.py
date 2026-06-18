"""Monitor mode: state file, refresh cycle, and the dashboard TUI.

The state file (``.pwnguard-monitor.json`` in the cwd by default)
caches each watched repo's last-audited SHA and the resolved
findings, so reopening the TUI doesn't re-query the LLM for commits
already seen. ``last_viewed_sha`` is the user's acknowledgement;
commits newer than it render a ``●`` dot and feed the row's ``N new``
chip.
"""

import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from pwnguard import runtime, ui
from pwnguard.anchors import resolve_anchors
from pwnguard.backends import dispatch_backend
from pwnguard.constants import (
    MONITOR_STATE_FILENAME,
    MONITOR_STATE_VERSION,
    SEVERITY_ORDER,
)
from pwnguard.diff import (
    _truncate_diff,
    estimate_tokens,
    filter_diff,
    parse_diff_files,
    parse_diff_lines,
)
from pwnguard.fetchers import (
    _build_commit_url,
    _format_relative_time,
    fetch_from_url,
    list_commit_range_from_url,
    list_commits_from_url,
)
from pwnguard.models import AuditResult, Finding
from pwnguard.parser import parse_response
from pwnguard.prompts import build_system_prompt
from pwnguard.render import SEVERITY_LETTER, _print_legend, _truncate_visible
from pwnguard.report import (
    _default_findings_export_path,
    export_monitor_findings_markdown,
)
from pwnguard.scan import _run_scan_chunked
from pwnguard.security import _sanitize
from pwnguard.tui import (
    block_rows,
    capture,
    compute_visible_window,
    emit_tui_frame,
    lines_rows,
    render_tui_finding_row,
)


# ---------------------------------------------------------------------------
# State file
# ---------------------------------------------------------------------------

def _repo_key(url: str, branch: str) -> str:
    """Canonical state-file key for a (repo url, branch) pair.

    Two monitored entries that differ only by branch must not collide,
    hence the explicit ``@<branch>`` suffix instead of using the URL
    alone.
    """
    return f"{url.rstrip('/')}@{branch}"


def _load_monitor_state(path: str) -> dict:
    """Read the monitor cache file, or return an empty skeleton.

    Missing file is normal (first run). Malformed file is treated the
    same way: warn on stderr, return a fresh skeleton, let the next
    save overwrite it. Skipping a corrupt cache is preferable to
    crashing the TUI; the worst case is we re-audit one commit.
    """
    skeleton = {"version": MONITOR_STATE_VERSION, "repos": {}}
    if not os.path.exists(path):
        return skeleton
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(
            ui.dim(
                f"PwnGuard: monitor state at {path} is unreadable ({e}); "
                f"starting fresh."
            ),
            file=sys.stderr,
        )
        return skeleton
    if not isinstance(data, dict) or "repos" not in data:
        return skeleton
    # Upgrade an older flat-findings file to the per-commit shape before
    # anything downstream touches it.
    data = _migrate_state_v1_to_v2(data)
    # Belt-and-braces sanitisation: model output was sanitized at parse
    # time, but the file could have been tampered with offline. Re-run
    # the same scrub on every string we hand to the renderer.
    return _sanitize_loaded_state(data)


def _migrate_state_v1_to_v2(state: dict) -> dict:
    """In-place upgrade of a v1 monitor cache to the v2 shape.

    v1 stored a single flat ``findings`` list + ``diff_lines`` per repo,
    keyed implicitly off ``last_audited_sha``. v2 nests them under a
    SHA-keyed ``commits`` map so the dashboard can show every audited
    commit, not just the latest. An already-audited repo becomes a
    single-commit cache; a placeholder (never audited) just gains empty
    ``commits`` / ``order``. Idempotent - entries already carrying
    ``commits`` are left untouched, so re-loading a v2 file is a no-op.
    """
    repos = state.get("repos")
    if not isinstance(repos, dict):
        return state
    for entry in repos.values():
        if not isinstance(entry, dict) or "commits" in entry:
            continue
        sha = entry.get("last_audited_sha")
        old_findings = entry.pop("findings", None) or []
        old_diff = entry.pop("diff_lines", None) or {}
        old_date = entry.pop("last_audited_commit_date", None)
        commits: dict = {}
        order: list = []
        if sha:
            commits[sha] = {
                "sha": sha,
                "date": old_date,
                "audited_at": entry.get("audited_at"),
                "findings": old_findings,
                "diff_lines": old_diff,
            }
            order = [sha]
        entry["commits"] = commits
        entry["order"] = order
        entry["head_sha"] = sha
    state["version"] = MONITOR_STATE_VERSION
    return state


def _sanitize_loaded_state(state: dict) -> dict:
    """Re-sanitise every model-supplied string in a freshly loaded state.

    Walks the per-commit cache: each ``commits[sha]`` record carries its
    own findings + diff_lines, both of which could have been tampered
    with offline.
    """
    repos = state.get("repos", {})
    if not isinstance(repos, dict):
        state["repos"] = {}
        return state
    for entry in repos.values():
        if not isinstance(entry, dict):
            continue
        # The repo header renders these SHAs raw via _format_short_sha,
        # so scrub them too - a tampered file could smuggle an ANSI
        # escape through a forged pointer.
        for sha_field in ("last_audited_sha", "last_viewed_sha", "head_sha"):
            v = entry.get(sha_field)
            if isinstance(v, str):
                entry[sha_field] = _sanitize(v)
        commits = entry.get("commits")
        if not isinstance(commits, dict):
            continue
        for rec in commits.values():
            if not isinstance(rec, dict):
                continue
            # The commit row renders rec["sha"] raw (short form), so it
            # gets the same scrub as the model-supplied finding fields.
            if isinstance(rec.get("sha"), str):
                rec["sha"] = _sanitize(rec["sha"])
            for f in rec.get("findings") or []:
                if not isinstance(f, dict):
                    continue
                for k in ("title", "file", "description", "recommendation",
                          "cwe", "fix_example", "hunk_context", "anchor"):
                    v = f.get(k)
                    if isinstance(v, str):
                        f[k] = _sanitize(v)
            # Cached diff content is straight from the upstream platform,
            # not from the model - so it's already "untrusted user data"
            # by the same logic as a live --review run. Scrub it the same
            # way before it reaches the renderer.
            cached_diff = rec.get("diff_lines")
            if isinstance(cached_diff, dict):
                for lines in cached_diff.values():
                    if not isinstance(lines, dict):
                        continue
                    for ln_key, content in list(lines.items()):
                        if isinstance(content, str):
                            lines[ln_key] = _sanitize(content)
    return state


def _save_monitor_state(state: dict, path: str) -> None:
    """Write the monitor cache file with mode 0600.

    chmod is best-effort: on Windows the call is a no-op, on Unix it
    locks the file to the owner so a multi-user host doesn't leak
    repo URLs / cached findings to other accounts.
    """
    state["version"] = MONITOR_STATE_VERSION
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    if os.name != "nt":
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
    os.replace(tmp_path, path)


def _monitor_state_path(config: dict) -> str:
    """Resolve the monitor state file path from config or default to cwd.

    Default puts state in the current working directory so two parallel
    runs from different directories never share state. Users wanting a
    per-user cache can set ``monitor.state_file`` to an absolute path.
    """
    monitor_cfg = config.get("monitor", {}) or {}
    custom = monitor_cfg.get("state_file")
    if custom:
        return os.path.expanduser(custom)
    return os.path.join(os.getcwd(), MONITOR_STATE_FILENAME)


# ---------------------------------------------------------------------------
# Diff-line cache serialisation
# ---------------------------------------------------------------------------

def _serialize_diff_lines(diff_lines: dict) -> dict:
    """Convert ``parse_diff_lines`` output to a JSON-safe shape.

    JSON dict keys must be strings, but ``parse_diff_lines`` uses int
    line numbers. We stringify on the way out and parse back on load.
    """
    out: dict = {}
    for fname, lines in (diff_lines or {}).items():
        if not isinstance(lines, dict):
            continue
        out[fname] = {str(ln): content for ln, content in lines.items()}
    return out


def _deserialize_diff_lines(serialized: dict) -> dict:
    """Reverse of ``_serialize_diff_lines``: turn string-keyed maps back
    into int-keyed ones the renderer expects. Silently drops malformed
    rows so a tampered cache can't crash the TUI.
    """
    out: dict = {}
    if not isinstance(serialized, dict):
        return out
    for fname, lines in serialized.items():
        if not isinstance(lines, dict):
            continue
        sub: dict = {}
        for ln_str, content in lines.items():
            try:
                ln = int(ln_str)
            except (TypeError, ValueError):
                continue
            sub[ln] = content if isinstance(content, str) else ""
        out[fname] = sub
    return out


def _make_commit_record(
    sha: str,
    date: Optional[str],
    result: AuditResult,
    diff_lines: dict,
) -> dict:
    """Assemble the per-commit cache record stored under ``commits[sha]``.

    Findings are serialised with ``asdict`` and diff lines through
    ``_serialize_diff_lines`` so the whole record is JSON-safe.
    """
    return {
        "sha": sha,
        "date": date,
        "audited_at": datetime.now(timezone.utc).isoformat(),
        "findings": [asdict(f) for f in result.findings],
        "diff_lines": _serialize_diff_lines(diff_lines),
    }


def _repo_all_findings(entry: dict) -> list:
    """Flatten findings across all of a repo's cached commits, newest
    commit first. Backs the repo-row severity breakdown so a repo's
    header reflects every audited commit, not just the latest."""
    out: list = []
    commits = entry.get("commits") or {}
    for sha in entry.get("order") or []:
        rec = commits.get(sha) or {}
        out.extend(rec.get("findings") or [])
    return out


# ---------------------------------------------------------------------------
# Refresh cycle
# ---------------------------------------------------------------------------

def _audit_commit_for_monitor(
    repo_url: str,
    sha: str,
    config: dict,
    backend: str,
):
    """Run the audit pipeline against one commit on a watched repo.

    Slimmer than ``run_scan``: the diff source is always a single
    commit URL, no CLI args, no spinner (the caller manages user
    feedback). Auto-switches to chunked scanning when the prompt
    would exceed the active backend's context window so big commits
    don't get silently truncated by the LLM. Returns
    ``(AuditResult, diff_lines)`` - the diff_lines mapping is cached
    in monitor state so the TUI can render the ±3 code-preview
    window for each finding without re-fetching.

    Failure-mode visibility: every audit run prints a one-line
    diagnostic to stderr when parsing fails or when findings get
    dropped because the model emitted unknown anchors. Without this
    the dashboard would just show "clean" for any commit whose
    prompt overflowed; the user would have no signal that the model
    in fact found something the host couldn't keep.
    """
    # TODO(normalize): the overflow check + dispatch/parse/resolve below
    # duplicate run_scan() (scan.py). Extract shared should_chunk() +
    # audit_single_diff() helpers - deferred, see
    # memory/project_monitor_audit_core_refactor.md.
    commit_url = _build_commit_url(repo_url, sha)
    raw_diff = fetch_from_url(commit_url)
    filtered = filter_diff(raw_diff, config, apply_truncation=False)
    if not filtered.strip():
        return AuditResult(), {}

    # Build diff_lines from the pre-truncation filtered diff. We cache
    # this alongside findings so the monitor TUI's expanded finding
    # cards render the same code window --review shows. parse_diff_lines
    # only stores added lines (not context), matching --review's
    # behaviour.
    diff_lines = parse_diff_lines(filtered)

    # Auto-chunk path: Ollama silently truncates prompts that exceed
    # num_ctx, which produces ghost findings whose anchors don't map
    # to our wrap_diff table. Mirror the same overflow check
    # ``run_scan`` does for the local backends and route through
    # _run_scan_chunked so each file is scanned within budget.
    overflow = False
    if backend in ("ollama", "openai-compat"):
        preview_prompt = build_system_prompt(
            include_preview_fields=runtime.show_code_preview,
        )
        prompt_tokens = (
            estimate_tokens(preview_prompt) + estimate_tokens(filtered)
        )
        backend_cfg = config.get(
            "ollama" if backend == "ollama" else "openai", {},
        )
        num_ctx = backend_cfg.get("num_ctx", 4096) if backend == "ollama" else None
        num_predict = backend_cfg.get("num_predict", 2048)
        if num_ctx is not None:
            budget = prompt_tokens + num_predict
            if budget > num_ctx:
                overflow = True

    if overflow:
        # ``_run_scan_chunked`` takes an ``args`` parameter it doesn't
        # actually read; pass a sentinel so the call shape stays
        # identical to run_scan's invocation.
        class _Args:
            pass
        result, _elapsed = _run_scan_chunked(_Args(), config, backend, filtered)
        if result.error:
            print(
                ui.dim(
                    f"PwnGuard Monitor: parse error during chunked audit: "
                    f"{result.error.splitlines()[0]}"
                ),
                file=sys.stderr,
            )
        files = parse_diff_files(filtered)
        result.files_scanned = len(files)
        return result, diff_lines

    filtered = _truncate_diff(filtered, config.get("max_diff_lines", 500))
    response, anchor_table = dispatch_backend(backend, filtered, config)
    result = parse_response(response)
    if result.error:
        print(
            ui.dim(
                f"PwnGuard Monitor: parse error: "
                f"{result.error.splitlines()[0]}"
            ),
            file=sys.stderr,
        )
    dropped = resolve_anchors(result, anchor_table)
    if dropped:
        print(
            ui.dim(
                f"PwnGuard Monitor: dropped {dropped} finding(s) with "
                f"unrecognised anchor token (model fabricated, or "
                f"prompt was truncated past num_ctx)"
            ),
            file=sys.stderr,
        )
    files = parse_diff_files(filtered)
    result.files_scanned = len(files)
    return result, diff_lines


# Upper bound on commits pulled per repo per refresh, independent of
# the per-refresh audit cap. Bounds the compare-API response so a repo
# thousands of commits ahead can't blow up memory; the audit cap then
# slices the oldest chunk out of this window.
_RANGE_FETCH_CEILING = 100


def _first_commit(commits: list) -> Optional[tuple]:
    """Normalise the head of a ``list_commits_from_url`` result to a
    ``(sha, date_or_None)`` tuple, tolerating the legacy bare-SHA shape.
    Returns None for an empty list."""
    if not commits:
        return None
    first = commits[0]
    if isinstance(first, tuple) and len(first) == 2:
        return first
    return (first, None)


def _record_audited_commit(
    entry: dict,
    sha: str,
    date: Optional[str],
    result: AuditResult,
    diff_lines: dict,
) -> None:
    """Store one audited commit in the repo entry and advance the
    pointer. ``order`` stays newest-first; calling this in oldest ->
    newest order leaves the newest commit at the front."""
    rec = _make_commit_record(sha, date, result, diff_lines)
    entry.setdefault("commits", {})[sha] = rec
    order = entry.setdefault("order", [])
    if sha in order:
        order.remove(sha)
    order.insert(0, sha)
    entry["last_audited_sha"] = sha
    entry["audited_at"] = rec["audited_at"]


def _prune_commits(entry: dict, keep: int) -> None:
    """Drop the oldest cached commits beyond ``keep`` to bound state-file
    growth. ``order`` is newest-first, so the tail is the oldest."""
    order = entry.get("order") or []
    if keep < 1 or len(order) <= keep:
        return
    drop = order[keep:]
    entry["order"] = order[:keep]
    commits = entry.get("commits") or {}
    for s in drop:
        commits.pop(s, None)


def _run_monitor_refresh(
    config: dict,
    state: dict,
    backend: str,
    progress=None,
) -> dict:
    """Iterate the configured monitor repos, audit every new commit
    between each repo's ``last_audited_sha`` and HEAD.

    First encounter audits HEAD only (so the user sees current state
    immediately). Afterwards the compare endpoint yields the commits
    that landed since ``last_audited_sha``; we dedup by SHA and audit
    them oldest -> newest so the pointer advances contiguously. With
    ``review_everything_at_once`` on (default) one refresh keeps
    draining windows until the branch is fully caught up; with it off
    we audit a single ``max_commits_per_refresh`` batch and surface the
    rest as backlog for the next [r] press.

    ``progress`` is an optional callback ``(idx, total, name, msg)``.
    Returns a dict keyed by repo state-key mapping to a status dict
    ``{"status", "audited", "backlog", "error"}`` where ``status`` is
    one of ``first-seen`` / ``unchanged`` / ``audited`` / ``diverged``
    (force-push fallback) / ``error``. One repo failing never aborts
    the whole refresh.
    """
    monitor_cfg = config.get("monitor", {}) or {}
    repos = monitor_cfg.get("repos", []) or []
    cap = max(1, int(monitor_cfg.get("max_commits_per_refresh", 10) or 10))
    keep = max(1, int(monitor_cfg.get("keep_commits", 30) or 30))
    ceiling = max(cap, _RANGE_FETCH_CEILING)
    summary: dict = {}
    state.setdefault("repos", {})

    def _err(msg, backlog=0):
        return {"status": "error", "error": msg, "audited": 0, "backlog": backlog}

    for idx, repo_cfg in enumerate(repos):
        name = repo_cfg.get("name") or repo_cfg.get("url", "?")
        url = repo_cfg.get("url")
        branch = repo_cfg.get("branch")
        if not url or not branch:
            summary[name] = _err("monitor entry missing 'url' or 'branch'")
            continue

        key = _repo_key(url, branch)
        entry = state["repos"].get(key) or {
            "name": name,
            "url": url,
            "branch": branch,
            "last_audited_sha": None,
            "last_viewed_sha": None,
            "head_sha": None,
            "audited_at": None,
            "commits": {},
            "order": [],
        }
        # Keep the name in sync with the latest config (the user may
        # have renamed an entry between runs).
        entry["name"] = name
        entry["url"] = url
        entry["branch"] = branch
        entry.setdefault("commits", {})
        entry.setdefault("order", [])
        # Reset per-refresh status each cycle; only the paths below set
        # them. last_error is cleared here so a repo that recovers stops
        # showing the stale error chip.
        entry["pending_count"] = 0
        entry["last_error"] = None
        state["repos"][key] = entry

        # Stamp an error on the entry (so the row can show it) as well as
        # the ephemeral summary (so the status line can count it).
        def _fail(msg, backlog=0, _entry=entry, _key=key):
            _entry["last_error"] = msg
            summary[_key] = _err(msg, backlog)

        base = entry.get("last_audited_sha")

        # ---- First encounter: audit HEAD only, set the baseline. ----
        if base is None:
            if progress:
                progress(idx + 1, len(repos), name, "fetching commits...")
            try:
                head = _first_commit(list_commits_from_url(url, branch, limit=1))
            except SystemExit as e:
                _fail(str(e.code))
                continue
            if head is None:
                _fail("no commits returned for branch")
                continue
            head_sha, head_date = head
            if progress:
                progress(idx + 1, len(repos), name, f"first audit {head_sha[:7]}...")
            try:
                result, diff_lines = _audit_commit_for_monitor(
                    url, head_sha, config, backend,
                )
            except SystemExit as e:
                _fail(str(e.code))
                continue
            _record_audited_commit(entry, head_sha, head_date, result, diff_lines)
            entry["head_sha"] = head_sha
            # First encounter is "you're looking at it now" - viewed =
            # audited so the [updated] chip stays quiet until the NEXT
            # commit lands.
            entry["last_viewed_sha"] = head_sha
            _prune_commits(entry, keep)
            summary[key] = {"status": "first-seen", "audited": 1, "backlog": 0}
            continue

        # ---- Subsequent: walk the commit range base..HEAD. ----
        if progress:
            progress(idx + 1, len(repos), name, "fetching commit range...")
        try:
            status, range_commits = list_commit_range_from_url(
                url, branch, base, limit=ceiling,
            )
        except SystemExit as e:
            _fail(str(e.code))
            continue

        if status == "identical":
            entry["head_sha"] = base
            summary[key] = {"status": "unchanged", "audited": 0, "backlog": 0}
            continue

        if status == "diverged":
            # Force-push / rebase orphaned base_sha. The range isn't a
            # clean forward set, so fall back to auditing HEAD only.
            try:
                head = _first_commit(list_commits_from_url(url, branch, limit=1))
            except SystemExit as e:
                _fail(str(e.code))
                continue
            if head is None:
                _fail("no commits returned for branch")
                continue
            head_sha, head_date = head
            entry["head_sha"] = head_sha
            if head_sha in (entry.get("commits") or {}):
                # Already audited this SHA under its old reachability.
                entry["last_audited_sha"] = head_sha
                summary[key] = {"status": "unchanged", "audited": 0, "backlog": 0}
                continue
            if progress:
                progress(idx + 1, len(repos), name,
                         f"auditing {head_sha[:7]} (history rewritten)...")
            try:
                result, diff_lines = _audit_commit_for_monitor(
                    url, head_sha, config, backend,
                )
            except SystemExit as e:
                _fail(str(e.code))
                continue
            _record_audited_commit(entry, head_sha, head_date, result, diff_lines)
            _prune_commits(entry, keep)
            summary[key] = {"status": "diverged", "audited": 1, "backlog": 0}
            continue

        # ---- status == "ok": forward range, oldest -> newest. ----
        # With review_everything_at_once on, loop until caught up to HEAD
        # (cap is just the progress batch size); off audits one capped
        # batch and reports the rest as backlog.
        catch_up = bool(monitor_cfg.get("review_everything_at_once", True))
        total_audited = 0
        err = None
        # Carried out of the loop to size the backlog chip from the last
        # window we touched.
        window_fresh = 0
        window_audited = 0
        while True:
            if range_commits:
                newest_in_window = range_commits[-1][0]
                if len(range_commits) >= ceiling:
                    # The window may be truncated at the ceiling, so its
                    # last element isn't necessarily the branch HEAD.
                    # Resolve the real HEAD (one cheap call) so the
                    # "+N more" backlog chip doesn't understate how far
                    # behind we are. Fall back to the window's newest if
                    # that lookup fails.
                    try:
                        head = _first_commit(
                            list_commits_from_url(url, branch, limit=1),
                        )
                    except SystemExit:
                        head = None
                    entry["head_sha"] = head[0] if head else newest_in_window
                else:
                    entry["head_sha"] = newest_in_window
            cached = entry.get("commits") or {}
            fresh = [(s, d) for (s, d) in range_commits if s not in cached]
            if not fresh:
                break

            to_audit = fresh if catch_up else fresh[:cap]
            window_fresh = len(fresh)
            window_audited = 0
            for j, (sha, date) in enumerate(to_audit):
                if progress:
                    progress(idx + 1, len(repos), name,
                             f"auditing {sha[:7]} ({total_audited + j + 1} new)...")
                try:
                    result, diff_lines = _audit_commit_for_monitor(
                        url, sha, config, backend,
                    )
                except SystemExit as e:
                    # Stop here so last_audited_sha stays contiguous -
                    # skipping a failed commit would leave a permanent
                    # gap in the audited history.
                    err = str(e.code)
                    break
                _record_audited_commit(entry, sha, date, result, diff_lines)
                window_audited += 1
                total_audited += 1
            _prune_commits(entry, keep)
            if err or not catch_up:
                break
            # Window smaller than the ceiling means it reached HEAD -
            # nothing left to fetch.
            if len(range_commits) < ceiling:
                break
            # More commits beyond this window: re-compare from the
            # advanced pointer and keep draining.
            base = entry["last_audited_sha"]
            try:
                status, range_commits = list_commit_range_from_url(
                    url, branch, base, limit=ceiling,
                )
            except SystemExit as e:
                err = str(e.code)
                break
            # "identical" = caught up; a mid-drain "diverged" (force-push
            # landed while we were auditing) stops here and the next
            # refresh's diverged fallback handles it.
            if status != "ok":
                break

        # What we didn't reach in the last window (over the cap, or after
        # an aborted batch) is surfaced as backlog; a clean catch-up -> 0.
        remaining = window_fresh - window_audited
        entry["pending_count"] = remaining

        if total_audited == 0:
            if err:
                _fail(err, remaining)
            else:
                # Range non-empty but every commit already cached (dedup),
                # e.g. an overlapping GitLab range: caught up, not an error.
                summary[key] = {
                    "status": "unchanged", "audited": 0, "backlog": remaining,
                }
            continue
        summary[key] = {
            "status": "audited",
            "audited": total_audited,
            "backlog": remaining,
            "error": err,
        }

    return summary


def _summarise_refresh(summary: dict) -> str:
    """One-line refresh summary for the status bar, counting commits
    (not repos) so a multi-commit drain reads honestly, and surfacing
    any backlog the per-refresh cap deferred."""
    def _stat(v):
        return v if isinstance(v, dict) else {}
    audited_commits = sum(_stat(v).get("audited", 0) for v in summary.values())
    unchanged = sum(1 for v in summary.values()
                    if _stat(v).get("status") == "unchanged")
    errors = sum(1 for v in summary.values()
                 if _stat(v).get("status") == "error")
    backlog = sum(_stat(v).get("backlog", 0) for v in summary.values())

    parts = []
    if audited_commits:
        parts.append(
            f"{audited_commits} commit{'s' if audited_commits != 1 else ''} audited"
        )
    if unchanged:
        parts.append(f"{unchanged} unchanged")
    if errors:
        parts.append(f"{errors} error{'s' if errors != 1 else ''}")
    line = "refresh: " + ", ".join(parts) if parts else "refresh: nothing to do"
    if errors:
        # The per-repo "error" chip + the message under an expanded repo
        # carry the detail; point the user there instead of dead-ending.
        line += "  (expand a repo marked 'error' to see why)"
    if backlog:
        line += f"  ({backlog} pending — press [r] again)"
    return line


# ---------------------------------------------------------------------------
# Dashboard helpers
# ---------------------------------------------------------------------------

def _format_short_sha(sha: Optional[str]) -> str:
    if not sha:
        return "—"
    return sha[:7]


def _finding_from_state_dict(d: dict) -> Finding:
    """Reconstruct a Finding from its asdict() form stored in state.

    Filters unknown keys so older state files with extra fields don't
    crash the constructor.
    """
    fields = set(Finding.__dataclass_fields__)
    cleaned = {k: v for k, v in d.items() if k in fields}
    return Finding(**cleaned)


def _severity_breakdown(findings: list) -> str:
    """Compact ``N S`` summary across the severity ladder, joined with
    ``·``. Each ``N S`` cell is coloured by severity so a CRITICAL
    cluster reads red, an INFO cluster reads dim. Empty severities are
    skipped (no "0 L" noise)."""
    counts: dict = {}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev not in counts:
            continue
        letter = SEVERITY_LETTER.get(sev, "?")
        parts.append(ui.severity_color(f"{counts[sev]} {letter}", sev))
    return "  " + "  ·  ".join(parts) if parts else ""


def _new_commit_shas(entry: dict) -> set:
    """SHAs of audited commits newer than ``last_viewed_sha`` (the user's
    acknowledgement point). ``order`` is newest-first; a viewed pointer
    that is None or pruned means everything cached counts as new."""
    order = entry.get("order") or []
    if not order:
        return set()
    viewed = entry.get("last_viewed_sha")
    if viewed is None or viewed not in order:
        return set(order)
    return set(order[: order.index(viewed)])


def _mark_commit_viewed(entry: dict, target_sha: str) -> bool:
    """Advance ``last_viewed_sha`` to ``target_sha`` as a forward
    high-water mark (clears its ``●`` dot and all older ones, leaving
    newer commits marked new). ``order`` is newest-first. Only moves the
    pointer forward, so marking an older commit is a no-op. Returns True
    if it moved."""
    order = entry.get("order") or []
    if target_sha not in order:
        return False
    viewed = entry.get("last_viewed_sha")
    cur_idx = order.index(viewed) if viewed in order else len(order)
    if order.index(target_sha) < cur_idx:
        entry["last_viewed_sha"] = target_sha
        return True
    return False


def _render_monitor_row(
    entry: dict,
    *,
    is_expanded: bool,
    is_current: bool,
    width: int,
    show_all: bool = False,
    new_shas: Optional[set] = None,
) -> None:
    """Print one repo header row. Findings, if any, are rendered as
    separate items beneath (see _render_monitor_finding_row); this
    function only handles the header line so the dashboard cursor
    can target the repo and its findings independently.
    """
    name = entry.get("name") or entry.get("url") or "?"
    sha = entry.get("last_audited_sha")
    order = entry.get("order") or []
    commits = entry.get("commits") or {}
    findings = _repo_all_findings(entry)
    audited = sha is not None
    if new_shas is None:
        new_shas = _new_commit_shas(entry)
    new_count = len(new_shas)
    # Commits seen on the branch but not yet audited (single-batch
    # deferral, or a refresh that errored before draining them).
    pending = int(entry.get("pending_count") or 0)
    error = entry.get("last_error")

    cursor_mark = ui.bold(ui.cyan("❯")) if is_current else " "
    arrow = "▼" if is_expanded else "▶"
    name_styled = ui.bold(name) if is_current else name
    if not audited:
        count_text = ui.dim("  awaiting first refresh")
    elif findings:
        # Severity breakdown aggregated across every audited commit,
        # e.g. "1 C  ·  3 H  ·  12 INFO", inline after the name.
        count_text = _severity_breakdown(findings)
    else:
        count_text = ui.dim("  clean")
    left = f" {cursor_mark} {arrow}  {name_styled}{count_text}"

    # Right side: relative age, short SHA, then one colour-coded status
    # chip per concern.
    newest_rec = commits.get(order[0]) if order else None
    commit_date = newest_rec.get("date") if newest_rec else None
    short = _format_short_sha(sha)
    relative = _format_relative_time(commit_date)
    right_parts = []
    if relative:
        right_parts.append(ui.dim(relative))
    if audited:
        right_parts.append(ui.dim(short))
    if new_count:
        right_parts.append(ui.cyan(f"{new_count} new"))
    # Only for genuine unaudited backlog. An errored repo shows the error
    # chip instead (its "pending" is just a symptom of the failure).
    if pending and not error:
        right_parts.append(ui.yellow(f"{pending} pending"))
    if error:
        right_parts.append(ui.red("error"))
    right = "  ".join(right_parts)

    # Reserve the right side and truncate the name if needed. Budget
    # width-1, never the last column: emit_tui_frame's per-line \x1b[K
    # would clip a glyph left in the final column.
    usable = max(1, width - 1)
    right_w = ui.visible_len(right)
    max_left = max(1, usable - right_w - 2)
    if ui.visible_len(left) > max_left:
        left = _truncate_visible(left, max_left)
    pad = max(2, usable - ui.visible_len(left) - right_w)
    print(left + (" " * pad) + right)

    if not is_expanded:
        return
    # The error message itself is only reachable by expanding the repo,
    # so the dashboard can answer "why did this error?" without a log.
    if error:
        msg = " ".join(str(error).split())
        print(ui.red("        error: ") + ui.dim(
            _truncate_visible(msg, max(10, width - 16)),
        ))
    if not order:
        if not error:
            print(ui.dim("        not yet audited — press [r] to refresh"))
        return
    # Findings-first mode hides clean commits; name how many so the count
    # isn't silent (new-ness is already shown by the ● dots and the chip).
    if not show_all:
        clean = [s for s in order if not (commits.get(s) or {}).get("findings")]
        if clean:
            print(ui.dim(
                f"        {len(clean)} clean hidden  "
                f"(press [f] to show all commits)"
            ))


def _render_monitor_commit_row(
    rec: dict,
    *,
    is_expanded: bool,
    is_current: bool,
    width: int,
    is_new: bool = False,
) -> None:
    """Print one commit row: short SHA, its own severity breakdown, and
    relative age. A ``●`` marks a commit newer than the repo's last-viewed
    point. Findings render as separate rows when the commit is expanded."""
    sha = rec.get("sha")
    findings = rec.get("findings") or []

    cursor_mark = ui.bold(ui.cyan("❯")) if is_current else " "
    arrow = "▼" if is_expanded else "▶"
    # New/unreviewed dot sits between the arrow and the SHA so the eye
    # can scan the column for what's landed since the last [v].
    new_dot = ui.cyan("●") if is_new else " "
    short = _format_short_sha(sha)
    short_styled = ui.bold(short) if is_current else ui.cyan(short)
    count_text = _severity_breakdown(findings) if findings else ui.dim("  clean")
    left = f"     {cursor_mark} {arrow} {new_dot} {short_styled}{count_text}"

    relative = _format_relative_time(rec.get("date"))
    right = ui.dim(relative) if relative else ""
    # Budget width-1 (never the last column) - see _render_monitor_row.
    usable = max(1, width - 1)
    pad = max(2, usable - ui.visible_len(left) - ui.visible_len(right))
    print(left + (" " * pad) + right)

    if is_expanded and not findings:
        print(ui.dim("            no findings on this commit"))


def _render_monitor_finding_row(
    f: Finding,
    *,
    is_expanded: bool,
    is_current: bool,
    width: int,
    diff_lines: Optional[dict] = None,
    is_marked: bool = False,
) -> None:
    """Print a finding row inside the monitor dashboard.

    Thin wrapper around the shared TUI row helper so callers within
    monitor.py can keep their original kwarg-only call sites.
    """
    render_tui_finding_row(
        f,
        is_marked=is_marked,
        is_expanded=is_expanded,
        is_current=is_current,
        width=width,
        diff_lines=diff_lines,
    )


def _sorted_finding_indices(findings: list) -> list:
    """Indices of ``findings`` ordered by severity (CRITICAL -> ... ->
    INFO) with a stable secondary order by emission index. Matches
    --review so a HIGH SQL-injection finding never sits buried under a
    pile of INFO rows."""
    return sorted(
        range(len(findings)),
        key=lambda i: (
            -SEVERITY_ORDER.get(
                (findings[i].get("severity") or "INFO").upper(), 0,
            ),
            i,
        ),
    )


def _build_monitor_items(
    state: dict,
    keys: list,
    repo_expanded: dict,
    commit_expanded: Optional[dict] = None,
    repo_show_all: Optional[dict] = None,
) -> list:
    """Flatten the dashboard into an item list the cursor can index.

    Each item is ``(kind, repo_key, ref)``:
      - ``"repo"``    -> ref is None
      - ``"commit"``  -> ref is the commit SHA (shown when the repo is
        expanded)
      - ``"finding"`` -> ref is ``(sha, finding_idx)`` (shown when that
        commit is expanded)

    Collapsing a repo removes its commits (and their findings) from the
    cursor-reachable set; collapsing a commit removes just its findings.
    Findings within a commit are severity-ordered.
    """
    commit_expanded = commit_expanded or {}
    repo_show_all = repo_show_all or {}
    items = []
    for key in keys:
        items.append(("repo", key, None))
        if not repo_expanded.get(key, False):
            continue
        entry = state.get("repos", {}).get(key) or {}
        commits = entry.get("commits") or {}
        # Findings-first by default: clean commits collapse into the
        # repo row's "N clean hidden" summary so a big catch-up reads as
        # the few commits that matter, not a wall. [f] reveals them all.
        show_all = repo_show_all.get(key, False)
        for sha in entry.get("order") or []:
            rec = commits.get(sha) or {}
            findings = rec.get("findings") or []
            if not show_all and not findings:
                continue
            items.append(("commit", key, sha))
            if not commit_expanded.get((key, sha), False):
                continue
            for i in _sorted_finding_indices(findings):
                items.append(("finding", key, (sha, i)))
    return items


def _render_monitor(
    state: dict,
    keys: list,
    items: list,
    cursor: int,
    repo_expanded: dict,
    commit_expanded: dict,
    finding_expanded: dict,
    finding_marked: dict,
    status_line: str,
    repo_show_all: Optional[dict] = None,
) -> None:
    """Full-screen redraw of the monitor dashboard.

    ``items`` is the flat (repo + commit + finding) list the cursor
    indexes into; ``keys`` is the repo subset used for the header count.
    Output is buffered and emitted by ``emit_tui_frame`` so the
    terminal repaints in one pass.
    """
    import contextlib
    import io
    width = ui.term_width()
    height = ui.term_height()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _render_monitor_into_buffer(
            state, keys, items, cursor,
            repo_expanded, commit_expanded, finding_expanded, finding_marked,
            status_line, width, height, repo_show_all or {},
        )
    emit_tui_frame(buf.getvalue())


def _render_monitor_into_buffer(
    state: dict,
    keys: list,
    items: list,
    cursor: int,
    repo_expanded: dict,
    commit_expanded: dict,
    finding_expanded: dict,
    finding_marked: dict,
    status_line: str,
    width: int,
    height: int,
    repo_show_all: Optional[dict] = None,
) -> None:
    """Inner render body. ``sys.stdout`` is redirected to the frame
    buffer by ``_render_monitor``; this function just emits lines."""
    repo_show_all = repo_show_all or {}
    n_repos = len(keys)

    header_lines = [
        ui.bold("PwnGuard Monitor") + ui.dim(
            f"  ·  {n_repos} repo{'s' if n_repos != 1 else ''}"
        ),
        ui.dim(
            "  up/down navigate   enter toggle   -/= collapse/expand all   "
            "space=strike   v=mark viewed   f=show all   e=export   "
            "r=refresh   q=quit"
        ),
    ]
    header_lines += capture(_print_legend)
    header_lines.append("")
    footer_lines = ["", ui.dim(f"  {status_line}")]

    if not items:
        for line in header_lines:
            print(line)
        print(ui.dim(
            "  No repos configured. Add a monitor.repos[] block to "
            "pwnguard.yaml."
        ))
        for line in footer_lines:
            print(line)
        return

    # Render each item into a buffer so we can measure for windowing.
    item_blocks = []
    for i, (kind, key, ref) in enumerate(items):
        entry = state.get("repos", {}).get(key) or {}
        commits = entry.get("commits") or {}
        new_shas = _new_commit_shas(entry)
        if kind == "repo":
            block = capture(
                _render_monitor_row,
                entry,
                is_expanded=repo_expanded.get(key, False),
                is_current=(i == cursor),
                width=width,
                show_all=repo_show_all.get(key, False),
                new_shas=new_shas,
            )
        elif kind == "commit":
            rec = commits.get(ref)
            if rec is None:
                block = [ui.dim("     (commit gone)")]
            else:
                block = capture(
                    _render_monitor_commit_row,
                    rec,
                    is_expanded=commit_expanded.get((key, ref), False),
                    is_current=(i == cursor),
                    width=width,
                    is_new=(ref in new_shas),
                )
        else:  # finding, ref == (sha, finding_idx)
            sha, idx = ref
            rec = commits.get(sha) or {}
            findings = rec.get("findings") or []
            if idx is None or idx >= len(findings):
                block = [ui.dim("            (finding gone)")]
            else:
                try:
                    f = _finding_from_state_dict(findings[idx])
                except (TypeError, KeyError):
                    block = [ui.dim("            (finding malformed)")]
                else:
                    diff_lines = _deserialize_diff_lines(
                        rec.get("diff_lines") or {}
                    )
                    block = capture(
                        _render_monitor_finding_row,
                        f,
                        is_expanded=finding_expanded.get((key, sha, idx), False),
                        is_current=(i == cursor),
                        is_marked=finding_marked.get((key, sha, idx), False),
                        width=width,
                        diff_lines=diff_lines,
                    )
        item_blocks.append(block)

    # Compute the available items region in actual terminal rows. A
    # header line wider than the terminal wraps onto multiple rows, and
    # the windowing math has to account for that to avoid the
    # navigation-induced flicker at the top of the alt-screen buffer.
    header_rows = lines_rows(header_lines, width)
    footer_rows = lines_rows(footer_lines, width)
    available = max(1, height - header_rows - footer_rows)

    item_heights = [block_rows(b, width) for b in item_blocks]
    visible_indices, hidden_above, hidden_below = compute_visible_window(
        item_heights, cursor, available,
    )

    for line in header_lines:
        print(line)
    if hidden_above:
        print(ui.dim(
            f"  ↑ {hidden_above} row{'s' if hidden_above != 1 else ''} above"
        ))
    for idx_v in visible_indices:
        for line in item_blocks[idx_v]:
            print(line)
    if hidden_below:
        print(ui.dim(
            f"  ↓ {hidden_below} row{'s' if hidden_below != 1 else ''} below"
        ))
    for line in footer_lines:
        print(line)


def _ensure_repo_entries(state: dict, config: dict) -> dict:
    """Pre-populate state with placeholder entries for every configured
    repo that doesn't already have one.

    Without this step, a freshly-opened TUI (state file missing or
    config just gained a new repo) renders ``?`` for every name and
    ``awaiting first refresh`` for every row would have nothing
    backing it. Placeholders carry the user's configured ``name`` /
    ``url`` / ``branch`` so the dashboard is meaningful even before
    the first ``[r]`` press. ``name`` is refreshed on every call so
    renaming an entry in yaml takes effect on the next launch.
    """
    monitor_cfg = config.get("monitor", {}) or {}
    cfg_repos = monitor_cfg.get("repos", []) or []
    repos = state.setdefault("repos", {})
    for r in cfg_repos:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        branch = r.get("branch")
        if not url or not branch:
            continue
        key = _repo_key(url, branch)
        name = r.get("name") or url
        entry = repos.get(key)
        if entry is None:
            repos[key] = {
                "name": name,
                "url": url,
                "branch": branch,
                "last_audited_sha": None,
                "last_viewed_sha": None,
                "head_sha": None,
                "audited_at": None,
                "commits": {},
                "order": [],
            }
        else:
            entry["name"] = name
            entry["url"] = url
            entry["branch"] = branch
            entry.setdefault("commits", {})
            entry.setdefault("order", [])
            entry.setdefault("head_sha", entry.get("last_audited_sha"))
    return state


def _ordered_monitor_keys(state: dict, config: dict) -> list:
    """Order repos by config order, then any orphaned state entries.

    Keeps the dashboard layout stable across runs: a repo listed third
    in pwnguard.yaml always renders third, even if its state entry was
    written months ago.
    """
    monitor_cfg = config.get("monitor", {}) or {}
    cfg_repos = monitor_cfg.get("repos", []) or []
    cfg_keys = [
        _repo_key(r["url"], r["branch"])
        for r in cfg_repos
        if isinstance(r, dict) and r.get("url") and r.get("branch")
    ]
    state_keys = list((state.get("repos") or {}).keys())
    orphans = [k for k in state_keys if k not in cfg_keys]
    return cfg_keys + orphans


def interactive_monitor(
    config: dict,
    backend: str,
    state_path: str,
) -> None:
    """Open the monitor TUI: dashboard of configured repos with cached
    findings, refreshable on demand.

    The tree has three levels: repo -> commit -> finding. Expanding a
    repo reveals its audited commits; expanding a commit reveals that
    commit's findings.

    Keys:
      up / down         navigate
      enter             toggle expand / collapse on the current row
      right             expand
      left              collapse
      -                 collapse everything (repos, commits, findings)
      =                 expand everything
      space             toggle strike-through on the current finding
                        (also collapses if it was expanded). On a repo
                        or commit row this is a no-op.
      v                 mark viewed up to the current row (repo -> all,
                        commit/finding -> that commit and older)
      f                 show all commits / findings-first for the repo
                        (clean commits are hidden by default)
      r                 refresh (audit every new commit since last scan)
      q, esc, Ctrl-C    save state and quit
    """
    if (not ui.CbreakTerminal.available
            or not sys.stdin.isatty()
            or not sys.stdout.isatty()):
        print(
            ui.dim("PwnGuard: monitor TUI unavailable (non-TTY or Windows)."),
            file=sys.stderr,
        )
        return

    monitor_cfg = config.get("monitor", {}) or {}
    cfg_repos = monitor_cfg.get("repos", []) or []
    if not cfg_repos:
        print(
            ui.red("Error:")
            + " no monitor.repos[] configured in pwnguard.yaml.",
            file=sys.stderr,
        )
        return

    state = _load_monitor_state(state_path)
    # Materialise an entry for every configured repo so the dashboard
    # renders the user's name + branch even on the very first launch,
    # before any refresh has populated last_audited_sha.
    _ensure_repo_entries(state, config)
    keys = _ordered_monitor_keys(state, config)
    # Three expansion dictionaries, one per tree level: repo controls
    # which commits are reachable, commit controls which findings are
    # reachable, finding controls one-liner vs full boxed card. Keyed by
    # stable identifiers so the state survives a refresh that adds or
    # reorders repos / commits / findings.
    repo_expanded: dict = {}
    commit_expanded: dict = {}
    finding_expanded: dict = {}
    finding_marked: dict = {}
    # Per-repo "show all commits" toggle ([f]). Off by default so clean
    # commits collapse into the repo summary; on reveals every commit.
    repo_show_all: dict = {}
    items = _build_monitor_items(
        state, keys, repo_expanded, commit_expanded, repo_show_all,
    )
    cursor = 0
    status_line = "loaded cached state — press [r] to refresh"

    def _refresh_items(prev_anchor=None):
        """Rebuild the items list and try to keep the cursor on the
        same logical row across expand / collapse / refresh.

        ``prev_anchor`` is the (kind, key, ref) tuple the cursor was on
        before the change. If that exact item still exists we land
        there; otherwise we walk up the tree (finding -> its commit ->
        its repo) to the nearest ancestor still on screen.
        """
        nonlocal items, cursor
        items = _build_monitor_items(
            state, keys, repo_expanded, commit_expanded, repo_show_all,
        )
        if not items:
            cursor = 0
            return
        if prev_anchor is not None:
            kind, key, ref = prev_anchor
            ancestors = []
            if kind == "finding" and isinstance(ref, tuple):
                ancestors.append(("commit", key, ref[0]))
            if kind in ("finding", "commit"):
                ancestors.append(("repo", key, None))
            for target in [prev_anchor, *ancestors]:
                for i, it in enumerate(items):
                    if it == target:
                        cursor = i
                        return
        cursor = min(cursor, len(items) - 1)

    _refresh_items()

    try:
        with ui.CbreakTerminal() as term:
            while True:
                _render_monitor(
                    state, keys, items, cursor,
                    repo_expanded, commit_expanded, finding_expanded,
                    finding_marked, status_line, repo_show_all,
                )
                try:
                    pressed = ui.read_key()
                except KeyboardInterrupt:
                    break

                if pressed in ("q", "esc"):
                    break
                if not items:
                    if pressed == "r":
                        pass  # fall through to refresh handling below
                    else:
                        continue

                current = items[cursor] if items else None

                if pressed == "up" and items:
                    cursor = (cursor - 1) % len(items)
                elif pressed == "down" and items:
                    cursor = (cursor + 1) % len(items)
                elif pressed in ("enter", "right", "left") and current:
                    kind, key, ref = current
                    if kind == "repo":
                        if pressed == "right":
                            new = True
                        elif pressed == "left":
                            new = False
                        else:
                            new = not repo_expanded.get(key, False)
                        repo_expanded[key] = new
                        _refresh_items(prev_anchor=current)
                    elif kind == "commit":
                        ekey = (key, ref)
                        if pressed == "right":
                            commit_expanded[ekey] = True
                        elif pressed == "left":
                            commit_expanded[ekey] = False
                        else:
                            commit_expanded[ekey] = (
                                not commit_expanded.get(ekey, False)
                            )
                        _refresh_items(prev_anchor=current)
                    else:  # finding, ref == (sha, idx)
                        sha, idx = ref
                        ekey = (key, sha, idx)
                        if pressed == "right":
                            finding_expanded[ekey] = True
                        elif pressed == "left":
                            finding_expanded[ekey] = False
                        else:
                            finding_expanded[ekey] = (
                                not finding_expanded.get(ekey, False)
                            )
                elif pressed == "space" and current:
                    kind, key, ref = current
                    if kind == "finding":
                        sha, idx = ref
                        ekey = (key, sha, idx)
                        if not finding_marked.get(ekey, False):
                            # Strike + collapse if the card was open.
                            finding_marked[ekey] = True
                            finding_expanded[ekey] = False
                        else:
                            finding_marked[ekey] = False
                elif pressed == "v" and current:
                    kind, key, ref = current
                    entry = state["repos"].get(key)
                    if entry and kind == "repo":
                        # Whole repo: acknowledge up to the newest audit.
                        entry["last_viewed_sha"] = entry.get("last_audited_sha")
                        status_line = (
                            f"marked '{entry.get('name', '?')}' viewed"
                        )
                    elif entry:
                        # Commit / finding: acknowledge up to that commit
                        # (and everything older). ref is the SHA on a
                        # commit row, (sha, idx) on a finding row.
                        sha = ref if kind == "commit" else ref[0]
                        _mark_commit_viewed(entry, sha)
                        status_line = f"marked {sha[:7]} viewed"
                elif pressed == "f" and current:
                    # Toggle showing every commit (incl. clean ones) for
                    # the current repo. Auto-expands it so the newly
                    # reachable commits render.
                    _, key, _ = current
                    show = not repo_show_all.get(key, False)
                    repo_show_all[key] = show
                    if show:
                        repo_expanded[key] = True
                    _refresh_items(prev_anchor=current)
                    status_line = (
                        "showing all commits" if show else "findings-first"
                    )
                elif pressed == "e":
                    # Export non-struck findings across every repo,
                    # grouped by repo (flattening all of a repo's
                    # commits under one heading), to a timestamped
                    # markdown file. Strike marks are the user's
                    # "resolved / ignore" signal so we drop them;
                    # nothing in persistent state changes.
                    grouped = []
                    total_kept = 0
                    for key in keys:
                        entry = state.get("repos", {}).get(key) or {}
                        commits = entry.get("commits") or {}
                        kept = []
                        for sha in entry.get("order") or []:
                            rec = commits.get(sha) or {}
                            for i, d in enumerate(rec.get("findings") or []):
                                if finding_marked.get((key, sha, i), False):
                                    continue
                                kept.append(_finding_from_state_dict(d))
                        total_kept += len(kept)
                        label = entry.get("name") or entry.get("url") or key
                        grouped.append((label, kept))
                    path = _default_findings_export_path(
                        "pwnguard-monitor-findings",
                    )
                    try:
                        export_monitor_findings_markdown(grouped, path)
                        status_line = (
                            f"exported {total_kept} finding"
                            f"{'s' if total_kept != 1 else ''} → {path}"
                        )
                    except OSError as exc:
                        status_line = f"export failed: {exc}"
                elif pressed == "-":
                    # Collapse everything: repos, commits, finding cards.
                    # Also drop back to findings-first so re-expanding
                    # starts from the uncluttered view.
                    repo_expanded.clear()
                    commit_expanded.clear()
                    finding_expanded.clear()
                    repo_show_all.clear()
                    _refresh_items(prev_anchor=current)
                    status_line = "collapsed all"
                elif pressed == "=":
                    # Expand everything: every repo, every commit (incl.
                    # clean ones), every finding card. Three passes
                    # because each level only appears in the item list
                    # once its parent is open.
                    for k in keys:
                        repo_expanded[k] = True
                        repo_show_all[k] = True
                    _refresh_items(prev_anchor=current)
                    for kind_, key_, ref_ in items:
                        if kind_ == "commit":
                            commit_expanded[(key_, ref_)] = True
                    _refresh_items(prev_anchor=current)
                    for kind_, key_, ref_ in items:
                        if kind_ == "finding":
                            sha_, i_ = ref_
                            finding_expanded[(key_, sha_, i_)] = True
                    status_line = "expanded all"
                elif pressed == "r":
                    if runtime.debug_mode:
                        # Drop out of cbreak / alt-buffer so the user
                        # can see streaming model output in their
                        # normal terminal scrollback. The TUI redraws
                        # automatically when we re-enter at top of
                        # the while loop.
                        with term.paused():
                            print(
                                "\nPwnGuard Monitor: --debug refresh "
                                "(streaming below)\n",
                                file=sys.stderr,
                            )
                            try:
                                summary = _run_monitor_refresh(
                                    config, state, backend,
                                )
                            except SystemExit as e:
                                summary = {}
                                print(
                                    f"\nrefresh aborted: {e.code}",
                                    file=sys.stderr,
                                )
                            print(
                                "\nPwnGuard Monitor: refresh complete.",
                                file=sys.stderr,
                            )
                            try:
                                input(
                                    "Press Enter to return to the "
                                    "dashboard..."
                                )
                            except (EOFError, KeyboardInterrupt):
                                pass
                    else:
                        status_line = "refreshing..."
                        _render_monitor(
                            state, keys, items, cursor,
                            repo_expanded, commit_expanded, finding_expanded,
                            finding_marked, status_line, repo_show_all,
                        )

                        def _progress(i, total, name, msg):
                            nonlocal status_line
                            status_line = (
                                f"refresh {i}/{total} · {name} · {msg}"
                            )
                            _render_monitor(
                                state, keys, items, cursor,
                                repo_expanded, commit_expanded,
                                finding_expanded, finding_marked, status_line,
                                repo_show_all,
                            )

                        try:
                            summary = _run_monitor_refresh(
                                config, state, backend, progress=_progress,
                            )
                        except SystemExit as e:
                            status_line = f"refresh aborted: {e.code}"
                            continue
                    _save_monitor_state(state, state_path)
                    keys = _ordered_monitor_keys(state, config)
                    _refresh_items(prev_anchor=current)
                    status_line = _summarise_refresh(summary)
    finally:
        # Persist marks-viewed and any other in-memory changes on exit.
        _save_monitor_state(state, state_path)

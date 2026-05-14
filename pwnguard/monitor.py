"""Monitor mode: state file, refresh cycle, and the dashboard TUI.

The state file (``.pwnguard-monitor.json`` in the cwd by default)
caches each watched repo's last-audited SHA and the resolved
findings, so reopening the TUI doesn't re-query the LLM for commits
already seen. ``last_viewed_sha`` is the user's acknowledgement;
when it lags ``last_audited_sha``, the row renders an ``[updated]``
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
    list_commits_from_url,
)
from pwnguard.models import AuditResult, Finding
from pwnguard.parser import parse_response
from pwnguard.prompts import build_system_prompt
from pwnguard.render import SEVERITY_LETTER, _print_legend
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
    # Belt-and-braces sanitisation: model output was sanitized at parse
    # time, but the file could have been tampered with offline. Re-run
    # the same scrub on every string we hand to the renderer.
    return _sanitize_loaded_state(data)


def _sanitize_loaded_state(state: dict) -> dict:
    """Re-sanitise every model-supplied string in a freshly loaded state."""
    repos = state.get("repos", {})
    if not isinstance(repos, dict):
        state["repos"] = {}
        return state
    for entry in repos.values():
        if not isinstance(entry, dict):
            continue
        findings = entry.get("findings") or []
        for f in findings:
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
        cached_diff = entry.get("diff_lines")
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


def _run_monitor_refresh(
    config: dict,
    state: dict,
    backend: str,
    progress=None,
) -> dict:
    """Iterate the configured monitor repos, audit any new commit.

    First-encounter strategy is "C — reset baseline to HEAD": when a
    repo has no ``last_audited_sha`` we record the current HEAD and
    skip the audit. Only commits that land **after** the first
    refresh produce findings.

    ``progress`` is an optional callback ``(idx, total, name, msg)`` so
    the TUI can update its status bar while we work. Returns a dict
    keyed by repo state-key mapping to one of:
      - ``"first-seen"`` — baseline recorded, no audit run.
      - ``"unchanged"`` — head matches last_audited_sha, nothing to do.
      - ``"audited"``   — new commit audited, state updated.
      - ``"error: ..."`` — recoverable failure (one repo failing must
        not abort the whole refresh).
    """
    monitor_cfg = config.get("monitor", {}) or {}
    repos = monitor_cfg.get("repos", []) or []
    summary: dict = {}
    state.setdefault("repos", {})

    for idx, repo_cfg in enumerate(repos):
        name = repo_cfg.get("name") or repo_cfg.get("url", "?")
        url = repo_cfg.get("url")
        branch = repo_cfg.get("branch")
        if not url or not branch:
            summary[name] = "error: monitor entry missing 'url' or 'branch'"
            continue

        key = _repo_key(url, branch)
        entry = state["repos"].get(key) or {
            "name": name,
            "url": url,
            "branch": branch,
            "last_audited_sha": None,
            "last_viewed_sha": None,
            "last_audited_commit_date": None,
            "audited_at": None,
            "findings": [],
        }
        # Keep the name in sync with the latest config (the user may
        # have renamed an entry between runs).
        entry["name"] = name
        entry["url"] = url
        entry["branch"] = branch
        state["repos"][key] = entry

        if progress:
            progress(idx + 1, len(repos), name, "fetching commits...")

        try:
            commits = list_commits_from_url(url, branch, limit=1)
        except SystemExit as e:
            summary[key] = f"error: {e.code}"
            continue
        if not commits:
            summary[key] = "error: no commits returned for branch"
            continue

        # list_commits_from_url returns (sha, committed_date_iso) tuples.
        # The date is informational - render-only - so we tolerate it
        # being None on backward-compat-flavoured servers that don't
        # ship it.
        first = commits[0]
        if isinstance(first, tuple) and len(first) == 2:
            latest_sha, latest_commit_date = first
        else:
            # Defensive: pre-v0.2.0 internal callers used to return bare
            # SHAs. Keep working if anyone wires this up differently.
            latest_sha, latest_commit_date = first, None

        is_first_encounter = entry["last_audited_sha"] is None
        if not is_first_encounter and entry["last_audited_sha"] == latest_sha:
            summary[key] = "unchanged"
            continue

        # First encounter OR new commit -> audit the head. The first
        # encounter case used to skip the audit and just record HEAD
        # as a "baseline," but that left the dashboard showing
        # "clean" for unaudited rows. Now the head always gets one
        # LLM call when a repo is first seen, so the user gets
        # current-state findings immediately on the first [r] press.
        if progress:
            label = "first audit" if is_first_encounter else "auditing"
            progress(
                idx + 1, len(repos), name,
                f"{label} {latest_sha[:7]}...",
            )
        try:
            result, diff_lines = _audit_commit_for_monitor(
                url, latest_sha, config, backend,
            )
        except SystemExit as e:
            summary[key] = f"error: {e.code}"
            continue

        entry["last_audited_sha"] = latest_sha
        entry["last_audited_commit_date"] = latest_commit_date
        entry["audited_at"] = datetime.now(timezone.utc).isoformat()
        entry["findings"] = [asdict(f) for f in result.findings]
        entry["diff_lines"] = _serialize_diff_lines(diff_lines)
        # First encounter is "you're looking at it now" - don't fire
        # the [updated] chip until the NEXT commit lands. Subsequent
        # audits leave last_viewed_sha alone so the chip surfaces
        # background changes the user hasn't acknowledged yet.
        if is_first_encounter:
            entry["last_viewed_sha"] = latest_sha
        summary[key] = "audited"

    return summary


def _summarise_refresh(summary: dict) -> str:
    """Format a one-line summary of a refresh cycle for the status bar."""
    audited = sum(1 for v in summary.values() if v == "audited")
    unchanged = sum(1 for v in summary.values() if v == "unchanged")
    errors = sum(1 for v in summary.values()
                 if isinstance(v, str) and v.startswith("error"))
    parts = []
    if audited:
        parts.append(f"{audited} audited")
    if unchanged:
        parts.append(f"{unchanged} unchanged")
    if errors:
        parts.append(f"{errors} error{'s' if errors != 1 else ''}")
    return "refresh: " + ", ".join(parts) if parts else "refresh: nothing to do"


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


def _render_monitor_row(
    entry: dict,
    *,
    is_expanded: bool,
    is_current: bool,
    width: int,
) -> None:
    """Print one repo header row. Findings, if any, are rendered as
    separate items beneath (see _render_monitor_finding_row); this
    function only handles the header line so the dashboard cursor
    can target the repo and its findings independently.
    """
    name = entry.get("name") or entry.get("url") or "?"
    sha = entry.get("last_audited_sha")
    last_viewed = entry.get("last_viewed_sha")
    commit_date = entry.get("last_audited_commit_date")
    findings = entry.get("findings") or []
    audited = sha is not None
    updated = audited and (sha != last_viewed)

    cursor_mark = ui.bold(ui.cyan("❯")) if is_current else " "
    arrow = "▼" if is_expanded else "▶"
    name_styled = ui.bold(name) if is_current else name
    if not audited:
        count_text = ui.dim("  awaiting first refresh")
    elif findings:
        # Severity breakdown, e.g. "1 C  ·  3 H  ·  12 INFO". Replaces
        # the previous flat "N findings" count so the user can see at
        # a glance which repo needs attention without expanding it.
        count_text = _severity_breakdown(findings)
    else:
        count_text = ui.dim("  clean")
    left = f" {cursor_mark} {arrow}  {name_styled}{count_text}"

    short = _format_short_sha(sha)
    relative = _format_relative_time(commit_date)
    chip = ui.dim("[updated]") if updated else ""
    right_parts = []
    if relative:
        right_parts.append(ui.dim(relative))
    right_parts.append(ui.dim(short))
    if chip:
        right_parts.append(chip)
    right = "  ".join(right_parts)

    pad = max(2, width - ui.visible_len(left) - ui.visible_len(right))
    print(left + (" " * pad) + right)

    # If expanded but no findings, the dashboard's items list won't
    # have any finding rows to render under this header; print a hint
    # in that case so the user understands why expansion looks empty.
    if is_expanded and not findings:
        if not audited:
            print(ui.dim(
                "        not yet audited — press [r] to refresh"
            ))
        else:
            print(ui.dim("        no findings on this commit"))


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


def _build_monitor_items(
    state: dict,
    keys: list,
    repo_expanded: dict,
) -> list:
    """Flatten the dashboard into an item list the cursor can index.

    Each item is ``(kind, repo_key, finding_idx)`` where ``kind`` is
    either ``"repo"`` (then ``finding_idx`` is None) or ``"finding"``.
    Findings only appear when their repo is expanded - collapsing a
    repo removes its findings from the cursor reachable set.

    Within an expanded repo, findings are ordered by severity
    (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO) with stable secondary
    ordering by emission index. Matches --review's behaviour so a
    HIGH SQL-injection finding doesn't sit buried under fifteen
    INFO "type ignore comment" rows.
    """
    items = []
    for key in keys:
        items.append(("repo", key, None))
        if repo_expanded.get(key, False):
            entry = state.get("repos", {}).get(key) or {}
            findings = entry.get("findings") or []
            sorted_idx = sorted(
                range(len(findings)),
                key=lambda i: (
                    -SEVERITY_ORDER.get(
                        (findings[i].get("severity") or "INFO").upper(), 0,
                    ),
                    i,  # stable: preserve emission order within severity
                ),
            )
            for i in sorted_idx:
                items.append(("finding", key, i))
    return items


def _render_monitor(
    state: dict,
    keys: list,
    items: list,
    cursor: int,
    repo_expanded: dict,
    finding_expanded: dict,
    finding_marked: dict,
    status_line: str,
) -> None:
    """Full-screen redraw of the monitor dashboard.

    ``items`` is the flat (repo + finding) list the cursor indexes
    into; ``keys`` is the repo subset used for the header count.
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
            repo_expanded, finding_expanded, finding_marked, status_line,
            width, height,
        )
    emit_tui_frame(buf.getvalue())


def _render_monitor_into_buffer(
    state: dict,
    keys: list,
    items: list,
    cursor: int,
    repo_expanded: dict,
    finding_expanded: dict,
    finding_marked: dict,
    status_line: str,
    width: int,
    height: int,
) -> None:
    """Inner render body. ``sys.stdout`` is redirected to the frame
    buffer by ``_render_monitor``; this function just emits lines."""
    n_repos = len(keys)

    header_lines = [
        ui.bold("PwnGuard Monitor") + ui.dim(
            f"  ·  {n_repos} repo{'s' if n_repos != 1 else ''}"
        ),
        ui.dim(
            "  up/down navigate   enter toggle   -/= collapse/expand all   "
            "space=strike   v=mark viewed   e=export   r=refresh   q=quit"
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
    for i, (kind, key, idx) in enumerate(items):
        if kind == "repo":
            entry = state.get("repos", {}).get(key) or {}
            block = capture(
                _render_monitor_row,
                entry,
                is_expanded=repo_expanded.get(key, False),
                is_current=(i == cursor),
                width=width,
            )
        else:  # finding
            entry = state.get("repos", {}).get(key) or {}
            findings = entry.get("findings") or []
            if idx is None or idx >= len(findings):
                block = [ui.dim("        (finding gone)")]
            else:
                try:
                    f = _finding_from_state_dict(findings[idx])
                except (TypeError, KeyError):
                    block = [ui.dim("        (finding malformed)")]
                else:
                    diff_lines = _deserialize_diff_lines(
                        entry.get("diff_lines") or {}
                    )
                    block = capture(
                        _render_monitor_finding_row,
                        f,
                        is_expanded=finding_expanded.get((key, idx), False),
                        is_current=(i == cursor),
                        is_marked=finding_marked.get((key, idx), False),
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
                "last_audited_commit_date": None,
                "audited_at": None,
                "findings": [],
                "diff_lines": {},
            }
        else:
            entry["name"] = name
            entry["url"] = url
            entry["branch"] = branch
            entry.setdefault("diff_lines", {})
            entry.setdefault("last_audited_commit_date", None)
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

    Keys:
      up / down         navigate
      enter             toggle expand / collapse on the current row
      right             expand
      left              collapse
      -                 collapse everything (all repos + all findings)
      =                 expand everything
      space             toggle strike-through on the current finding
                        (also collapses if it was expanded). On a repo
                        row this is a no-op.
      v                 mark the current repo viewed (clears [updated])
      r                 refresh (poll all repos, audit anything new)
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
    # Two expansion dictionaries: repo-level toggle controls which
    # findings are reachable in the item list; finding-level toggle
    # controls whether a finding renders as a one-liner or the full
    # boxed card. Using dicts keyed by stable identifiers means the
    # state survives a refresh that adds or reorders repos / findings.
    repo_expanded: dict = {}
    finding_expanded: dict = {}
    finding_marked: dict = {}
    items = _build_monitor_items(state, keys, repo_expanded)
    cursor = 0
    status_line = "loaded cached state — press [r] to refresh"

    def _refresh_items(prev_anchor=None):
        """Rebuild the items list and try to keep the cursor on the
        same logical row across expand / collapse / refresh.

        ``prev_anchor`` is the (kind, key, idx) tuple the cursor was
        on before the change. If that exact item still exists in the
        new list we land there; if it's been collapsed away (e.g.
        cursor was on a finding under a repo that just closed), we
        fall back to that repo's row.
        """
        nonlocal items, cursor
        items = _build_monitor_items(state, keys, repo_expanded)
        if not items:
            cursor = 0
            return
        if prev_anchor is not None:
            for i, it in enumerate(items):
                if it == prev_anchor:
                    cursor = i
                    return
            # Fall back: same repo, repo row.
            kind, key, _ = prev_anchor
            for i, it in enumerate(items):
                if it[0] == "repo" and it[1] == key:
                    cursor = i
                    return
        cursor = min(cursor, len(items) - 1)

    _refresh_items()

    try:
        with ui.CbreakTerminal() as term:
            while True:
                _render_monitor(
                    state, keys, items, cursor,
                    repo_expanded, finding_expanded, finding_marked,
                    status_line,
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
                    kind, key, idx = current
                    if kind == "repo":
                        if pressed == "right":
                            new = True
                        elif pressed == "left":
                            new = False
                        else:
                            new = not repo_expanded.get(key, False)
                        repo_expanded[key] = new
                        _refresh_items(prev_anchor=current)
                    else:  # finding
                        ekey = (key, idx)
                        if pressed == "right":
                            finding_expanded[ekey] = True
                        elif pressed == "left":
                            finding_expanded[ekey] = False
                        else:
                            finding_expanded[ekey] = (
                                not finding_expanded.get(ekey, False)
                            )
                elif pressed == "space" and current:
                    kind, key, idx = current
                    if kind == "finding":
                        ekey = (key, idx)
                        if not finding_marked.get(ekey, False):
                            # Strike + collapse if the card was open.
                            finding_marked[ekey] = True
                            finding_expanded[ekey] = False
                        else:
                            finding_marked[ekey] = False
                elif pressed == "v" and current:
                    kind, key, _ = current
                    if kind == "repo":
                        entry = state["repos"].get(key)
                        if entry:
                            entry["last_viewed_sha"] = entry.get("last_audited_sha")
                            status_line = (
                                f"marked '{entry.get('name', '?')}' viewed"
                            )
                elif pressed == "e":
                    # Export non-struck findings across every repo,
                    # grouped by repo, to a timestamped markdown file
                    # in the current directory. Strike marks are the
                    # user's "resolved / ignore" signal so we drop
                    # them; nothing in persistent state changes.
                    grouped = []
                    total_kept = 0
                    for key in keys:
                        entry = state.get("repos", {}).get(key) or {}
                        raw = entry.get("findings") or []
                        kept = [
                            _finding_from_state_dict(d)
                            for i, d in enumerate(raw)
                            if not finding_marked.get((key, i), False)
                        ]
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
                    # Collapse everything: all repos closed, every
                    # finding card closed.
                    repo_expanded.clear()
                    finding_expanded.clear()
                    _refresh_items(prev_anchor=current)
                    status_line = "collapsed all"
                elif pressed == "=":
                    # Expand everything: each repo open with all its
                    # findings expanded. One-key overview.
                    for k in keys:
                        repo_expanded[k] = True
                    _refresh_items(prev_anchor=current)
                    for kind_, key_, idx_ in items:
                        if kind_ == "finding":
                            finding_expanded[(key_, idx_)] = True
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
                            repo_expanded, finding_expanded, finding_marked,
                            status_line,
                        )

                        def _progress(i, total, name, msg):
                            nonlocal status_line
                            status_line = (
                                f"refresh {i}/{total} · {name} · {msg}"
                            )
                            _render_monitor(
                                state, keys, items, cursor,
                                repo_expanded, finding_expanded,
                                finding_marked, status_line,
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

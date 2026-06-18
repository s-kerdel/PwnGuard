"""Top-level scan pipeline.

``run_scan`` is the one entry point called from the CLI for the
normal pre-commit / CI / manual / --from-url paths. ``_run_scan_chunked``
is the per-file fallback used when the diff would otherwise overflow
the active model's context. ``explain_finding`` re-queries the backend
for a deeper writeup of a single previously-reported finding.
"""

import hashlib
import json
import os
import subprocess
import sys
import urllib.parse
from dataclasses import asdict
from typing import Optional

from pwnguard import __version__, runtime, ui
from pwnguard.anchors import resolve_anchors, wrap_diff
from pwnguard.backends import dispatch_backend
from pwnguard.constants import STREAMING_BACKENDS
from pwnguard.diff import (
    _chunk_token_budget,
    _split_file_chunk_by_hunks,
    _truncate_diff,
    estimate_tokens,
    filter_diff,
    get_file_contents,
    get_mr_diff,
    get_staged_diff,
    parse_diff_files,
    parse_diff_lines,
    split_diff_per_file,
    _looks_like_unified_diff,
)
from pwnguard.fetchers import fetch_from_url
from pwnguard.models import AuditResult, Finding, Observation
from pwnguard.parser import parse_response
from pwnguard.prompts import EXPLAIN_PROMPT_TEMPLATE, build_system_prompt
from pwnguard.security import _sanitize
from pwnguard.suppress import apply_inline_suppressions


def _run_scan_chunked(
    args,
    config: dict,
    backend: str,
    filtered_diff: str,
) -> tuple:
    """Per-file chunked scan path. Returns (AuditResult, total_elapsed).

    Splits the (already-filtered) diff into one chunk per file. When a
    single file's diff still exceeds the per-chunk token budget for the
    current backend, splits that file further at hunk (`@@`) boundaries
    so even oversized single-file diffs scan without silent truncation.
    Findings are concatenated; total elapsed is the sum of per-call
    wall times. The model loses cross-file context - that's the cost
    of avoiding truncation.
    """
    file_chunks = split_diff_per_file(filtered_diff)
    chunk_budget = _chunk_token_budget(backend, config)

    # Flatten per-file chunks into a sub-chunk list. The 3rd tuple slot
    # is an optional "part X/N" suffix shown in per-chunk progress so
    # the user sees when a single file was further split.
    flat_chunks: list = []
    for filename, file_chunk in file_chunks:
        if estimate_tokens(file_chunk) <= chunk_budget:
            flat_chunks.append((filename, file_chunk, None))
        else:
            sub = _split_file_chunk_by_hunks(file_chunk, chunk_budget)
            for i, piece in enumerate(sub, start=1):
                flat_chunks.append((filename, piece, f"part {i}/{len(sub)}"))

    n_files = len(file_chunks)
    n_total = len(flat_chunks)
    extras = n_total - n_files
    summary_line = f"chunked mode - {n_files} file(s)"
    if extras:
        summary_line += f", {extras} extra sub-chunk(s) for oversized files"
    print(ui.dim(f"PwnGuard: {summary_line}."), file=sys.stderr)

    all_findings: list = []
    all_observations: list = []
    total_elapsed = 0.0
    parse_errors: list = []
    total_dropped = 0

    for idx, (filename, chunk, suffix) in enumerate(flat_chunks, start=1):
        chunk_tokens = estimate_tokens(chunk)
        label = filename if suffix is None else f"{filename}  ({suffix})"
        print(
            ui.dim(
                f"PwnGuard: [{idx}/{n_total}] {label} "
                f"(~{chunk_tokens:,} tokens)"
            ),
            file=sys.stderr,
        )
        spinner_label = f"  scanning {label}"
        spinner_enabled = not (runtime.debug_mode and backend in STREAMING_BACKENDS)
        with ui.Spinner(spinner_label, enabled=spinner_enabled) as spinner:
            try:
                response, anchor_table = dispatch_backend(backend, chunk, config)
            except SystemExit as e:
                # One chunk failed - continue the rest so the user
                # still gets findings from chunks that did succeed.
                print(
                    ui.red(f"  PwnGuard: scan of {label} failed: {e}"),
                    file=sys.stderr,
                )
                continue
        total_elapsed += spinner.elapsed

        sub_result = parse_response(response)
        if sub_result.error:
            parse_errors.append((label, sub_result.error))
        # Resolve anchors against THIS chunk's table - tokens reset per
        # call, so a finding from chunk N must be looked up in chunk N's
        # table or it gets dropped.
        dropped = resolve_anchors(sub_result, anchor_table)
        if dropped:
            print(
                ui.dim(
                    f"  PwnGuard: dropped {dropped} finding(s) in {label} "
                    f"with unrecognised anchor token"
                ),
                file=sys.stderr,
            )
            total_dropped += dropped
        all_findings.extend(sub_result.findings)
        all_observations.extend(sub_result.observations)

    merged = AuditResult()
    merged.findings = all_findings
    merged.observations = all_observations
    if parse_errors:
        # Only set the global error (which makes main() exit with code 2)
        # when every chunk failed. If some chunks parsed cleanly, surface
        # the failures as stderr warnings and let the successful findings
        # drive the exit code - better than dropping good results.
        if not all_findings:
            merged.error = "\n".join(
                f"[{fname}] {err.splitlines()[0]}" for fname, err in parse_errors
            )
        else:
            for fname, err in parse_errors:
                print(
                    ui.dim(
                        f"PwnGuard: parse error in {fname}: "
                        f"{err.splitlines()[0]}"
                    ),
                    file=sys.stderr,
                )
    return merged, total_elapsed


# --- Scan cache --------------------------------------------------------
# Lets a follow-up `--review --cached` reuse the hook's scan instead of
# re-hitting the AI. Single entry in .git/, content-keyed (so a changed
# staged diff misses and re-scans), best-effort (never blocks a commit).

_SCAN_CACHE_VERSION = 1


def _scan_cache_path() -> Optional[str]:
    """Path to the per-repo cache file inside .git/, or None if not in a repo."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True, text=True, check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    git_dir = out.stdout.strip()
    if out.returncode != 0 or not git_dir:
        return None
    return os.path.join(git_dir, "pwnguard-scan-cache.json")


def _scan_cache_key(diff: str, backend: str, config: dict) -> str:
    """Hash of everything that changes findings: pwnguard version, diff,
    backend, model, obs flag. Including the version means an upgrade that
    changes detection invalidates old entries instead of replaying them."""
    models = "|".join(
        str((config.get(sec) or {}).get("model", ""))
        for sec in ("ollama", "claude_api", "openai")
    )
    obs = "1" if runtime.show_observations else "0"
    payload = "\0".join([__version__, diff, backend, models, obs])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_cacheable(args) -> bool:
    """True only for the staged-diff path. URL / file / manual / CI sources
    don't share the staged cache, so they neither read nor write it."""
    return not (
        getattr(args, "from_url", None)
        or getattr(args, "diff_file", None)
        or (getattr(args, "mode", None) == "manual" and getattr(args, "files", None))
        or getattr(args, "mode", None) == "ci"
        or getattr(args, "mr_diff", None)
    )


def _result_to_dict(result: AuditResult) -> dict:
    return {
        "findings": [asdict(f) for f in result.findings],
        "observations": [asdict(o) for o in result.observations],
        "files_scanned": result.files_scanned,
        "error": result.error,
        "elapsed": result.elapsed,
        "suppressed": result.suppressed,
    }


def _result_from_dict(data: dict) -> AuditResult:
    return AuditResult(
        findings=[Finding(**f) for f in data.get("findings", [])],
        observations=[Observation(**o) for o in data.get("observations", [])],
        files_scanned=data.get("files_scanned", 0),
        error=data.get("error"),
        elapsed=data.get("elapsed", 0.0),
        suppressed=data.get("suppressed", 0),
    )


def _store_scan_cache(key: str, diff: str, result: AuditResult) -> None:
    """Write the latest scan. Swallows every error so a commit can't fail here.
    Errored scans aren't cached, so a transient backend failure isn't replayed
    by a later --cached run instead of being retried."""
    if result.error:
        return
    path = _scan_cache_path()
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {"version": _SCAN_CACHE_VERSION, "key": key,
                 "diff": diff, "result": _result_to_dict(result)},
                f,
            )
    except (OSError, TypeError):
        pass


def _load_scan_cache(key: str) -> Optional[tuple]:
    """Return (result, diff, diff_lines, files_scanned) on an exact key match,
    else None. Any missing file / parse error / key mismatch is a miss."""
    path = _scan_cache_path()
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("version") != _SCAN_CACHE_VERSION or data.get("key") != key:
            return None
        diff = data["diff"]
        result = _result_from_dict(data["result"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return result, diff, parse_diff_lines(diff), len(parse_diff_files(diff))


def run_scan(
    args,
    config: dict,
    backend: str,
    max_file_size_kb: int,
) -> tuple:
    """Single-scan path used by main() and indirectly by --explain / --review.

    Returns (AuditResult, diff, diff_lines, files_scanned). Always prints a
    one-line diff-size summary on stderr so the developer sees how much was
    sent (helpful for diagnosing slow scans or unexpectedly large prompts).
    """
    # Get the diff. URL-based and file-based sources take priority over
    # --mode so we can test against a pre-fetched MR/PR without needing
    # to be inside the relevant git repo.
    if args.from_url:
        raw_diff = fetch_from_url(args.from_url)
        # Same guard as --diff-file: if GitLab/GitHub returns an HTML
        # error page (auth failure, rate limit, brief outage) the body
        # will be HTML, not a diff. Without this check we'd silently
        # "scan 0 files" and report PASS, masking the real failure.
        if not _looks_like_unified_diff(raw_diff):
            preview = _sanitize(raw_diff[:200].replace("\n", " ")) or "(empty)"
            sys.exit(
                f"Error: {args.from_url!r} did not return a unified diff "
                f"(no 'diff --git' or '+++ b/' headers in the response).\n"
                f"This usually means the fetch failed (auth, rate limit, "
                f"or wrong URL) and the server returned an HTML error "
                f"page or empty body instead.\n"
                f"Response preview: {preview!r}"
            )
    elif args.diff_file:
        with open(args.diff_file) as f:
            raw_diff = f.read()
        # --diff-file expects a unified diff. A common mistake is to
        # point it at a source file: with no `diff --git` / `+++ b/`
        # headers the anchor tagger has no file context, every
        # finding comes back with file="" line=N, and the renderer
        # has nothing to show. Refuse early with a precise hint.
        if not _looks_like_unified_diff(raw_diff):
            sys.exit(
                f"Error: {args.diff_file!r} doesn't look like a unified "
                f"diff (no 'diff --git' or '+++ b/' headers found).\n"
                f"To scan a source file directly, use:\n"
                f"  python audit.py --mode manual --files {args.diff_file}"
            )
    elif args.mode == "manual" and args.files:
        raw_diff = get_file_contents(args.files, max_file_size_kb)
    elif args.mode == "ci" or args.mr_diff:
        raw_diff = get_mr_diff()
    else:
        raw_diff = get_staged_diff()

    if not raw_diff.strip():
        return AuditResult(), "", {}, 0

    # Pattern-filter WITHOUT applying max_diff_lines yet. The overflow
    # check below needs the full filtered size so it can auto-switch to
    # chunked mode when appropriate. Truncating first would silently
    # drop files past the cap before the chunker ever sees them.
    filtered = filter_diff(raw_diff, config, apply_truncation=False)
    if not filtered.strip():
        return AuditResult(), "", {}, 0

    # Key on the pre-truncation diff so write (below) and read use the
    # same value regardless of the later chunk/truncate decision. Only the
    # staged-diff path participates in the cache.
    cacheable = _is_cacheable(args)
    cache_key = _scan_cache_key(filtered, backend, config)
    if cacheable and getattr(args, "cached", False):
        cached = _load_scan_cache(cache_key)
        if cached is not None:
            print(ui.dim("PwnGuard: reusing cached scan (--cached)"), file=sys.stderr)
            return cached

    # Diff-size telemetry is always shown so the dev knows what just went
    # over the wire (especially relevant for paid backends).
    print(
        ui.dim(
            f"PwnGuard: diff {len(filtered):,} chars, "
            f"{len(filtered.splitlines()):,} lines, "
            f"~{estimate_tokens(filtered):,} tokens"
        ),
        file=sys.stderr,
    )

    # Pre-flight checks for local backends. Printed BEFORE the spinner
    # so the heads-up appears first instead of after "Scanning with
    # ollama..." has already started counting.
    # TODO(normalize): this overflow check + the dispatch/parse/resolve
    # further down are duplicated in _audit_commit_for_monitor
    # (monitor.py). Extract shared should_chunk() + audit_single_diff()
    # helpers - deferred, see memory/project_monitor_audit_core_refactor.md.
    if backend == "ollama":
        # Build the same prompt the backend will see so the estimate is
        # accurate (slim vs full + framework hints affect total tokens).
        preview_prompt = build_system_prompt(include_preview_fields=runtime.show_code_preview)
        prompt_tokens = estimate_tokens(preview_prompt) + estimate_tokens(filtered)
        ollama_cfg = config.get("ollama", {})
        ollama_num_ctx = ollama_cfg.get("num_ctx", 4096)
        ollama_num_predict = ollama_cfg.get("num_predict", 2048)
        budget = prompt_tokens + ollama_num_predict

        # Auto-fallback: if the estimated prompt + response budget
        # exceeds num_ctx, Ollama would silently truncate the diff and
        # the model would only see part of it. Switch to chunked mode
        # automatically rather than producing a quietly-incomplete scan.
        if not args.chunk_per_file and budget > ollama_num_ctx:
            print(
                ui.dim(
                    f"PwnGuard: estimated prompt+response (~{budget:,} tokens) "
                    f"exceeds ollama num_ctx ({ollama_num_ctx:,}). "
                    f"Switching to --chunk-per-file (one AI call per file) "
                    f"so the model sees every file in full."
                ),
                file=sys.stderr,
            )
            args.chunk_per_file = True
        elif not args.chunk_per_file and prompt_tokens > 5000:
            # Fits in context but still big enough to feel slow.
            approx_secs = prompt_tokens // 80 + 10
            print(
                ui.dim(
                    f"PwnGuard: large prompt (~{prompt_tokens:,} tokens) on local "
                    f"backend - rough estimate ~{approx_secs}s before findings "
                    f"appear. For diffs this size, --backend claude-code (or "
                    f"claude-api) is dramatically faster."
                ),
                file=sys.stderr,
            )
    elif backend == "openai-compat":
        # Surface destination (host + model) BEFORE the spinner starts
        # so the "where is this diff going" heads-up appears first, not
        # after "Scanning with openai-compat..." has begun counting.
        # Validation stays in query_openai_compat; this block is purely
        # informational so we tolerate a missing/odd url here.
        openai_cfg = config.get("openai", {})
        raw_url = openai_cfg.get("url", "")
        model = openai_cfg.get("model", "")
        host = ""
        if raw_url:
            try:
                host = urllib.parse.urlparse(raw_url).hostname or raw_url
            except ValueError:
                host = raw_url
        if host or model:
            safe_host = _sanitize(host) or host or "(unset)"
            safe_model = _sanitize(model) or model or "(unset)"
            print(
                ui.dim("PwnGuard: sending diff to ")
                + ui.green(safe_host)
                + ui.dim(" (model: ")
                + ui.blue(safe_model)
                + ui.dim(")"),
                file=sys.stderr,
            )

    # Now that we know whether we're chunking, apply max_diff_lines.
    # Non-chunked mode still gets capped (safety net for runaway diffs);
    # chunked mode skips it because the per-file splitter handles size.
    if not args.chunk_per_file:
        filtered = _truncate_diff(filtered, config.get("max_diff_lines", 500))

    diff_lines = parse_diff_lines(filtered)
    files = parse_diff_files(filtered)

    # Chunked mode: scan each file separately so each request stays
    # within num_ctx. Findings from every chunk are merged into one
    # result so the rest of the rendering pipeline doesn't need to
    # know whether chunking happened. Anchor resolution happens
    # inside _run_scan_chunked because each chunk has its own
    # anchor namespace; the merged result arrives already resolved.
    response = ""  # used by the "tiny response" diagnostic below
    if args.chunk_per_file:
        result, elapsed = _run_scan_chunked(args, config, backend, filtered)
    else:
        # Query the AI. In debug mode the spinner is disabled because
        # the live token stream from the backend replaces it as the
        # progress signal - interleaving the two would garble the output.
        spinner_label = f"Scanning with {backend}"
        spinner_enabled = not (runtime.debug_mode and backend in STREAMING_BACKENDS)
        with ui.Spinner(spinner_label, enabled=spinner_enabled) as spinner:
            response, anchor_table = dispatch_backend(backend, filtered, config)
        elapsed = spinner.elapsed
        result = parse_response(response)
        # One O(1) lookup per finding replaces the old three-stage
        # repair chain (snippet match, function-name regex, hunk
        # header scrape). Tokens the model fabricates lose the
        # corresponding finding outright - no fuzzy recovery.
        dropped = resolve_anchors(result, anchor_table)
        if dropped:
            print(
                ui.dim(
                    f"PwnGuard: dropped {dropped} finding(s) with "
                    f"unrecognised anchor token (model fabricated)"
                ),
                file=sys.stderr,
            )
    result.files_scanned = len(files)
    result.elapsed = elapsed

    # Diagnostic when the model returned valid JSON but zero findings.
    # On small/legit "no issues" responses this stays out of the way
    # (we only print when the response is suspiciously short, which
    # usually means the model truncated, refused, or got confused).
    # Chunked mode doesn't have a single ``response`` to inspect, so
    # this only runs on the non-chunked path.
    if response and not result.findings and not result.error:
        if len(response.strip()) < 80:
            print(
                ui.dim(
                    f"PwnGuard: received {len(response.strip())}-char "
                    f"response with zero findings - model may have "
                    f"truncated or skipped the scan. Raw: "
                    f"{response.strip()[:120]!r}"
                ),
                file=sys.stderr,
            )

    # Observation counter (only when the flag is on). Distinguishes
    # "model returned zero observations" from "we never asked" - useful
    # for debugging why the observations block didn't render. Skipped
    # in chunked mode because there's no single ``response`` to grep.
    if runtime.show_observations and not result.error and response:
        n = len(result.observations)
        present = "yes" if '"observations"' in response else "no"
        print(
            ui.dim(
                f"PwnGuard: model returned {n} observation{'s' if n != 1 else ''} "
                f"(observations field in response: {present})"
            ),
            file=sys.stderr,
        )

    # Inline suppressions: drop findings the developer marked as accepted
    # false positives with a pwnguard:ignore comment in the diff, before
    # the gate sees them. Cached after this so a --cached re-run matches.
    suppressed = apply_inline_suppressions(result, diff_lines)
    if suppressed:
        print(
            ui.dim(
                f"PwnGuard: {suppressed} finding(s) suppressed inline "
                f"(pwnguard:ignore)"
            ),
            file=sys.stderr,
        )

    # Persist for a later --cached run (e.g. the --review re-run), staged
    # path only so URL/file/CI scans don't leave a stray cache.
    if cacheable:
        _store_scan_cache(cache_key, filtered, result)

    return result, filtered, diff_lines, len(files)


def explain_finding(
    finding: Finding,
    diff: str,
    config: dict,
    backend: str,
) -> str:
    """Re-query the AI for a longer explanation of one finding."""
    wrapped_diff, _ = wrap_diff(diff)
    explain_prompt = EXPLAIN_PROMPT_TEMPLATE.format(
        severity=finding.severity,
        title=finding.title,
        file=finding.file,
        line=finding.line if finding.line else "?",
        description=finding.description,
        recommendation=finding.recommendation,
        cwe=finding.cwe or "(none)",
        diff=wrapped_diff,
    )

    # Re-use the same backend dispatch with a custom system prompt that
    # asks for prose rather than JSON. The diff is already embedded in
    # explain_prompt, so pass pre_wrapped=True to skip dispatch's wrap
    # (otherwise we'd send a stray empty <diff_to_review> envelope).
    response, _ = dispatch_backend(
        backend,
        diff="",
        config=config,
        system_prompt=explain_prompt,
        pre_wrapped=True,
    )
    return response.strip()

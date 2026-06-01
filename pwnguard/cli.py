"""CLI entry point: argparse, runtime-toggle wiring, and main flow.

The main() function below is what ``audit.py`` at the repo root calls
when invoked directly. All implementation lives in the rest of the
package.
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import asdict

from pwnguard import __version__, runtime, ui
from pwnguard.backends import claude_code_available
from pwnguard.config import _maybe_load_env_files, load_config
from pwnguard.diff import (
    estimate_tokens,
    filter_diff,
    get_file_contents,
    get_mr_diff,
    get_staged_diff,
    parse_diff_files,
)
from pwnguard.fetchers import fetch_from_url
from pwnguard.monitor import _monitor_state_path, interactive_monitor
from pwnguard.render import (
    _ordered_findings,
    _print_finding_block,
    print_terminal,
)
from pwnguard.report import (
    format_gitlab_comment,
    post_gitlab_comment,
    write_report,
)
from pwnguard.review import interactive_review
from pwnguard.scan import explain_finding, run_scan


def _run_self_test() -> int:
    """Run the bundled pytest suite against tests/ and return its exit code.

    Looks for the tests directory in three locations, in order:

      1. Next to the ``audit.py`` shim - standalone layout, the common
         case (the PwnGuard repository itself runs --self-test against
         its own bundled tests/).
      2. Inside the ``pwnguard/`` package directory - the legacy
         embedded layout, where a consumer might have copied PwnGuard's
         tests alongside the implementation files.
      3. One level above the shim - belt-and-braces fallback that
         covers obscure nested checkouts.

    Runs pytest as a subprocess so it doesn't entangle the CLI's own
    argparse state with pytest's collection.
    """
    package_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(package_dir)
    candidates = [
        os.path.join(repo_root, "tests"),
        os.path.join(package_dir, "tests"),
        os.path.join(os.path.dirname(repo_root), "tests"),
    ]
    tests_dir = next(
        (p for p in candidates
         if os.path.isdir(p) and os.path.isfile(os.path.join(p, "test_anchors.py"))),
        None,
    )
    if tests_dir is None:
        print(
            ui.red("Error:") + " tests/ directory not found next to audit.py.\n"
            "  Looked in:\n"
            + "".join(f"    {p}\n" for p in candidates),
            file=sys.stderr,
        )
        return 2
    try:
        import pytest  # noqa: F401  - probed for presence only
    except ImportError:
        print(
            ui.red("Error:") + " pytest is not installed. Install dev deps:\n"
            "  pip install -e \".[dev]\"   (inside a venv, from the repo root)\n"
            "  pipx inject pwnguard pytest   (if you installed via pipx)",
            file=sys.stderr,
        )
        return 2
    print(ui.dim(f"PwnGuard: running test suite in {tests_dir}"), file=sys.stderr)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", tests_dir, "-v"],
        check=False,
    )
    return result.returncode


class _WideHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """argparse formatter with a wider gap between flag and description."""

    def __init__(self, prog, **kwargs):
        super().__init__(prog, max_help_position=32, **kwargs)


def main():
    parser = argparse.ArgumentParser(
        prog="pwnguard",
        description="PwnGuard: AI-powered security audit for git commits",
        epilog=(
            "Examples:\n"
            "  pwnguard --install-hook                        Install the pre-commit hook in the current git repo\n"
            "  pwnguard --mode manual --files src/Foo.py      Scan one or more files manually\n"
            "  pwnguard --from-url <gitlab-mr-url>            Audit a remote MR/PR via API\n"
            "  pwnguard --diff-file branch.diff --review      Walk findings interactively from a saved diff\n"
            "  pwnguard --monitor                             Open the watch-repos dashboard\n"
            "\n"
            "Config: pwnguard.yaml + .pwnguard.env in the project root (none required; defaults work).\n"
            "Docs:   https://github.com/s-kerdel/PwnGuard"
        ),
        formatter_class=_WideHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"PwnGuard {__version__}",
    )

    source_group = parser.add_argument_group("Source")
    source_group.add_argument(
        "--mode",
        choices=["hook", "ci", "manual"],
        default="hook",
        help="Run mode: hook (pre-commit), ci (GitLab pipeline), manual (specific files)",
    )
    source_group.add_argument(
        "--files",
        nargs="+",
        help="Specific files to scan (manual mode only)",
    )
    source_group.add_argument(
        "--from-url",
        metavar="URL",
        help=(
            "Fetch the diff from a GitLab MR / GitHub PR / commit URL "
            "via the platform API. Requires GITLAB_TOKEN for GitLab; "
            "GITHUB_TOKEN is optional for public repos."
        ),
    )

    backend_group = parser.add_argument_group("Backend")
    backend_group.add_argument(
        "--backend",
        choices=["claude-code", "ollama", "claude-api", "openai-compat"],
        default=None,
        help="AI backend (default: claude-code for hook, ollama for ci)",
    )
    backend_group.add_argument(
        "--model",
        help="Override model (e.g. qwen2.5-coder:14b, claude-opus-4-7, claude-sonnet-4-6)",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of formatted text",
    )
    output_group.add_argument(
        "--quiet",
        action="store_true",
        help="One-line-per-finding output (good for terse CI logs)",
    )
    output_group.add_argument(
        "--code-preview",
        choices=["auto", "on", "off"],
        default="auto",
        help=(
            "Show affected code lines and fix_example snippets. "
            "'auto' (default): on for every backend; the renderer falls "
            "back to the file's changed lines when the model omits a "
            "precise `line`, so even smaller local models produce "
            "something useful. Use 'off' to suppress the code block "
            "entirely."
        ),
    )
    output_group.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Stream the model's output live to stderr instead of showing "
            "the spinner. Also prints per-request stats (token count, "
            "speed, stop reason). Useful when scans return empty or "
            "stop unexpectedly."
        ),
    )

    policy_group = parser.add_argument_group("Policy")
    policy_group.add_argument(
        "--threshold",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Override severity threshold from config",
    )
    policy_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be sent to AI without sending",
    )
    policy_group.add_argument(
        "--review",
        action="store_true",
        help="Walk through findings interactively after the scan",
    )
    policy_group.add_argument(
        "--chunk-per-file",
        action="store_true",
        help=(
            "Split the diff at `diff --git` boundaries and scan each file "
            "separately, then merge findings. Useful when the full diff "
            "exceeds the local model's context window - keeps each request "
            "small enough to fit in num_ctx. Adds wall time (one AI call "
            "per file) but avoids silent truncation."
        ),
    )

    advanced_group = parser.add_argument_group("Advanced")
    advanced_group.add_argument(
        "--diff-file",
        metavar="PATH",
        help=(
            "Read a unified diff from PATH instead of running git. "
            "Handy for offline testing against arbitrary diffs."
        ),
    )
    advanced_group.add_argument(
        "--mr-diff",
        action="store_true",
        help="Use MR diff instead of staged diff (CI mode)",
    )
    advanced_group.add_argument("--config", help="Path to config file")
    advanced_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color and hyperlinks",
    )
    advanced_group.add_argument(
        "--report",
        metavar="PATH",
        help="Write findings as a markdown report to PATH",
    )
    advanced_group.add_argument(
        "--show-observations",
        action="store_true",
        help=(
            "Also surface a short list of neutral observations about "
            "defensive patterns the model noticed in the diff (e.g. "
            "'parameterised query', 'output escaped'). Opt-in only, "
            "additive: never replaces findings, never claims code is "
            "secure. Adds a small number of prompt + output tokens."
        ),
    )
    advanced_group.add_argument(
        "--explain",
        metavar="N",
        type=int,
        help="Re-query the AI for a deeper explanation of finding N (1-based)",
    )
    advanced_group.add_argument(
        "--env-file",
        metavar="PATH",
        help=(
            "Load KEY=VALUE pairs from PATH into the environment. "
            ".env and .pwnguard.env in the current directory are also "
            "auto-loaded; existing process env vars always take precedence."
        ),
    )
    advanced_group.add_argument(
        "--self-test",
        action="store_true",
        help=(
            "Run PwnGuard's bundled test suite (anchor pipeline, JSON "
            "parser repair, diff validation, box-card width math) and "
            "exit with pytest's status code. Useful for verifying that "
            "an install is healthy. Requires pytest "
            "(pip install -e \".[dev]\" inside a venv, or pipx inject "
            "pwnguard pytest)."
        ),
    )
    advanced_group.add_argument(
        "--ollama-format",
        choices=["json", "raw"],
        default="json",
        help=(
            "Ollama output mode. 'json' (default) forces valid JSON via "
            "Ollama's constrained generation - reliable but ~2x slower "
            "on 7B models. 'raw' lets the model emit freely; faster but "
            "leans on PwnGuard's parse fallbacks when the model wraps "
            "JSON in markdown or adds preamble."
        ),
    )
    advanced_group.add_argument(
        "--monitor",
        action="store_true",
        help=(
            "Open the monitor TUI: a dashboard that watches the repos "
            "configured under monitor.repos[] in pwnguard.yaml, audits "
            "newly-landed commits (one per refresh per repo), and lets "
            "you step through findings without re-running the audit. "
            "Press [r] inside the TUI to refresh."
        ),
    )

    setup_group = parser.add_argument_group("Setup")
    setup_group.add_argument(
        "--install-hook",
        action="store_true",
        help=(
            "Install PwnGuard's pre-commit hook into the current git "
            "repository's .git/hooks/pre-commit. Run from inside the "
            "repository you want to protect."
        ),
    )
    setup_group.add_argument(
        "--uninstall-hook",
        action="store_true",
        help=(
            "Remove PwnGuard's pre-commit hook from the current git "
            "repository. Only removes the hook if PwnGuard installed it; "
            "a user-owned or third-party hook is left untouched."
        ),
    )

    # Bare `pwnguard` with no flags: show help without the Advanced
    # group, then point at `--help` for the full reference. Without
    # this, `--mode hook` is the default and the user falls through
    # to a git error when there's no staged diff (or no repo at all).
    if len(sys.argv) == 1:
        parser._action_groups.remove(advanced_group)
        parser.print_help()
        print("\nRun `pwnguard --help` for advanced flags.")
        sys.exit(0)

    args = parser.parse_args()

    # --install-hook / --uninstall-hook short-circuit every other flag:
    # no backend, no diff, no yaml load. Drop or remove the bundled
    # pre-commit script in the current repo's .git/hooks/ and exit.
    if args.install_hook:
        from pwnguard.installer import install_hook
        sys.exit(install_hook())
    if args.uninstall_hook:
        from pwnguard.installer import uninstall_hook
        sys.exit(uninstall_hook())

    # --self-test short-circuits every other flag: it doesn't touch the
    # AI backend, doesn't read a diff, doesn't load yaml. Run pytest
    # against the bundled tests/ dir and exit with its status.
    if args.self_test:
        sys.exit(_run_self_test())

    # Configure UI before any styled output.
    ui.configure(color=ui.should_use_color(no_color_flag=args.no_color))

    # Load env vars before anything that might need them (tokens for
    # --from-url, ANTHROPIC_API_KEY for claude-api, GITLAB_TOKEN for
    # CI mode comment posting).
    _maybe_load_env_files(args.env_file)

    # Load config
    config = load_config(args.config)

    # Determine backend. Precedence: CLI flag → config (pwnguard.yaml or
    # pwnguard.local.yaml) → mode-based auto-detection. The config knob
    # lets a project pin a backend without every developer typing
    # --backend on each invocation; pwnguard.local.yaml makes the same
    # thing work as a personal override since it deep-merges on top.
    VALID_BACKENDS = ("claude-code", "ollama", "claude-api", "openai-compat")
    if args.backend:
        backend = args.backend
    elif (cfg_backend := config.get("backend")):
        if cfg_backend not in VALID_BACKENDS:
            sys.exit(
                f"Error: invalid `backend` in pwnguard.yaml: {cfg_backend!r}. "
                f"Must be one of: {', '.join(VALID_BACKENDS)}."
            )
        backend = cfg_backend
    elif args.mode == "ci":
        # CI: prefer claude-api if key present, else self-hosted ollama runner.
        backend = "claude-api" if os.environ.get("ANTHROPIC_API_KEY") else "ollama"
    else:
        # Local: prefer claude-code (Pro subscription), fall back to ollama.
        backend = "claude-code" if claude_code_available() else "ollama"

    # Determine threshold
    threshold = args.threshold or config.get("severity_threshold", "HIGH")

    # Override model if specified
    if args.model:
        config.setdefault("ollama", {})["model"] = args.model
        config.setdefault("claude_api", {})["model"] = args.model
        config.setdefault("openai", {})["model"] = args.model

    max_file_size_kb = config.get("max_file_size_kb", 100)

    # Resolve the code-preview default: Claude backends are precise enough
    # that the preview adds real value; ollama backends default off so
    # imprecise line numbers don't end up highlighting the wrong code.
    if args.code_preview == "on":
        runtime.set_code_preview(True)
    elif args.code_preview == "off":
        runtime.set_code_preview(False)
    else:
        # Code preview default: on for every backend. The original
        # reason for off-on-ollama was wrong line numbers from 7B
        # models. The block renderer now falls back to "all changed
        # lines in this file" when the precise window can't be built,
        # so even unreliable `line` values produce something useful.
        # `--code-preview off` still works for users who want it off.
        runtime.set_code_preview(True)

    # Ollama JSON mode toggle (only meaningful for the ollama backend).
    runtime.set_ollama_json_mode(args.ollama_format == "json")

    # Debug mode replaces the spinner with a live token stream and
    # prints per-request diagnostics. Currently only the ollama backend
    # actually streams (Claude Code / Claude API run as a single call).
    runtime.set_debug_mode(args.debug)

    # Opt-in observations block. Default off so the standard hook flow
    # stays silent on success and findings never get diluted.
    runtime.set_show_observations(args.show_observations)

    # Monitor mode: dashboard over the configured monitor.repos[]. Opens
    # the TUI immediately on cached state; [r] inside the TUI refreshes.
    # Short-circuits the normal scan path entirely - no diff source, no
    # threshold gating, no exit code beyond TUI quit.
    if args.monitor:
        state_path = _monitor_state_path(config)
        interactive_monitor(config, backend, state_path)
        sys.exit(0)

    # Dry-run: build the diff and report what would be sent, then exit.
    if args.dry_run:
        if args.from_url:
            diff = fetch_from_url(args.from_url)
        elif args.diff_file:
            with open(args.diff_file) as f:
                diff = f.read()
        elif args.mode == "manual" and args.files:
            diff = get_file_contents(args.files, max_file_size_kb)
        elif args.mode == "ci" or args.mr_diff:
            diff = get_mr_diff()
        else:
            diff = get_staged_diff()
        diff = filter_diff(diff, config)
        files = parse_diff_files(diff)
        print(f"Would scan {len(files)} file(s) using {backend}:")
        for f in files:
            print(f"  {f}")
        print(
            f"\nDiff size: {len(diff):,} characters, "
            f"{len(diff.splitlines()):,} lines, "
            f"~{estimate_tokens(diff):,} tokens"
        )
        print(f"Threshold: {threshold}")
        sys.exit(0)

    # Normal scan path.
    result, diff, diff_lines, files_scanned = run_scan(
        args, config, backend, max_file_size_kb,
    )

    if files_scanned == 0 and not result.findings and not result.error:
        print(ui.dim("No changes to audit."))
        sys.exit(0)

    # --explain N: produce a deeper explanation of one finding and exit.
    if args.explain is not None:
        idx = args.explain - 1  # 1-based on CLI for human friendliness
        findings = _ordered_findings(result)
        if not (0 <= idx < len(findings)):
            sys.exit(
                f"--explain {args.explain}: index out of range "
                f"(only {len(findings)} finding(s) found)."
            )
        target = findings[idx]
        # Print the finding header so the user knows what they're reading.
        print(f"  {ui.underline(ui.bold(target.file))}")
        _print_finding_block(target, diff_lines)
        with ui.Spinner("Re-querying for a deeper explanation") as spinner:
            detail = explain_finding(target, diff, config, backend)
        print()
        for line in detail.splitlines():
            print(f"  {line}")
        print()
        sys.exit(0)

    # --review opens an informative TUI walk *before* the normal report.
    # Marks and expansions are visual progress only - they don't affect
    # the threshold check or the exit code, so the standard print path
    # still runs after the user quits the TUI.
    if args.review and result.findings:
        interactive_review(result, diff_lines)

    if args.json:
        output = {
            "findings": [asdict(f) for f in result.findings],
            "summary": result.summary,
            "files_scanned": result.files_scanned,
            "threshold": threshold,
            "blocked": result.exceeds_threshold(threshold),
            "elapsed_seconds": round(result.elapsed, 2),
        }
        # Only surface the observations key when the flag was passed so
        # downstream consumers don't see an unexpected empty list.
        if runtime.show_observations:
            output["observations"] = [asdict(o) for o in result.observations]
        if result.error:
            output["error"] = result.error
        print(json.dumps(output, indent=2))
    elif args.mode == "ci":
        # Terminal output for CI logs
        print_terminal(
            result, threshold, diff_lines,
            files_scanned=files_scanned, quiet=args.quiet,
        )
        # Post to GitLab MR
        comment = format_gitlab_comment(result)
        post_gitlab_comment(comment)
    else:
        print_terminal(
            result, threshold, diff_lines,
            files_scanned=files_scanned, quiet=args.quiet,
        )

    # Optional report file.
    if args.report:
        write_report(result, args.report)

    # Exit code
    if result.error:
        sys.exit(2)
    if result.exceeds_threshold(threshold):
        sys.exit(1)
    sys.exit(0)

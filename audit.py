#!/usr/bin/env python3
"""Thin CLI entry point for PwnGuard.

The implementation lives under ``pwnguard/``. This module stays at the
repo root so:

  * ``python3 audit.py …`` (the pre-commit hook, the README CLI
    examples, GitLab CI snippets) keeps working unchanged.
  * The bundled test suite can ``import audit`` and reach the same
    public surface it always did, including module-level helpers
    intentionally exposed for testing (``_sanitize``, ``_is_safe_ref``,
    monitor-state helpers, render-row helpers).

Anything new should land inside ``pwnguard/`` and only be re-exported
here if a caller outside the package needs it.
"""

# Public surface (data + dataclasses) ---------------------------------------
from pwnguard import __version__, ui  # noqa: F401 - ui is touched by tests
from pwnguard.constants import (  # noqa: F401
    MONITOR_STATE_FILENAME,
    MONITOR_STATE_VERSION,
)
from pwnguard.models import AuditResult, Finding, Observation  # noqa: F401

# Diff + anchor + parser primitives -----------------------------------------
from pwnguard.anchors import resolve_anchors, wrap_diff  # noqa: F401
from pwnguard.diff import (  # noqa: F401
    _looks_like_unified_diff,
    _truncate_diff,
    filter_diff,
    parse_diff_files,
    parse_diff_lines,
    split_diff_per_file,
)
from pwnguard.parser import (  # noqa: F401
    _escape_unescaped_inner_quotes,
    _normalize_anchor,
    parse_response,
)
from pwnguard.prompts import build_system_prompt  # noqa: F401
from pwnguard.security import _is_safe_ref, _sanitize  # noqa: F401

# Remote fetching ------------------------------------------------------------
from pwnguard.fetchers import (  # noqa: F401
    _build_commit_url,
    _format_relative_time,
    fetch_from_url,
    list_commits_from_url,
)

# Rendering helpers tested directly -----------------------------------------
from pwnguard.render import (  # noqa: F401
    _print_finding_block,
    _truncate_visible,
)
from pwnguard.review import _render_review_row  # noqa: F401

# Monitor state + dashboard helpers tested directly -------------------------
from pwnguard.monitor import (  # noqa: F401
    _build_monitor_items,
    _deserialize_diff_lines,
    _ensure_repo_entries,
    _load_monitor_state,
    _monitor_state_path,
    _ordered_monitor_keys,
    _repo_key,
    _run_monitor_refresh,
    _save_monitor_state,
    _serialize_diff_lines,
    _summarise_refresh,
)


if __name__ == "__main__":
    from pwnguard.cli import main
    main()

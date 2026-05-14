"""Diff parsing, filtering, chunking, and the cheap token estimator.

Inputs into this module are always unified-diff strings produced
either by ``git diff`` or by ``fetchers`` (after reconstructing
GitLab's commit-diff API shape into the same on-the-wire format).
"""

import fnmatch
import os
import re
import subprocess
import sys
from typing import Optional

from pwnguard.constants import FETCH_TIMEOUT, GIT_TIMEOUT
from pwnguard.security import _is_safe_ref


def estimate_tokens(text: str) -> int:
    """Rough token count for English+code (~4 chars / token)."""
    return len(text) // 4


def get_staged_diff() -> str:
    """Get the diff of staged files (for pre-commit hook)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--diff-filter=ACMR", "-U3"],
        capture_output=True, text=True, timeout=GIT_TIMEOUT,
    )
    if result.returncode != 0:
        sys.exit(f"git diff failed: {result.stderr.strip()}")
    return result.stdout


def get_mr_diff() -> str:
    """Get the diff against the MR target branch (for CI)."""
    # Detect target branch from GitLab CI environment (attacker-influenced).
    target = os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")
    if not _is_safe_ref(target):
        sys.exit(f"Refusing unsafe target branch name: {target!r}")

    # Fetch target branch. `--` separates options from the ref to prevent
    # argument injection even if _is_safe_ref ever loosens.
    fetch = subprocess.run(
        ["git", "fetch", "origin", "--", target],
        capture_output=True, text=True, timeout=FETCH_TIMEOUT,
    )
    if fetch.returncode != 0:
        # Fail loudly: a silent failure here would produce an empty diff
        # and "no findings" -> commit passes -> false sense of safety.
        sys.exit(f"git fetch origin {target} failed: {fetch.stderr.strip()}")

    result = subprocess.run(
        ["git", "diff", f"origin/{target}...HEAD", "--diff-filter=ACMR", "-U3"],
        capture_output=True, text=True, timeout=FETCH_TIMEOUT,
    )
    if result.returncode != 0:
        sys.exit(f"git diff failed: {result.stderr.strip()}")
    return result.stdout


def get_file_contents(files: list, max_size_kb: int) -> str:
    """Read specific files and format as a real unified diff (manual mode).

    Emits a proper ``diff --git`` header, a ``@@`` hunk header sized to
    the file, and prefixes every content line with ``+`` so the output
    is parseable by both filter_diff() (for ignore/language filtering)
    AND parse_diff_lines() (for the affected-code-block lookup used in
    the renderer). Without the ``+`` prefix, parse_diff_lines records
    zero lines for manual-mode scans and the affected block disappears
    from the report.
    """
    output = []
    max_bytes = max_size_kb * 1024
    for filepath in files:
        if not os.path.exists(filepath):
            continue
        # Respect max_file_size_kb so an oversized file doesn't blow up the prompt.
        size = os.path.getsize(filepath)
        if size > max_bytes:
            note = f"[SKIPPED: file {size // 1024} KB exceeds max_file_size_kb={max_size_kb}]"
            output.append(
                f"diff --git a/{filepath} b/{filepath}\n"
                f"--- /dev/null\n+++ b/{filepath}\n"
                f"@@ -0,0 +1,1 @@\n"
                f"+{note}"
            )
            continue
        with open(filepath) as f:
            content = f.read()
        lines = content.splitlines()
        if not lines:
            output.append(
                f"diff --git a/{filepath} b/{filepath}\n"
                f"--- /dev/null\n+++ b/{filepath}\n"
            )
            continue
        plus_lines = "\n".join(f"+{line}" for line in lines)
        output.append(
            f"diff --git a/{filepath} b/{filepath}\n"
            f"--- /dev/null\n+++ b/{filepath}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n"
            f"{plus_lines}"
        )
    return "\n".join(output)


def parse_diff_files(diff: str) -> list:
    """Extract file paths from a unified diff."""
    files = []
    for line in diff.split("\n"):
        if line.startswith("+++ b/"):
            files.append(line[6:])
    return files


def split_diff_per_file(diff: str) -> list:
    """Split a unified diff at `diff --git` boundaries.

    Returns a list of (filename, chunk_text) tuples, one per file. Used
    by --chunk-per-file to scan each file separately when the full diff
    would overflow a local model's context window. Each chunk is a
    self-contained mini-diff starting with its own `diff --git` header.
    """
    chunks = []
    current_lines = []
    current_file: Optional[str] = None
    for line in diff.split("\n"):
        if line.startswith("diff --git"):
            if current_lines:
                chunks.append((current_file or "unknown", "\n".join(current_lines)))
            current_lines = [line]
            parts = line.split(" b/")
            current_file = parts[-1] if len(parts) > 1 else "unknown"
        else:
            current_lines.append(line)
    if current_lines:
        chunks.append((current_file or "unknown", "\n".join(current_lines)))
    return chunks


def _split_file_chunk_by_hunks(file_chunk: str, max_tokens: int) -> list:
    """Split one file's diff at hunk (`@@`) boundaries when it's too big.

    A unified diff for a single file is structured as:
        diff --git ... / --- ... / +++ ...   <- file header (3 lines)
        @@ -A,B +C,D @@                       <- hunk header
        ... hunk content ...
        @@ -E,F +G,H @@                       <- next hunk header
        ... hunk content ...

    This function repeats the file header at the start of every sub-chunk
    so each one parses as a self-contained mini-diff. Hunks are grouped
    greedily up to ``max_tokens`` per sub-chunk. A single hunk that
    exceeds ``max_tokens`` on its own gets its own sub-chunk anyway -
    we don't split inside hunks because that would break the @@ line
    arithmetic.
    """
    lines = file_chunk.split("\n")

    # The file header is everything before the first `@@`. If there's no
    # `@@` at all (binary diff, pure rename, etc.) return the chunk as-is.
    header_end = None
    for i, line in enumerate(lines):
        if line.startswith("@@"):
            header_end = i
            break
    if header_end is None:
        return [file_chunk]

    header = "\n".join(lines[:header_end])

    # Group lines into hunks (each starts with `@@` and runs until the
    # next `@@` or end of file).
    hunks = []
    current = []
    for line in lines[header_end:]:
        if line.startswith("@@"):
            if current:
                hunks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        hunks.append("\n".join(current))

    # Greedy pack hunks into sub-chunks under the token budget.
    header_tokens = estimate_tokens(header)
    sub_chunks = []
    current_hunks = []
    current_tokens = header_tokens

    for hunk in hunks:
        hunk_tokens = estimate_tokens(hunk)
        # If adding this hunk would push us over, emit what we have and
        # start a new sub-chunk. If a single hunk alone is over budget,
        # it still goes in alone (we don't slice inside a hunk).
        if current_hunks and current_tokens + hunk_tokens > max_tokens:
            sub_chunks.append(header + "\n" + "\n".join(current_hunks))
            current_hunks = [hunk]
            current_tokens = header_tokens + hunk_tokens
        else:
            current_hunks.append(hunk)
            current_tokens += hunk_tokens

    if current_hunks:
        sub_chunks.append(header + "\n" + "\n".join(current_hunks))

    return sub_chunks


def _chunk_token_budget(backend: str, config: dict) -> int:
    """Per-chunk token budget for the diff portion alone.

    Subtracts the system prompt + response budget + a small safety
    margin from num_ctx so each chunk we send to the model fits with
    room to spare. Only meaningful for Ollama (Claude backends have
    so much context that further sub-splitting is wasteful).
    """
    if backend != "ollama":
        # Claude variants: effectively unlimited; never sub-split.
        return 100_000
    cfg = config.get("ollama", {})
    num_ctx = cfg.get("num_ctx", 4096)
    num_predict = cfg.get("num_predict", 2048)
    # ~1000 tokens for the system prompt + ~100 safety margin. Floor at
    # 1000 so we always at least try with whatever budget we can scrape.
    return max(1000, num_ctx - num_predict - 1100)


def _looks_like_unified_diff(text: str) -> bool:
    """Heuristic: does ``text`` look like the output of ``git diff``?

    True if any line starts with ``diff --git`` or ``+++ b/`` - the two
    headers a normal unified diff always carries. Returns False on
    plain source files, so ``--diff-file foo.py`` fails loudly with a
    precise error instead of producing findings with empty file paths.
    """
    for line in text.splitlines():
        if line.startswith("diff --git") or line.startswith("+++ b/"):
            return True
    return False


def parse_diff_lines(diff: str) -> dict:
    """Map filename -> {line_number: line_content} for added/unchanged lines.

    Used to show the offending line under each finding without re-reading
    the file (and getting a possibly different working-tree version).
    Walks hunk headers (``@@ -a,b +c,d @@``) to know the new-file line
    number, then collects ``+`` and context (`` ``) lines.
    """
    result = {}
    current_file: Optional[str] = None
    current_lineno = 0

    for line in diff.split("\n"):
        if line.startswith("+++ b/"):
            current_file = line[6:]
            result.setdefault(current_file, {})
            current_lineno = 0
        elif line.startswith("@@") and current_file is not None:
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if m:
                # ``current_lineno`` is incremented BEFORE recording, so set
                # it to (start - 1) so the first content line lands on `start`.
                current_lineno = int(m.group(1)) - 1
        elif current_file is not None and line.startswith("+") and not line.startswith("+++"):
            current_lineno += 1
            result[current_file][current_lineno] = line[1:]
        elif current_file is not None and (line.startswith(" ") or line == ""):
            current_lineno += 1
        # Lines starting with '-' don't advance the new-file line counter.

    return result


def _truncate_diff(diff: str, max_lines: int) -> str:
    """Cap a unified diff at max_lines, appending a TRUNCATED marker.

    Pulled out of filter_diff so chunked mode can skip truncation
    entirely - chunked mode handles size by per-file splitting, and
    truncating first would silently drop files past the cap before
    the splitter ever saw them.
    """
    lines = diff.split("\n")
    if len(lines) <= max_lines:
        return diff
    return (
        "\n".join(lines[:max_lines])
        + f"\n\n[TRUNCATED: {len(lines) - max_lines} lines omitted]"
    )


def filter_diff(diff: str, config: dict, *, apply_truncation: bool = True) -> str:
    """Filter diff based on ignore patterns and language focus.

    apply_truncation defaults True for backward compatibility. Chunked
    mode passes apply_truncation=False so the per-file splitter sees
    every file - otherwise files past line max_diff_lines get dropped
    before the chunker can isolate them.
    """
    ignore = config.get("ignore_patterns", [])
    focus = config.get("language_focus", [])

    filtered_chunks = []
    current_chunk = []
    current_file = None
    include = True

    for line in diff.split("\n"):
        if line.startswith("diff --git"):
            # Save previous chunk
            if current_chunk and include:
                filtered_chunks.extend(current_chunk)

            current_chunk = [line]
            # Extract filename
            parts = line.split(" b/")
            current_file = parts[-1] if len(parts) > 1 else ""

            # Check ignore patterns
            include = not any(fnmatch.fnmatch(current_file, p) for p in ignore)

            # Check language focus (if configured). os.path.splitext keeps
            # us free of pathlib for this one suffix-extraction use.
            if include and focus:
                ext = os.path.splitext(current_file)[1].lstrip(".")
                include = ext in focus or not ext

        else:
            current_chunk.append(line)

    # Don't forget last chunk
    if current_chunk and include:
        filtered_chunks.extend(current_chunk)

    result = "\n".join(filtered_chunks)

    if apply_truncation:
        result = _truncate_diff(result, config.get("max_diff_lines", 500))

    return result

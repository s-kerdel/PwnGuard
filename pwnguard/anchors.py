"""Opaque anchor token tagging and resolution.

Replaces fuzzy line-number / snippet matching: each ``+`` (added) and
context (`` ``) line in the diff is prefixed with ``[a<N>]``. The
model is told to echo the bare token back in each finding's
``anchor`` field; the host resolves the token via the table built
during tagging.

Why opaque tokens beat plain line numbers: they have no numeric
semantics the model can drift on, so they can only be copied
verbatim, not regenerated from "where this probably is in the file."
"""

import re
from typing import Optional

from pwnguard.constants import DIFF_WRAPPER_OPEN, DIFF_WRAPPER_CLOSE


def wrap_diff(diff: str) -> tuple:
    """Wrap diff in delimiters, tag content lines with anchor tokens, and
    return both the wrapped text and an anchor lookup table.

    Each ``+`` (added) and context (`` ``) content line is prefixed
    with an opaque token of the form ``[a<N>]`` (e.g. ``[a1]``,
    ``[a42]``). The model is told to echo the bare token back in each
    finding's ``anchor`` field; the returned table maps each token to
    ``(file, line, content, kind, hunk_context)`` so post-parse
    resolution is a single dict lookup. No counting, no fuzzy quote
    matching, no function-name regex fallback.

    Opaque tokens beat the old 5-digit line-number prefix because
    they have no numeric semantics the model can drift on - they can
    only be copied verbatim, not regenerated from "where this
    probably is in the file". The namespace resets per call, which
    is fine because each AI request is parsed against its own table.

    Diff metadata (file headers, hunk headers, removed lines) is left
    untagged: those don't correspond to a new-file position.

    Returns ``(wrapped_text, anchor_table)`` where ``anchor_table`` is
    a ``dict[str, dict]`` keyed by the bare token (no brackets).
    """
    body, anchors = _anchor_diff_lines(diff)
    wrapped = f"{DIFF_WRAPPER_OPEN}\n{body}\n{DIFF_WRAPPER_CLOSE}"
    return wrapped, anchors


def _anchor_diff_lines(diff: str) -> tuple:
    """Walk the diff once, emitting ``[a<N>]`` tokens and building the
    anchor table.

    Replaces the old ``_number_diff_lines`` line-number prefixer. The
    token namespace is a simple incrementing counter (``a1``, ``a2``,
    ...) reset on every call. Removed (``-``) lines, file headers,
    hunk headers, and the ``diff --git`` line stay untagged - the
    model can't anchor a finding to them, so giving them a token
    would only invite hallucinated references.
    """
    out = []
    anchors = {}
    next_id = 1
    current_file: Optional[str] = None
    current_lineno = 0
    current_hunk_context: Optional[str] = None

    # ``git diff`` always emits a trailing newline; ``split("\n")`` then
    # yields a trailing "" that isn't a real content line. Drop it so we
    # don't tag a phantom context anchor past the last real line (which
    # the model could then pick, resolving to an empty-content row).
    lines = diff.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]

    for line in lines:
        if line.startswith("+++ b/"):
            current_file = line[6:]
            current_lineno = 0
            current_hunk_context = None
            out.append(line)
            continue
        if line.startswith("@@"):
            m = re.match(
                r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@\s*(.*)",
                line,
            )
            if m:
                current_lineno = int(m.group(1)) - 1
                ctx = m.group(2).strip()
                current_hunk_context = ctx or None
            out.append(line)
            continue
        # Until we've seen a `+++ b/<file>` header we don't know what
        # file a line belongs to. Skip tagging in that state - emitting
        # tokens with file="" would let the model anchor findings to a
        # blank file and produce findings with no path / no preview
        # (the typical symptom of feeding a non-diff to --diff-file).
        if current_file is None:
            out.append(line)
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current_lineno += 1
            tok = f"a{next_id}"
            next_id += 1
            anchors[tok] = {
                "file": current_file,
                "line": current_lineno,
                "content": line[1:],
                "kind": "added",
                "hunk_context": current_hunk_context,
            }
            out.append(f"[{tok}] {line}")
            continue
        if line.startswith(" ") or line == "":
            current_lineno += 1
            tok = f"a{next_id}"
            next_id += 1
            anchors[tok] = {
                "file": current_file,
                "line": current_lineno,
                "content": line[1:] if line else "",
                "kind": "context",
                "hunk_context": current_hunk_context,
            }
            out.append(f"[{tok}] {line}")
            continue
        # `-` removed lines, `---` headers, `diff --git ...`, etc.
        out.append(line)

    return "\n".join(out), anchors


def resolve_anchors(result, anchor_table: dict) -> int:
    """Resolve each finding's / observation's ``anchor`` token to a real
    location, rewriting ``file``, ``line``, and ``hunk_context``.

    Returns the number of items dropped because their anchor was
    unknown - "loud failure" rather than fuzzy recovery. The host
    should surface the count on stderr so the user sees that a
    fabricated anchor occurred.

    Resolution rules per finding/observation:

    - Anchor present AND in table: rewrite ``file`` / ``line`` /
      ``hunk_context`` from the table entry. Trust the table.
    - Anchor present but NOT in table: model fabricated an anchor.
      Drop the item; do not try fuzzy matching - that's exactly the
      pre-anchor fallback chain we're replacing.
    - Anchor absent: file-level carve-out. Keep the item, leave
      ``file`` as the model supplied it, ``line`` stays None.

    The previous pipeline (``_anchor_findings_by_snippet`` etc.) is
    gone; one O(1) lookup replaces the whole repair chain.
    """
    dropped = 0
    kept_findings = []
    for f in result.findings:
        if f.anchor is None:
            # File-level carve-out: model deliberately omitted anchor
            # and supplied "file" directly. Keep if file is set;
            # otherwise drop (no way to render it).
            if f.file:
                kept_findings.append(f)
            else:
                dropped += 1
            continue
        entry = anchor_table.get(f.anchor)
        if not entry:
            dropped += 1
            continue
        f.file = entry["file"]
        f.line = entry["line"]
        f.hunk_context = entry.get("hunk_context")
        kept_findings.append(f)
    result.findings = kept_findings

    kept_obs = []
    for o in result.observations:
        if o.anchor is None:
            kept_obs.append(o)
            continue
        entry = anchor_table.get(o.anchor)
        if not entry:
            # Drop the observation silently - we don't count these in
            # the "dropped" tally because they're opt-in informational.
            continue
        o.file = entry["file"]
        o.line = entry["line"]
        kept_obs.append(o)
    result.observations = kept_obs

    return dropped

"""Inline finding suppression via ``pwnguard:ignore`` markers.

A developer marks an accepted false positive with a comment in the code
under review; the matching finding is dropped before the gate so it
doesn't block a commit / deploy, while every other finding still counts.
The marker travels in the same diff as the code it excuses, so reviewers
see the reason next to the code and there's no central file to maintain.

Marker forms (anywhere a comment is valid in the language):
  pwnguard:ignore                 bare - drops a finding anchored within
                                  a few lines of the marker.
  pwnguard:ignore CWE-89          file-scoped - drops findings in this
                                  file whose CWE matches.
  pwnguard:ignore "sql injection" file-scoped - drops findings in this
                                  file whose title/description contains
                                  the quoted text (case-insensitive).
Trailing free text (a reason) is allowed and ignored by the matcher.
"""

import re

_MARKER_RE = re.compile(r"pwnguard:ignore\b(.*)", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_QUOTED_RE = re.compile(r"""['"]([^'"]+)['"]""")

# A bare marker matches findings within this many lines, absorbing the
# small line-number drift local models produce.
_BARE_LINE_WINDOW = 3


class _Marker:
    __slots__ = ("line", "cwe", "keyword")

    def __init__(self, line, cwe, keyword):
        self.line = line      # int line number of the marker, or None
        self.cwe = cwe        # "CWE-89" (upper) for a CWE-scoped marker
        self.keyword = keyword  # lowercased substring for a keyword marker

    @property
    def is_bare(self) -> bool:
        return self.cwe is None and self.keyword is None


def _parse_markers(diff_lines: dict) -> dict:
    """Map ``file -> [_Marker]`` from pwnguard:ignore comments in the diff.

    ``diff_lines`` is the per-file ``{line: added-content}`` map already
    built for the scan, so only lines added in this change are searched -
    exactly the comments the developer is introducing.
    """
    out: dict = {}
    for file, lines in (diff_lines or {}).items():
        if not isinstance(lines, dict):
            continue
        for lineno, content in lines.items():
            if not isinstance(content, str):
                continue
            m = _MARKER_RE.search(content)
            if not m:
                continue
            rest = m.group(1)
            cwe_m = _CWE_RE.search(rest)
            cwe = cwe_m.group(0).upper() if cwe_m else None
            keyword = None
            if cwe is None:
                q = _QUOTED_RE.search(rest)
                if q:
                    keyword = q.group(1).strip().lower() or None
            try:
                ln = int(lineno)
            except (TypeError, ValueError):
                ln = None
            out.setdefault(file, []).append(_Marker(ln, cwe, keyword))
    return out


def _finding_suppressed(f, markers: list) -> bool:
    fcwe = (getattr(f, "cwe", None) or "").upper()
    hay = (
        (getattr(f, "title", "") or "") + " " + (getattr(f, "description", "") or "")
    ).lower()
    fline = getattr(f, "line", None)
    for mk in markers:
        if mk.cwe is not None:
            if fcwe and fcwe == mk.cwe:
                return True
        elif mk.keyword is not None:
            if mk.keyword in hay:
                return True
        elif (
            mk.line is not None
            and isinstance(fline, int)
            and abs(mk.line - fline) <= _BARE_LINE_WINDOW
        ):
            return True
    return False


def apply_inline_suppressions(result, diff_lines: dict) -> int:
    """Drop findings matched by a pwnguard:ignore marker in the same file.

    Mutates ``result.findings`` (and sets ``result.suppressed``) and
    returns the number suppressed. A marker only affects findings in its
    own file, so an ignore in one file can't silently hide issues in
    another.
    """
    markers = _parse_markers(diff_lines)
    findings = getattr(result, "findings", None) or []
    if not markers or not findings:
        return 0
    kept = []
    suppressed = 0
    for f in findings:
        file_markers = markers.get(getattr(f, "file", None), [])
        if file_markers and _finding_suppressed(f, file_markers):
            suppressed += 1
        else:
            kept.append(f)
    result.findings = kept
    result.suppressed = getattr(result, "suppressed", 0) + suppressed
    return suppressed

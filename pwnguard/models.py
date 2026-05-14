"""Dataclasses for findings, observations, and aggregated audit results."""

import re
from dataclasses import dataclass, field
from typing import Optional

from pwnguard.constants import SEVERITY_ORDER


@dataclass
class Finding:
    severity: str
    title: str
    file: str
    line: Optional[int]
    description: str
    recommendation: str
    cwe: Optional[str] = None
    confidence: str = "high"
    # Optional short code snippet showing the corrected pattern.
    # Filled by the AI when it can produce a useful 1-2 line example;
    # left None for findings where a code sample doesn't apply
    # (missing annotation, config change, removed dependency, etc.).
    fix_example: Optional[str] = None
    # Hunk context lifted from the diff's `@@` header (the enclosing
    # function / class git auto-attaches when it can detect one).
    # Populated post-parse by resolve_anchors from the anchor table.
    hunk_context: Optional[str] = None
    # Raw anchor token the model returned (e.g. "a8"). The host
    # program resolves this back to (file, line, content) via the
    # per-call anchor table built by wrap_diff; the resolution writes
    # the file / line / hunk_context fields on this dataclass. Left
    # None for file-level findings that use the prompt's no-anchor
    # carve-out (model supplies "file" directly in that case).
    anchor: Optional[str] = None

    def cwe_url(self) -> Optional[str]:
        """Return a MITRE CWE URL if self.cwe parses as CWE-<digits>.

        We only build a link when the ID has the expected shape so a
        hallucinated value like ``CWE-???`` stays as plain text rather
        than a broken link target.
        """
        if not self.cwe:
            return None
        m = re.match(r"\s*CWE-(\d+)\s*$", self.cwe, re.IGNORECASE)
        if not m:
            return None
        return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"


@dataclass
class Observation:
    """A neutral, descriptive observation about a pattern in the diff.

    Deliberately NOT a security validation: the schema and prompt forbid
    phrasing like "this is secure" / "this is safe". The intent is to
    surface patterns the model noticed (parameterised SQL, escaping,
    CSRF token checks, allowlist authz) without giving the developer a
    credential they can wave away real findings with. Opt-in only,
    rendered dim and clearly labelled "informational".
    """
    pattern: str
    file: str
    line: Optional[int]
    note: str
    # Raw anchor token from the model. Resolved post-parse alongside
    # findings; the file / line fields above are populated from it.
    anchor: Optional[str] = None


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    files_scanned: int = 0
    error: Optional[str] = None
    elapsed: float = 0.0  # seconds spent waiting on the AI backend

    @property
    def blocking_findings(self) -> list[Finding]:
        """Only high and medium confidence findings can block commits."""
        return [f for f in self.findings if f.confidence in ("high", "medium")]

    @property
    def max_severity(self) -> int:
        blocking = self.blocking_findings
        if not blocking:
            return 0
        return max(SEVERITY_ORDER.get(f.severity, 0) for f in blocking)

    def exceeds_threshold(self, threshold: str) -> bool:
        return self.max_severity >= SEVERITY_ORDER.get(threshold, 3)

    @property
    def summary(self) -> dict:
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

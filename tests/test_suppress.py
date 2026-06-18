"""Tests for inline pwnguard:ignore finding suppression."""

from pwnguard.models import AuditResult, Finding
from pwnguard.suppress import apply_inline_suppressions


def _finding(file, line, *, cwe=None, title="sqli", severity="HIGH"):
    return Finding(
        severity=severity, title=title, file=file, line=line,
        description="d", recommendation="r", anchor="a", cwe=cwe,
        confidence="high",
    )


def _result(*findings):
    return AuditResult(findings=list(findings))


def test_cwe_marker_suppresses_matching_finding_in_same_file():
    res = _result(_finding("app/db.py", 10, cwe="CWE-89"))
    diff_lines = {"app/db.py": {3: "# pwnguard:ignore CWE-89 - ORM-parameterized"}}
    n = apply_inline_suppressions(res, diff_lines)
    assert n == 1
    assert res.findings == []
    assert res.suppressed == 1


def test_cwe_marker_does_not_touch_other_cwe():
    res = _result(_finding("app/db.py", 10, cwe="CWE-79"))
    diff_lines = {"app/db.py": {3: "// pwnguard:ignore CWE-89"}}
    assert apply_inline_suppressions(res, diff_lines) == 0
    assert len(res.findings) == 1


def test_marker_is_scoped_to_its_own_file():
    res = _result(_finding("app/other.py", 10, cwe="CWE-89"))
    diff_lines = {"app/db.py": {3: "# pwnguard:ignore CWE-89"}}
    assert apply_inline_suppressions(res, diff_lines) == 0
    assert len(res.findings) == 1


def test_keyword_marker_matches_title_substring():
    res = _result(_finding("a.py", 5, title="SQL injection via user_id"))
    diff_lines = {"a.py": {1: '# pwnguard:ignore "sql injection" - false positive'}}
    assert apply_inline_suppressions(res, diff_lines) == 1
    assert res.findings == []


def test_bare_marker_suppresses_finding_within_window():
    res = _result(_finding("a.py", 12, cwe="CWE-89"))
    # Marker at line 10, finding at 12 -> within the +/-3 window.
    diff_lines = {"a.py": {10: "    x = 1  # pwnguard:ignore"}}
    assert apply_inline_suppressions(res, diff_lines) == 1


def test_bare_marker_does_not_suppress_far_finding():
    res = _result(_finding("a.py", 40, cwe="CWE-89"))
    diff_lines = {"a.py": {10: "# pwnguard:ignore"}}
    assert apply_inline_suppressions(res, diff_lines) == 0
    assert len(res.findings) == 1


def test_no_markers_is_a_noop():
    res = _result(_finding("a.py", 5, cwe="CWE-89"))
    assert apply_inline_suppressions(res, {"a.py": {1: "x = 1"}}) == 0
    assert len(res.findings) == 1


def test_partial_suppression_keeps_the_rest():
    res = _result(
        _finding("a.py", 5, cwe="CWE-89"),
        _finding("a.py", 6, cwe="CWE-79"),
    )
    diff_lines = {"a.py": {1: "# pwnguard:ignore CWE-89"}}
    assert apply_inline_suppressions(res, diff_lines) == 1
    assert [f.cwe for f in res.findings] == ["CWE-79"]


def test_marker_match_is_case_insensitive():
    res = _result(_finding("a.py", 5, cwe="cwe-89"))
    diff_lines = {"a.py": {1: "# PwnGuard:Ignore cwe-89"}}
    assert apply_inline_suppressions(res, diff_lines) == 1

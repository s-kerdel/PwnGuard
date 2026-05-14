"""Tests for the opaque-anchor pipeline introduced in v0.1.2.

These guard the wrap_diff / _anchor_diff_lines / resolve_anchors
contract. The whole point of the refactor was to remove silent
mis-location of findings, so any failure here should block release.

Run from the project root: ``pytest tests/`` (or ``python -m pytest``).
"""
import pytest

import audit


# ---------------------------------------------------------------------------
# wrap_diff: tagging behaviour
# ---------------------------------------------------------------------------

def test_wrap_diff_returns_text_and_table(simple_diff):
    wrapped, table = audit.wrap_diff(simple_diff)
    assert "<diff_to_review>" in wrapped
    assert "</diff_to_review>" in wrapped
    assert isinstance(table, dict) and table


def test_added_lines_are_tagged(simple_diff):
    _, table = audit.wrap_diff(simple_diff)
    added = [m for m in table.values() if m["kind"] == "added"]
    assert len(added) == 3
    contents = [m["content"] for m in added]
    assert any("SELECT * FROM users" in c for c in contents)
    assert any("cur.execute(sql)" in c for c in contents)
    assert any("cur.fetchone()" in c for c in contents)


def test_context_lines_are_tagged(simple_diff):
    _, table = audit.wrap_diff(simple_diff)
    ctx = [m for m in table.values() if m["kind"] == "context"]
    assert ctx
    assert any("def authenticate" in m["content"] for m in ctx)


def test_removed_lines_are_not_tagged(simple_diff):
    _, table = audit.wrap_diff(simple_diff)
    for meta in table.values():
        assert "return verify(user, password)" not in meta["content"], (
            "removed (`-`) lines must not be tagged"
        )


def test_diff_metadata_lines_are_not_tagged(simple_diff):
    wrapped, _ = audit.wrap_diff(simple_diff)
    for marker in ("diff --git a/auth.py",
                   "+++ b/auth.py",
                   "@@ -10,3 +10,5 @@"):
        assert marker in wrapped
        # If they had been tagged, the prefix would precede them.
        assert f"[a1] {marker}" not in wrapped
        assert f"[a2] {marker}" not in wrapped


def test_anchor_line_numbers_follow_hunk_arithmetic(simple_diff):
    """@@ -10,3 +10,5 @@ -> first new-file line is 10."""
    _, table = audit.wrap_diff(simple_diff)
    assert sorted(m["line"] for m in table.values()) == [10, 11, 12, 13]


def test_hunk_context_is_captured(simple_diff):
    _, table = audit.wrap_diff(simple_diff)
    for meta in table.values():
        assert meta["hunk_context"] == "def authenticate(user, password):"


def test_tokens_have_letter_digit_shape(simple_diff):
    import re
    wrapped, table = audit.wrap_diff(simple_diff)
    for tok in table:
        assert re.match(r"^a\d+$", tok)
        assert f"[{tok}]" in wrapped


def test_tokens_increment_sequentially(simple_diff):
    _, table = audit.wrap_diff(simple_diff)
    ids = sorted(int(tok[1:]) for tok in table)
    assert ids == list(range(1, len(ids) + 1))


# ---------------------------------------------------------------------------
# wrap_diff: defense-in-depth guard
# ---------------------------------------------------------------------------

def test_source_file_input_produces_empty_table():
    """No +++ b/ header -> no anchors. Protects against ``--diff-file``
    being pointed at a plain source file."""
    php_source = (
        "<?php\n"
        "namespace Demo;\n"
        "\n"
        " * doc comment line starting with space\n"
        "class Foo {\n"
        "    public function bar() { return 1; }\n"
        "}\n"
    )
    _, table = audit.wrap_diff(php_source)
    assert table == {}


def test_binary_only_diff_chunk_produces_empty_table():
    partial = (
        "diff --git a/x.bin b/x.bin\n"
        "Binary files a/x.bin and b/x.bin differ\n"
    )
    _, table = audit.wrap_diff(partial)
    assert table == {}


# ---------------------------------------------------------------------------
# wrap_diff: multi-file diffs
# ---------------------------------------------------------------------------

def test_each_anchor_attributed_to_its_file(multifile_diff):
    _, table = audit.wrap_diff(multifile_diff)
    assert {m["file"] for m in table.values()} == {"a.py", "b.py"}


def test_line_arithmetic_resets_per_file(multifile_diff):
    _, table = audit.wrap_diff(multifile_diff)
    per_file: dict = {}
    for meta in table.values():
        per_file.setdefault(meta["file"], []).append(meta["line"])
    assert sorted(per_file["a.py"]) == [1, 2]
    assert sorted(per_file["b.py"]) == [5, 6]


# ---------------------------------------------------------------------------
# _normalize_anchor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("a8", "a8"),
    ("[a8]", "a8"),
    (8, "a8"),
    ("8", "a8"),
    ("  a8  ", "a8"),
])
def test_normalize_anchor_canonicalises(raw, expected):
    assert audit._normalize_anchor(raw) == expected


@pytest.mark.parametrize("raw", [
    None, "", "   ", "a", "foo", "8a", "a8b9", "a-8", "0x42",
])
def test_normalize_anchor_rejects_garbage(raw):
    assert audit._normalize_anchor(raw) is None


# ---------------------------------------------------------------------------
# resolve_anchors
# ---------------------------------------------------------------------------

@pytest.fixture
def anchor_table():
    return {
        "a1": {"file": "x.py", "line": 10, "content": "code1",
               "kind": "added", "hunk_context": "def foo():"},
        "a2": {"file": "x.py", "line": 11, "content": "code2",
               "kind": "added", "hunk_context": "def foo():"},
        "a3": {"file": "y.py", "line": 42, "content": "code3",
               "kind": "context", "hunk_context": None},
    }


def _finding(anchor=None, file=""):
    return audit.Finding(
        severity="HIGH", title="t", file=file, line=None,
        description="d", recommendation="r", anchor=anchor,
    )


def test_valid_anchor_populates_file_line_and_hunk(anchor_table):
    result = audit.AuditResult()
    result.findings = [_finding(anchor="a1")]
    dropped = audit.resolve_anchors(result, anchor_table)
    assert dropped == 0
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.file == "x.py"
    assert f.line == 10
    assert f.hunk_context == "def foo():"


def test_fabricated_anchor_is_dropped_with_counter(anchor_table):
    result = audit.AuditResult()
    result.findings = [
        _finding(anchor="a1"),
        _finding(anchor="a999"),
        _finding(anchor="a2"),
    ]
    dropped = audit.resolve_anchors(result, anchor_table)
    assert dropped == 1
    assert [f.anchor for f in result.findings] == ["a1", "a2"]


def test_file_level_finding_without_anchor_is_kept(anchor_table):
    result = audit.AuditResult()
    result.findings = [_finding(anchor=None, file="config.yaml")]
    dropped = audit.resolve_anchors(result, anchor_table)
    assert dropped == 0
    assert result.findings[0].file == "config.yaml"
    assert result.findings[0].line is None


def test_finding_without_anchor_or_file_is_dropped(anchor_table):
    result = audit.AuditResult()
    result.findings = [_finding(anchor=None, file="")]
    dropped = audit.resolve_anchors(result, anchor_table)
    assert dropped == 1
    assert result.findings == []


def test_cross_file_anchor_disambiguation(anchor_table):
    result = audit.AuditResult()
    result.findings = [_finding(anchor="a1"), _finding(anchor="a3")]
    audit.resolve_anchors(result, anchor_table)
    assert [f.file for f in result.findings] == ["x.py", "y.py"]
    assert [f.line for f in result.findings] == [10, 42]


def test_observations_resolve_same_way(anchor_table):
    result = audit.AuditResult()
    result.observations = [
        audit.Observation(pattern="p", file="", line=None, note="n",
                          anchor="a1"),
        audit.Observation(pattern="p", file="", line=None, note="n",
                          anchor="a999"),  # fabricated, dropped silently
        audit.Observation(pattern="p", file="", line=None, note="n",
                          anchor=None),    # anchor-less, kept
    ]
    audit.resolve_anchors(result, anchor_table)
    assert len(result.observations) == 2
    assert result.observations[0].file == "x.py"
    assert result.observations[0].line == 10


# ---------------------------------------------------------------------------
# End-to-end: build a diff, simulate a model response, resolve back
# ---------------------------------------------------------------------------

def test_full_roundtrip(simple_diff):
    _, table = audit.wrap_diff(simple_diff)
    target = next(tok for tok, m in table.items()
                  if "SELECT" in m["content"])
    fake_response = (
        '{"findings": [{"severity": "HIGH", "confidence": "high", '
        f'"anchor": "{target}", "title": "sql injection", '
        '"description": "interpolated user into SQL", '
        '"recommendation": "use a parameterised query"}]}'
    )
    result = audit.parse_response(fake_response)
    assert len(result.findings) == 1
    dropped = audit.resolve_anchors(result, table)
    assert dropped == 0
    f = result.findings[0]
    assert f.file == "auth.py"
    assert f.line == 11
    assert f.hunk_context == "def authenticate(user, password):"

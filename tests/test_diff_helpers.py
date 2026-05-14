"""Tests for diff input validation + parsing helpers.

These guard the validation that protects --diff-file and --from-url
from silently scanning non-diff input.
"""
import pytest

import audit


SAMPLE_DIFF = """diff --git a/a.py b/a.py
index aaaaaaa..bbbbbbb 100644
--- a/a.py
+++ b/a.py
@@ -1,1 +1,2 @@
 import os
+import sys
diff --git a/b.py b/b.py
index ccccccc..ddddddd 100644
--- a/b.py
+++ b/b.py
@@ -5,1 +5,2 @@
 def foo():
+    pass
"""


# ---------------------------------------------------------------------------
# _looks_like_unified_diff
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    SAMPLE_DIFF,
    # Just the +++/--- pair (some platforms strip `diff --git`).
    "--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n hello\n",
])
def test_unified_diff_is_accepted(text):
    assert audit._looks_like_unified_diff(text)


@pytest.mark.parametrize("text", [
    # PHP source
    "<?php\nnamespace Demo;\nclass Foo { public function bar() {} }\n",
    # Python source
    "def foo():\n    return 1\n\n# comment\n",
    # HTML error page (rate-limited fetch)
    "<!DOCTYPE html>\n<html><body><h1>401 Unauthorized</h1></body></html>\n",
    # Empty / whitespace
    "",
    "   \n\n  \t\n",
])
def test_non_diff_input_is_rejected(text):
    assert not audit._looks_like_unified_diff(text)


# ---------------------------------------------------------------------------
# split_diff_per_file
# ---------------------------------------------------------------------------

def test_split_returns_one_chunk_per_file():
    chunks = audit.split_diff_per_file(SAMPLE_DIFF)
    assert [fn for fn, _ in chunks] == ["a.py", "b.py"]


def test_each_chunk_is_self_contained():
    for filename, body in audit.split_diff_per_file(SAMPLE_DIFF):
        assert "diff --git" in body, f"chunk for {filename} missing diff --git"
        assert f"+++ b/{filename}" in body, (
            f"chunk for {filename} missing +++ header"
        )


def test_split_single_file_diff():
    single = (
        "diff --git a/only.py b/only.py\n"
        "--- a/only.py\n"
        "+++ b/only.py\n"
        "@@ -1,1 +1,2 @@\n"
        " a\n"
        "+b\n"
    )
    chunks = audit.split_diff_per_file(single)
    assert len(chunks) == 1
    assert chunks[0][0] == "only.py"


# ---------------------------------------------------------------------------
# parse_diff_lines: feeds the ±3 code-preview window
#
# Despite the historical docstring ("added/unchanged"), the function
# only stores the ``+`` (added) lines. Context lines advance the line
# counter so the line numbers stay correct, but only added lines land
# in the returned dict. These tests pin that behaviour.
# ---------------------------------------------------------------------------

def test_parse_diff_lines_stores_only_added_lines():
    result = audit.parse_diff_lines(SAMPLE_DIFF)
    assert set(result) == {"a.py", "b.py"}
    # Each hunk in SAMPLE_DIFF adds exactly one line.
    assert len(result["a.py"]) == 1
    assert len(result["b.py"]) == 1


def test_parse_diff_lines_assigns_correct_line_numbers():
    result = audit.parse_diff_lines(SAMPLE_DIFF)
    # a.py: @@ -1,1 +1,2 @@ -> the added `+import sys` lands on line 2.
    assert list(result["a.py"]) == [2]
    assert result["a.py"][2] == "import sys"
    # b.py: @@ -5,1 +5,2 @@ -> the added `+    pass` lands on line 6.
    assert list(result["b.py"]) == [6]
    assert result["b.py"][6] == "    pass"


def test_parse_diff_lines_excludes_removed_lines():
    diff = (
        "diff --git a/x.py b/x.py\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,3 +1,2 @@\n"
        " keep\n"
        "-drop\n"
        "+add\n"
    )
    result = audit.parse_diff_lines(diff)
    contents = list(result["x.py"].values())
    # Only the added line is stored. ``keep`` is context (advances the
    # counter, not stored) and ``drop`` is removed (does neither).
    assert contents == ["add"]


# ---------------------------------------------------------------------------
# parse_diff_files
# ---------------------------------------------------------------------------

def test_parse_diff_files_lists_all():
    assert set(audit.parse_diff_files(SAMPLE_DIFF)) == {"a.py", "b.py"}


def test_parse_diff_files_empty_returns_empty():
    assert audit.parse_diff_files("") == []

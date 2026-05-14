"""Shared pytest setup.

Puts the project root on sys.path so the test files can ``import audit``
without an install step. Also provides a few small fixtures used by
more than one test module.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit  # noqa: E402  (must come after the sys.path insert)


SIMPLE_DIFF = """diff --git a/auth.py b/auth.py
index 1111111..2222222 100644
--- a/auth.py
+++ b/auth.py
@@ -10,3 +10,5 @@ def authenticate(user, password):
 def authenticate(user, password):
-    return verify(user, password)
+    sql = "SELECT * FROM users WHERE name='" + user + "'"
+    cur.execute(sql)
+    return cur.fetchone()
"""


MULTIFILE_DIFF = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,1 +1,2 @@
 import os
+import sys
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -5,1 +5,2 @@
 def foo():
+    pass
"""


@pytest.fixture
def simple_diff() -> str:
    return SIMPLE_DIFF


@pytest.fixture
def multifile_diff() -> str:
    return MULTIFILE_DIFF


@pytest.fixture
def restore_term_width():
    """Yield a setter that pins ui.term_width and is undone after the test."""
    original = audit.ui.term_width

    def _set(width: int) -> None:
        audit.ui.term_width = lambda w=width: w

    yield _set
    audit.ui.term_width = original

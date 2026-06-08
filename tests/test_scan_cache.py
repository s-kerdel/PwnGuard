"""Tests for the --cached scan cache.

The cache lets a follow-up `--review --cached` reuse the hook's scan
without re-hitting the AI. These pin the two properties that keep it
safe: an exact-key round-trip must reconstruct the result, and any
mismatch / corruption must be a silent miss (never an error, never a
stale hit for a different diff).
"""
import json
from types import SimpleNamespace

import pytest

from pwnguard import scan
from pwnguard.models import AuditResult, Finding, Observation


@pytest.fixture
def cache_file(tmp_path, monkeypatch):
    """Point the cache at a tmp file instead of a real .git/ dir."""
    path = tmp_path / "pwnguard-scan-cache.json"
    monkeypatch.setattr(scan, "_scan_cache_path", lambda: str(path))
    return path


def _result() -> AuditResult:
    r = AuditResult()
    r.findings = [
        Finding(
            severity="HIGH", title="SQLi", file="a.py", line=4,
            description="d", recommendation="r", cwe="CWE-89",
            confidence="high", fix_example="use params",
        ),
    ]
    r.observations = [
        Observation(pattern="escaping", file="b.py", line=2, note="ok"),
    ]
    r.files_scanned = 2
    r.elapsed = 1.5
    return r


# --- serialization round-trip ------------------------------------------

def test_result_dict_round_trip_preserves_fields():
    original = _result()
    rebuilt = scan._result_from_dict(scan._result_to_dict(original))
    assert rebuilt.findings == original.findings
    assert rebuilt.observations == original.observations
    assert rebuilt.files_scanned == 2
    assert rebuilt.elapsed == 1.5


# --- store / load ------------------------------------------------------

def test_store_then_load_hit_returns_tuple(cache_file):
    diff = "diff --git a/a.py b/a.py\n@@ -1 +1 @@\n-old\n+new\n"
    scan._store_scan_cache("key1", diff, _result())
    hit = scan._load_scan_cache("key1")
    assert hit is not None
    result, cached_diff, diff_lines, files = hit
    assert cached_diff == diff
    assert result.findings[0].title == "SQLi"
    assert isinstance(diff_lines, dict)


def test_load_with_wrong_key_is_miss(cache_file):
    scan._store_scan_cache("key1", "diff", _result())
    assert scan._load_scan_cache("other") is None


def test_load_missing_file_is_miss(cache_file):
    assert scan._load_scan_cache("key1") is None


def test_load_corrupt_file_is_miss(cache_file):
    cache_file.write_text("{not json")
    assert scan._load_scan_cache("key1") is None


def test_load_version_mismatch_is_miss(cache_file):
    cache_file.write_text(json.dumps({"version": 999, "key": "key1", "diff": "", "result": {}}))
    assert scan._load_scan_cache("key1") is None


def test_store_skips_errored_scans(cache_file):
    # A transient backend error must not be cached, else --cached replays
    # it instead of retrying.
    errored = AuditResult()
    errored.error = "backend timeout"
    scan._store_scan_cache("key1", "diff", errored)
    assert not cache_file.exists()
    assert scan._load_scan_cache("key1") is None


def test_store_is_noop_when_not_in_repo(monkeypatch):
    monkeypatch.setattr(scan, "_scan_cache_path", lambda: None)
    # Must not raise.
    scan._store_scan_cache("key1", "diff", _result())
    assert scan._load_scan_cache("key1") is None


# --- key sensitivity ---------------------------------------------------

def test_key_changes_with_diff_backend_and_model():
    cfg = {"ollama": {"model": "m1"}}
    base = scan._scan_cache_key("diffA", "ollama", cfg)
    assert scan._scan_cache_key("diffB", "ollama", cfg) != base
    assert scan._scan_cache_key("diffA", "claude-api", cfg) != base
    assert scan._scan_cache_key("diffA", "ollama", {"ollama": {"model": "m2"}}) != base
    # Same inputs -> stable key.
    assert scan._scan_cache_key("diffA", "ollama", cfg) == base


def test_key_changes_with_pwnguard_version(monkeypatch):
    cfg = {"ollama": {"model": "m1"}}
    base = scan._scan_cache_key("diffA", "ollama", cfg)
    # An upgrade that bumps __version__ must invalidate old entries.
    monkeypatch.setattr(scan, "__version__", "0.0.0-test")
    assert scan._scan_cache_key("diffA", "ollama", cfg) != base


# --- cacheable scoping (staged-diff path only) -------------------------

def test_is_cacheable_only_for_staged_diff():
    assert scan._is_cacheable(SimpleNamespace(mode="hook")) is True
    assert scan._is_cacheable(SimpleNamespace(mode="manual", files=None)) is True
    # Non-staged sources opt out of the cache entirely.
    assert scan._is_cacheable(SimpleNamespace(from_url="http://x")) is False
    assert scan._is_cacheable(SimpleNamespace(diff_file="x.diff")) is False
    assert scan._is_cacheable(SimpleNamespace(mode="manual", files=["a.py"])) is False
    assert scan._is_cacheable(SimpleNamespace(mode="ci")) is False
    assert scan._is_cacheable(SimpleNamespace(mr_diff=True)) is False

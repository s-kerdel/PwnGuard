"""Tests for monitor state load / save / sanitize.

The state file is the only persistence path for monitor mode. A
regression here either loses cached findings (annoying) or fails to
strip control chars on load (security-relevant if a tampered cache
contains ANSI escapes).
"""
import json
import os
import stat

import pytest

import audit


# ---------------------------------------------------------------------------
# _repo_key
# ---------------------------------------------------------------------------

def test_repo_key_combines_url_and_branch():
    assert audit._repo_key(
        "https://gitlab.com/g/p", "main"
    ) == "https://gitlab.com/g/p@main"


def test_repo_key_strips_trailing_slash():
    assert audit._repo_key(
        "https://gitlab.com/g/p/", "main"
    ) == "https://gitlab.com/g/p@main"


def test_repo_key_disambiguates_branches():
    a = audit._repo_key("https://gitlab.com/g/p", "main")
    b = audit._repo_key("https://gitlab.com/g/p", "develop")
    assert a != b


# ---------------------------------------------------------------------------
# _load_monitor_state
# ---------------------------------------------------------------------------

def test_load_missing_file_returns_skeleton(tmp_path):
    path = str(tmp_path / "no-such-file.json")
    state = audit._load_monitor_state(path)
    assert state == {"version": audit.MONITOR_STATE_VERSION, "repos": {}}


def test_load_malformed_file_returns_skeleton(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{ this is not json")
    state = audit._load_monitor_state(str(path))
    assert state["repos"] == {}


def test_load_wrong_shape_returns_skeleton(tmp_path):
    path = tmp_path / "wrong-shape.json"
    path.write_text(json.dumps([1, 2, 3]))  # list, not dict
    state = audit._load_monitor_state(str(path))
    assert state["repos"] == {}


def test_load_preserves_well_formed_v2_state(tmp_path):
    """A v2 file (commits already present) round-trips untouched - the
    migration is a no-op for it."""
    path = tmp_path / "state.json"
    state = {
        "version": 2,
        "repos": {
            "https://gitlab.com/g/p@main": {
                "name": "p",
                "url": "https://gitlab.com/g/p",
                "branch": "main",
                "last_audited_sha": "abc1234",
                "last_viewed_sha":  "abc1234",
                "head_sha": "abc1234",
                "audited_at": "2026-05-15T09:14:00+00:00",
                "commits": {
                    "abc1234": {
                        "sha": "abc1234",
                        "date": None,
                        "audited_at": "2026-05-15T09:14:00+00:00",
                        "findings": [],
                        "diff_lines": {},
                    },
                },
                "order": ["abc1234"],
            }
        },
    }
    path.write_text(json.dumps(state))
    loaded = audit._load_monitor_state(str(path))
    assert loaded == state


# ---------------------------------------------------------------------------
# v1 -> v2 migration
# ---------------------------------------------------------------------------

def test_migrate_v1_wraps_findings_into_a_commit(tmp_path):
    """An audited v1 entry becomes a single-commit v2 cache; the flat
    findings / diff_lines / last_audited_commit_date fields move under
    commits[last_audited_sha]."""
    path = tmp_path / "v1.json"
    v1 = {
        "version": 1,
        "repos": {
            "k": {
                "name": "n", "url": "u", "branch": "b",
                "last_audited_sha": "abc1234",
                "last_viewed_sha": "abc1234",
                "last_audited_commit_date": "2026-05-10T00:00:00Z",
                "audited_at": "2026-05-15T09:14:00+00:00",
                "findings": [{"severity": "HIGH", "title": "t"}],
                "diff_lines": {"f.py": {"10": "code"}},
            }
        },
    }
    path.write_text(json.dumps(v1))
    loaded = audit._load_monitor_state(str(path))

    assert loaded["version"] == 2
    entry = loaded["repos"]["k"]
    # Flat fields are gone; the commit cache carries them now.
    assert "findings" not in entry
    assert "diff_lines" not in entry
    assert entry["head_sha"] == "abc1234"
    assert entry["order"] == ["abc1234"]
    rec = entry["commits"]["abc1234"]
    assert rec["date"] == "2026-05-10T00:00:00Z"
    assert rec["findings"][0]["title"] == "t"
    assert rec["diff_lines"] == {"f.py": {"10": "code"}}


def test_migrate_v1_placeholder_gets_empty_commit_cache(tmp_path):
    """A never-audited v1 placeholder (no SHA) just gains empty
    commits / order, no synthetic commit."""
    path = tmp_path / "v1.json"
    v1 = {
        "version": 1,
        "repos": {
            "k": {
                "name": "n", "url": "u", "branch": "b",
                "last_audited_sha": None,
                "last_viewed_sha": None,
                "findings": [],
            }
        },
    }
    path.write_text(json.dumps(v1))
    entry = audit._load_monitor_state(str(path))["repos"]["k"]
    assert entry["commits"] == {}
    assert entry["order"] == []
    assert entry["head_sha"] is None


def test_migrate_is_idempotent_for_v2_entries():
    """Re-running the migration on a v2 entry leaves the commit cache
    untouched."""
    state = {
        "version": 2,
        "repos": {
            "k": {
                "name": "n", "url": "u", "branch": "b",
                "last_audited_sha": "abc",
                "commits": {"abc": {"sha": "abc", "findings": [{"title": "keep"}]}},
                "order": ["abc"],
                "head_sha": "abc",
            }
        },
    }
    out = audit._migrate_state_v1_to_v2(state)
    assert out["repos"]["k"]["commits"]["abc"]["findings"][0]["title"] == "keep"
    assert out["repos"]["k"]["order"] == ["abc"]


# ---------------------------------------------------------------------------
# _sanitize_loaded_state (belt-and-braces against tampered cache)
# ---------------------------------------------------------------------------

def test_load_sanitizes_ansi_escape_in_findings(tmp_path):
    """Sanitisation reaches findings nested under the per-commit cache,
    whether they arrive via migration (v1) or natively (v2)."""
    path = tmp_path / "tampered.json"
    state = {
        "version": 1,
        "repos": {
            "https://gitlab.com/g/p@main": {
                "name": "p",
                "url": "https://gitlab.com/g/p",
                "branch": "main",
                "last_audited_sha": "abc",
                "last_viewed_sha": "abc",
                "audited_at": "2026-05-15T09:14:00+00:00",
                "findings": [{
                    "severity": "HIGH",
                    "title": "\x1b[31mmalicious title\x1b[0m",
                    "description": "ok",
                    "recommendation": "ok",
                    "file": "x.py",
                    "line": 1,
                    "anchor": "a1",
                }],
            }
        },
    }
    path.write_text(json.dumps(state))
    loaded = audit._load_monitor_state(str(path))
    rec = loaded["repos"]["https://gitlab.com/g/p@main"]["commits"]["abc"]
    title = rec["findings"][0]["title"]
    assert "\x1b" not in title
    assert "malicious title" in title


def test_load_sanitizes_ansi_escape_in_shas(tmp_path):
    """Pointer SHAs (repo header) and the per-commit SHA (commit row)
    render raw via _format_short_sha, so a tampered file must not be
    able to inject an ANSI escape through them."""
    path = tmp_path / "tampered.json"
    state = {
        "version": 2,
        "repos": {
            "k": {
                "name": "p", "url": "u", "branch": "main",
                "last_audited_sha": "abc\x1b[31m",
                "last_viewed_sha": "abc",
                "head_sha": "abc\x1b[0m",
                "commits": {
                    "abc": {
                        "sha": "abc\x1b[31mevil", "findings": [],
                        "diff_lines": {},
                    },
                },
                "order": ["abc"],
            }
        },
    }
    path.write_text(json.dumps(state))
    e = audit._load_monitor_state(str(path))["repos"]["k"]
    assert "\x1b" not in e["last_audited_sha"]
    assert "\x1b" not in e["head_sha"]
    assert "\x1b" not in e["commits"]["abc"]["sha"]


def test_load_sanitizes_ansi_escape_in_cached_diff_lines(tmp_path):
    """Cached diff content (untrusted upstream data) is scrubbed too."""
    path = tmp_path / "tampered.json"
    state = {
        "version": 2,
        "repos": {
            "k": {
                "name": "p", "url": "u", "branch": "main",
                "last_audited_sha": "abc", "head_sha": "abc",
                "commits": {
                    "abc": {
                        "sha": "abc", "findings": [],
                        "diff_lines": {"x.py": {"1": "\x1b[31mevil\x1b[0m"}},
                    },
                },
                "order": ["abc"],
            }
        },
    }
    path.write_text(json.dumps(state))
    loaded = audit._load_monitor_state(str(path))
    content = loaded["repos"]["k"]["commits"]["abc"]["diff_lines"]["x.py"]["1"]
    assert "\x1b" not in content
    assert "evil" in content


# ---------------------------------------------------------------------------
# _save_monitor_state
# ---------------------------------------------------------------------------

def test_save_creates_readable_file(tmp_path):
    path = str(tmp_path / "state.json")
    state = {"repos": {"key": {"name": "n", "findings": []}}}
    audit._save_monitor_state(state, path)
    assert os.path.exists(path)
    reloaded = json.loads(open(path).read())
    assert reloaded["repos"]["key"]["name"] == "n"


def test_save_sets_owner_only_permissions_on_unix(tmp_path):
    if os.name == "nt":
        pytest.skip("permission bits don't apply on Windows")
    path = str(tmp_path / "state.json")
    audit._save_monitor_state({"repos": {}}, path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    # 0600 = owner read/write, no group, no other.
    assert mode & 0o077 == 0, f"world / group bits leaked: {oct(mode)}"


def test_save_then_load_roundtrips(tmp_path):
    path = str(tmp_path / "state.json")
    state = {
        "version": 2,
        "repos": {
            "k": {
                "name": "n", "url": "u", "branch": "b",
                "last_audited_sha": "abc",
                "last_viewed_sha":  "abc",
                "head_sha": "abc",
                "audited_at": "2026-05-15T09:14:00+00:00",
                "commits": {
                    "abc": {
                        "sha": "abc", "date": None,
                        "audited_at": "2026-05-15T09:14:00+00:00",
                        "findings": [{
                            "severity": "HIGH", "title": "t", "description": "d",
                            "recommendation": "r", "file": "f", "line": 1,
                            "anchor": "a1",
                        }],
                        "diff_lines": {},
                    },
                },
                "order": ["abc"],
            }
        },
    }
    audit._save_monitor_state(state, path)
    loaded = audit._load_monitor_state(path)
    assert loaded["repos"]["k"]["commits"]["abc"]["findings"][0]["title"] == "t"
    assert loaded["repos"]["k"]["last_audited_sha"] == "abc"


# ---------------------------------------------------------------------------
# _monitor_state_path
# ---------------------------------------------------------------------------

def test_state_path_defaults_to_cwd_dotfile(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = audit._monitor_state_path({})
    assert path == str(tmp_path / audit.MONITOR_STATE_FILENAME)


def test_state_path_respects_custom_override(tmp_path):
    custom = str(tmp_path / "custom-cache.json")
    path = audit._monitor_state_path({
        "monitor": {"state_file": custom},
    })
    assert path == custom


# ---------------------------------------------------------------------------
# _new_commit_shas: the "checked vs new" boundary (last_viewed_sha)
# ---------------------------------------------------------------------------

def test_new_commit_shas_splits_on_viewed_pointer():
    # order is newest-first; everything ahead of last_viewed is new.
    entry = {"order": ["c3", "c2", "c1", "c0"], "last_viewed_sha": "c1"}
    assert audit._new_commit_shas(entry) == {"c3", "c2"}


def test_new_commit_shas_all_new_when_viewed_is_newest():
    entry = {"order": ["c2", "c1"], "last_viewed_sha": "c2"}
    assert audit._new_commit_shas(entry) == set()


def test_new_commit_shas_none_viewed_means_all_new():
    entry = {"order": ["c2", "c1"], "last_viewed_sha": None}
    assert audit._new_commit_shas(entry) == {"c2", "c1"}


def test_new_commit_shas_pruned_viewed_means_all_new():
    # last_viewed pointed at a commit since pruned out of the cache.
    entry = {"order": ["c5", "c4"], "last_viewed_sha": "c0"}
    assert audit._new_commit_shas(entry) == {"c5", "c4"}


def test_new_commit_shas_empty_order():
    assert audit._new_commit_shas({"order": [], "last_viewed_sha": None}) == set()


# ---------------------------------------------------------------------------
# _mark_commit_viewed: per-commit acknowledgement (forward high-water)
# ---------------------------------------------------------------------------

def test_mark_commit_viewed_advances_pointer_and_clears_dots():
    entry = {"order": ["c4", "c3", "c2", "c1"], "last_viewed_sha": "c1"}
    moved = audit._mark_commit_viewed(entry, "c3")
    assert moved is True
    assert entry["last_viewed_sha"] == "c3"
    # c3 and older are viewed; only c4 (newer) stays new.
    assert audit._new_commit_shas(entry) == {"c4"}


def test_mark_commit_viewed_is_forward_only():
    # Pointer already at c2 (newer); marking older c1 must not un-view c2.
    entry = {"order": ["c3", "c2", "c1"], "last_viewed_sha": "c2"}
    moved = audit._mark_commit_viewed(entry, "c1")
    assert moved is False
    assert entry["last_viewed_sha"] == "c2"


def test_mark_commit_viewed_from_none_pointer():
    entry = {"order": ["c3", "c2", "c1"], "last_viewed_sha": None}
    assert audit._mark_commit_viewed(entry, "c2") is True
    assert entry["last_viewed_sha"] == "c2"
    assert audit._new_commit_shas(entry) == {"c3"}


def test_mark_commit_viewed_unknown_sha_is_noop():
    entry = {"order": ["c2", "c1"], "last_viewed_sha": "c1"}
    assert audit._mark_commit_viewed(entry, "deadbeef") is False
    assert entry["last_viewed_sha"] == "c1"

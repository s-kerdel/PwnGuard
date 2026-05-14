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


def test_load_preserves_well_formed_state(tmp_path):
    path = tmp_path / "state.json"
    state = {
        "version": 1,
        "repos": {
            "https://gitlab.com/g/p@main": {
                "name": "p",
                "url": "https://gitlab.com/g/p",
                "branch": "main",
                "last_audited_sha": "abc1234",
                "last_viewed_sha":  "abc1234",
                "audited_at": "2026-05-15T09:14:00+00:00",
                "findings": [],
            }
        },
    }
    path.write_text(json.dumps(state))
    loaded = audit._load_monitor_state(str(path))
    assert loaded == state


# ---------------------------------------------------------------------------
# _sanitize_loaded_state (belt-and-braces against tampered cache)
# ---------------------------------------------------------------------------

def test_load_sanitizes_ansi_escape_in_findings(tmp_path):
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
    title = loaded["repos"]["https://gitlab.com/g/p@main"]["findings"][0]["title"]
    assert "\x1b" not in title
    assert "malicious title" in title


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
        "version": 1,
        "repos": {
            "k": {
                "name": "n", "url": "u", "branch": "b",
                "last_audited_sha": "abc",
                "last_viewed_sha":  "abc",
                "audited_at": "2026-05-15T09:14:00+00:00",
                "findings": [{
                    "severity": "HIGH", "title": "t", "description": "d",
                    "recommendation": "r", "file": "f", "line": 1,
                    "anchor": "a1",
                }],
            }
        },
    }
    audit._save_monitor_state(state, path)
    loaded = audit._load_monitor_state(path)
    assert loaded["repos"]["k"]["findings"][0]["title"] == "t"
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

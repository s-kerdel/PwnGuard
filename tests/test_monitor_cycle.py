"""Tests for the monitor refresh cycle.

End-to-end behaviour:
  - First encounter records the head as baseline, never invokes the LLM.
  - No-new-commits path is a no-op (no LLM call, status 'unchanged').
  - New commit triggers an audit, findings land in state.
  - Per-repo errors are isolated and don't abort the whole cycle.

The audit + diff-fetch + list-commits layers are mocked - we're
testing the orchestration, not the platform plumbing (that lives in
test_list_commits.py and test_fetch_url.py).
"""
import pytest

import audit
import pwnguard.monitor


@pytest.fixture
def cfg():
    return {
        "monitor": {
            "repos": [
                {"name": "alpha",
                 "url": "https://gitlab.com/g/alpha",
                 "branch": "main"},
                {"name": "beta",
                 "url": "https://github.com/o/beta",
                 "branch": "main"},
            ],
        },
    }


@pytest.fixture
def state():
    return {"version": 1, "repos": {}}


@pytest.fixture
def patched(monkeypatch):
    """Replace network + audit calls with recorders so the cycle
    becomes deterministic + offline."""
    calls = {"list": [], "audit": []}

    def fake_list(url, branch, limit=1):
        calls["list"].append((url, branch, limit))
        # Caller-controlled responses via the dict below. Each entry
        # may be a list of bare SHAs (back-compat) or list of
        # (sha, date) tuples (current shape).
        raw = calls["next_shas"].get(url, [])
        return [
            x if isinstance(x, tuple) else (x, None)
            for x in raw
        ]

    def fake_audit(repo_url, sha, config, backend):
        calls["audit"].append((repo_url, sha))
        result = audit.AuditResult()
        # Return whatever findings the test pre-loaded.
        for f in calls["next_findings"].get((repo_url, sha), []):
            result.findings.append(f)
        # _audit_commit_for_monitor returns (result, diff_lines).
        diff_lines = calls["next_diff_lines"].get((repo_url, sha), {})
        return result, diff_lines

    # _run_monitor_refresh lives in pwnguard.monitor and calls these
    # via its own module-level bindings, so we patch them on the source
    # module rather than the audit.py re-export shim.
    monkeypatch.setattr(pwnguard.monitor, "list_commits_from_url", fake_list)
    monkeypatch.setattr(pwnguard.monitor, "_audit_commit_for_monitor", fake_audit)

    calls["next_shas"] = {}
    calls["next_findings"] = {}
    calls["next_diff_lines"] = {}
    return calls


# ---------------------------------------------------------------------------
# First encounter: audit HEAD so the dashboard shows current state
# ---------------------------------------------------------------------------

def test_first_encounter_audits_head(cfg, state, patched):
    """A repo with no prior state gets its current HEAD audited on
    the first refresh — strategy C as agreed, but applied to the
    head commit so the user sees branch state immediately."""
    patched["next_shas"] = {
        "https://gitlab.com/g/alpha":   ["sha_a1"],
        "https://github.com/o/beta":    ["sha_b1"],
    }
    finding = audit.Finding(
        severity="HIGH", title="sqli", file="x.py", line=10,
        description="d", recommendation="r", anchor="a1",
    )
    patched["next_findings"] = {
        ("https://gitlab.com/g/alpha", "sha_a1"): [finding],
    }
    patched["next_diff_lines"] = {
        ("https://gitlab.com/g/alpha", "sha_a1"): {
            "x.py": {10: "    sql = f\"SELECT ...\""},
        },
    }

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    # Both audited on first encounter, not baselined-without-audit.
    assert set(summary.values()) == {"audited"}
    assert set(patched["audit"]) == {
        ("https://gitlab.com/g/alpha", "sha_a1"),
        ("https://github.com/o/beta",  "sha_b1"),
    }
    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    key_b = audit._repo_key("https://github.com/o/beta", "main")
    assert state["repos"][key_a]["last_audited_sha"] == "sha_a1"
    # First encounter sets viewed = audited so [updated] doesn't fire
    # on something the user is staring at right now.
    assert state["repos"][key_a]["last_viewed_sha"] == "sha_a1"
    assert state["repos"][key_a]["audited_at"] is not None
    assert len(state["repos"][key_a]["findings"]) == 1
    # diff_lines cached alongside findings so the TUI can render the
    # ±3 code preview without re-fetching. JSON-safe form: string keys.
    assert state["repos"][key_a]["diff_lines"] == {
        "x.py": {"10": "    sql = f\"SELECT ...\""},
    }
    # Commit date (from list_commits_from_url) is stored too so the
    # dashboard can render a relative-time chip next to the SHA.
    assert "last_audited_commit_date" in state["repos"][key_a]
    assert state["repos"][key_b]["last_audited_sha"] == "sha_b1"
    assert state["repos"][key_b]["findings"] == []


# ---------------------------------------------------------------------------
# diff_lines serialise / deserialise roundtrip
# ---------------------------------------------------------------------------

def test_serialize_diff_lines_stringifies_int_keys():
    serialised = audit._serialize_diff_lines({
        "x.py": {10: "row ten", 11: "row eleven"},
    })
    assert serialised == {
        "x.py": {"10": "row ten", "11": "row eleven"},
    }


def test_deserialize_diff_lines_parses_string_keys_back():
    out = audit._deserialize_diff_lines({
        "x.py": {"10": "row ten", "11": "row eleven"},
    })
    assert out == {"x.py": {10: "row ten", 11: "row eleven"}}


def test_deserialize_diff_lines_drops_malformed_rows():
    """A tampered cache with non-int line keys shouldn't crash."""
    out = audit._deserialize_diff_lines({
        "x.py": {"10": "ok", "abc": "bad-key", "11": 12345},  # bad value type too
    })
    assert out == {"x.py": {10: "ok", 11: ""}}


def test_deserialize_non_dict_returns_empty():
    assert audit._deserialize_diff_lines("not a dict") == {}
    assert audit._deserialize_diff_lines(None) == {}


# ---------------------------------------------------------------------------
# No-change cycle (no LLM call)
# ---------------------------------------------------------------------------

def test_unchanged_repo_is_skipped(cfg, state, patched):
    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key_a] = {
        "name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main",
        "last_audited_sha": "sha_a1", "last_viewed_sha": "sha_a1",
        "audited_at": "2026-05-15T09:00:00+00:00", "findings": [],
    }
    # alpha returns the same SHA it already audited.
    patched["next_shas"] = {
        "https://gitlab.com/g/alpha":   ["sha_a1"],
        "https://github.com/o/beta":    ["sha_b1"],
    }
    # beta hasn't been seen yet, so it'll be audited on first encounter.

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key_a] == "unchanged"
    # alpha unchanged -> no audit; beta first-encounter -> audited.
    assert patched["audit"] == [("https://github.com/o/beta", "sha_b1")]


# ---------------------------------------------------------------------------
# New commit triggers an audit
# ---------------------------------------------------------------------------

def test_new_commit_triggers_audit_and_updates_state(cfg, state, patched):
    # Pre-load BOTH repos as already audited so this test focuses on
    # the new-commit path, not the first-encounter audits.
    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    key_b = audit._repo_key("https://github.com/o/beta", "main")
    state["repos"][key_a] = {
        "name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main",
        "last_audited_sha": "sha_a1", "last_viewed_sha": "sha_a1",
        "audited_at": "2026-05-15T09:00:00+00:00", "findings": [],
    }
    state["repos"][key_b] = {
        "name": "beta", "url": "https://github.com/o/beta", "branch": "main",
        "last_audited_sha": "sha_b1", "last_viewed_sha": "sha_b1",
        "audited_at": "2026-05-15T09:00:00+00:00", "findings": [],
    }
    # alpha advanced to sha_a2; beta is unchanged.
    patched["next_shas"] = {
        "https://gitlab.com/g/alpha":   ["sha_a2"],
        "https://github.com/o/beta":    ["sha_b1"],
    }
    finding = audit.Finding(
        severity="HIGH", title="sqli", file="x.py", line=10,
        description="d", recommendation="r", anchor="a1",
    )
    patched["next_findings"] = {
        ("https://gitlab.com/g/alpha", "sha_a2"): [finding],
    }

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key_a] == "audited"
    assert summary[key_b] == "unchanged"
    # Only alpha was audited (beta unchanged).
    assert patched["audit"] == [("https://gitlab.com/g/alpha", "sha_a2")]
    assert state["repos"][key_a]["last_audited_sha"] == "sha_a2"
    # last_viewed_sha stays at sha_a1 — this is a subsequent audit
    # (not first-encounter), so the [updated] chip will fire until
    # the user marks it viewed.
    assert state["repos"][key_a]["last_viewed_sha"] == "sha_a1"
    assert len(state["repos"][key_a]["findings"]) == 1
    assert state["repos"][key_a]["findings"][0]["title"] == "sqli"


# ---------------------------------------------------------------------------
# Error isolation
# ---------------------------------------------------------------------------

def test_one_repo_error_does_not_abort_others(cfg, state, patched, monkeypatch):
    # alpha will error on list_commits; beta should still proceed.
    def fake_list(url, branch, limit=1):
        if "alpha" in url:
            raise SystemExit("alpha listing failed")
        return ["sha_b1"]
    monkeypatch.setattr(pwnguard.monitor, "list_commits_from_url", fake_list)

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    key_b = audit._repo_key("https://github.com/o/beta", "main")
    assert summary[key_a].startswith("error")
    # beta is first-encounter -> audited.
    assert summary[key_b] == "audited"


def test_missing_url_in_config_records_error(state, patched):
    bad_cfg = {"monitor": {"repos": [{"name": "broken", "branch": "main"}]}}
    summary = audit._run_monitor_refresh(bad_cfg, state, "ollama")
    assert "broken" in summary
    assert summary["broken"].startswith("error")
    assert patched["audit"] == []


# ---------------------------------------------------------------------------
# Empty / missing configuration
# ---------------------------------------------------------------------------

def test_no_monitor_config_returns_empty_summary(state, patched):
    summary = audit._run_monitor_refresh({}, state, "ollama")
    assert summary == {}


def test_empty_repos_list_returns_empty_summary(state, patched):
    summary = audit._run_monitor_refresh(
        {"monitor": {"repos": []}}, state, "ollama",
    )
    assert summary == {}


# ---------------------------------------------------------------------------
# Progress callback (TUI integration point)
# ---------------------------------------------------------------------------

def test_progress_callback_fires_per_repo(cfg, state, patched):
    patched["next_shas"] = {
        "https://gitlab.com/g/alpha":   ["sha_a1"],
        "https://github.com/o/beta":    ["sha_b1"],
    }
    seen = []

    def progress(idx, total, name, msg):
        seen.append((idx, total, name))

    audit._run_monitor_refresh(
        cfg, state, "ollama", progress=progress,
    )

    # Each repo should produce at least one progress callback.
    names = {n for _, _, n in seen}
    assert names == {"alpha", "beta"}
    assert all(total == 2 for _, total, _ in seen)


# ---------------------------------------------------------------------------
# _summarise_refresh formatter
# ---------------------------------------------------------------------------

def test_summarise_refresh_counts_categories():
    summary = {
        "a": "audited", "b": "audited",
        "c": "unchanged", "d": "error: boom",
    }
    line = audit._summarise_refresh(summary)
    assert "2 audited" in line
    assert "1 unchanged" in line
    assert "1 error" in line


def test_summarise_refresh_handles_empty_summary():
    assert "nothing to do" in audit._summarise_refresh({})


# ---------------------------------------------------------------------------
# _ordered_monitor_keys preserves config order
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# _ensure_repo_entries - placeholder rows for not-yet-refreshed repos
# ---------------------------------------------------------------------------

def test_ensure_creates_placeholder_for_each_configured_repo(cfg):
    state = {"version": 1, "repos": {}}
    audit._ensure_repo_entries(state, cfg)
    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    key_b = audit._repo_key("https://github.com/o/beta", "main")
    assert set(state["repos"]) == {key_a, key_b}
    # Placeholder carries the configured name / url / branch.
    assert state["repos"][key_a]["name"] == "alpha"
    assert state["repos"][key_a]["url"] == "https://gitlab.com/g/alpha"
    assert state["repos"][key_a]["branch"] == "main"
    # No audit data yet.
    assert state["repos"][key_a]["last_audited_sha"] is None
    assert state["repos"][key_a]["findings"] == []


def test_ensure_preserves_existing_entry_data(cfg):
    """Existing audited entries keep their findings + sha after ensure."""
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state = {"version": 1, "repos": {
        key: {
            "name": "alpha",
            "url": "https://gitlab.com/g/alpha",
            "branch": "main",
            "last_audited_sha": "sha_a1",
            "last_viewed_sha": "sha_a1",
            "audited_at": "2026-05-15T09:00:00+00:00",
            "findings": [{"severity": "HIGH", "title": "t"}],
        }
    }}
    audit._ensure_repo_entries(state, cfg)
    assert state["repos"][key]["last_audited_sha"] == "sha_a1"
    assert len(state["repos"][key]["findings"]) == 1


def test_ensure_refreshes_renamed_entry(cfg):
    """A config rename takes effect on the next ensure pass without
    losing audit data."""
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state = {"version": 1, "repos": {
        key: {
            "name": "OLD-NAME",
            "url": "https://gitlab.com/g/alpha",
            "branch": "main",
            "last_audited_sha": "sha_a1",
            "last_viewed_sha": "sha_a1",
            "findings": [],
        }
    }}
    audit._ensure_repo_entries(state, cfg)
    assert state["repos"][key]["name"] == "alpha"
    assert state["repos"][key]["last_audited_sha"] == "sha_a1"


def test_ensure_skips_malformed_config_entries():
    """Bad config entries (no url / branch) don't create placeholders
    and don't crash the loop."""
    cfg = {"monitor": {"repos": [
        {"name": "incomplete-1"},                       # no url, no branch
        {"name": "incomplete-2", "url": "https://x"},  # no branch
        {"name": "ok", "url": "https://github.com/o/r", "branch": "main"},
    ]}}
    state = {"version": 1, "repos": {}}
    audit._ensure_repo_entries(state, cfg)
    # Only the well-formed entry gets a placeholder.
    assert len(state["repos"]) == 1
    key = audit._repo_key("https://github.com/o/r", "main")
    assert key in state["repos"]


# ---------------------------------------------------------------------------
# _build_monitor_items orders findings by severity
# ---------------------------------------------------------------------------

def test_findings_sort_by_severity_inside_expanded_repo():
    """High-severity findings must surface above low-severity noise -
    matches --review's behaviour. Stable secondary order = emission
    index so two findings of the same severity keep their relative
    order from the model's response."""
    key = audit._repo_key("https://github.com/o/r", "main")
    state = {"version": 1, "repos": {
        key: {
            "name": "r", "url": "https://github.com/o/r", "branch": "main",
            "findings": [
                {"severity": "INFO",     "title": "info-1"},
                {"severity": "HIGH",     "title": "high-1"},
                {"severity": "INFO",     "title": "info-2"},
                {"severity": "CRITICAL", "title": "crit-1"},
                {"severity": "MEDIUM",   "title": "med-1"},
                {"severity": "HIGH",     "title": "high-2"},
            ],
        }
    }}
    items = audit._build_monitor_items(state, [key], {key: True})

    # Drop the repo header; rest are findings in render order, but
    # each tuple contains the ORIGINAL state index. So we look up the
    # original title to verify the sort.
    finding_titles = [
        state["repos"][k]["findings"][i]["title"]
        for kind, k, i in items if kind == "finding"
    ]
    assert finding_titles == [
        "crit-1",   # CRITICAL first
        "high-1", "high-2",  # then HIGH, emission order preserved
        "med-1",    # MEDIUM
        "info-1", "info-2",  # INFO last, emission order preserved
    ]


def test_findings_without_severity_default_to_info_at_end():
    """A finding missing the severity field shouldn't crash sort;
    it defaults to INFO and lands at the bottom."""
    key = audit._repo_key("https://github.com/o/r", "main")
    state = {"version": 1, "repos": {
        key: {
            "name": "r", "url": "https://github.com/o/r", "branch": "main",
            "findings": [
                {"title": "missing-sev"},  # no severity key
                {"severity": "HIGH", "title": "high-1"},
            ],
        }
    }}
    items = audit._build_monitor_items(state, [key], {key: True})
    titles = [
        state["repos"][k]["findings"][i]["title"]
        for kind, k, i in items if kind == "finding"
    ]
    assert titles == ["high-1", "missing-sev"]


# ---------------------------------------------------------------------------
# _format_relative_time - just the edge cases worth pinning. The
# per-granularity branches are integer division at multiples of 60 /
# 3600 / 86400; testing them with timedeltas is both flaky (clock
# advances during setup) and just verifies Python arithmetic.
# ---------------------------------------------------------------------------

def test_relative_time_handles_z_suffix():
    """GitHub returns UTC dates with 'Z' suffix; Python's
    fromisoformat() before 3.11 didn't accept it - the helper has to
    normalise. Empty string would mean the parse silently failed."""
    assert audit._format_relative_time("2026-05-13T10:00:00Z") != ""


def test_relative_time_returns_empty_on_garbage():
    assert audit._format_relative_time(None) == ""
    assert audit._format_relative_time("") == ""
    assert audit._format_relative_time("not a date") == ""


def test_relative_time_clock_skew_returns_zero():
    """A commit dated in the future (system clock skew between local
    host and the platform's API) must not produce a negative count."""
    from datetime import datetime, timezone, timedelta
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    assert audit._format_relative_time(future.isoformat()) == "0s"


def test_ordered_keys_follow_config_then_orphans(cfg):
    state = {"repos": {
        audit._repo_key("https://gitlab.com/g/alpha", "main"): {},
        audit._repo_key("https://gitlab.com/g/old",   "main"): {},
        audit._repo_key("https://github.com/o/beta",  "main"): {},
    }}
    keys = audit._ordered_monitor_keys(state, cfg)
    # alpha first, beta second (config order), then orphaned `old` at end.
    assert keys[0] == audit._repo_key("https://gitlab.com/g/alpha", "main")
    assert keys[1] == audit._repo_key("https://github.com/o/beta", "main")
    assert audit._repo_key("https://gitlab.com/g/old", "main") in keys[2:]

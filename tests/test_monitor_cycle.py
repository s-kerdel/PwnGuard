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
        # Caller-controlled responses via the dict below.
        return calls["next_shas"].get(url, [])

    def fake_audit(repo_url, sha, config, backend):
        calls["audit"].append((repo_url, sha))
        result = audit.AuditResult()
        # Return whatever findings the test pre-loaded.
        for f in calls["next_findings"].get((repo_url, sha), []):
            result.findings.append(f)
        return result

    monkeypatch.setattr(audit, "list_commits_from_url", fake_list)
    monkeypatch.setattr(audit, "_audit_commit_for_monitor", fake_audit)

    calls["next_shas"] = {}
    calls["next_findings"] = {}
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
    assert state["repos"][key_b]["last_audited_sha"] == "sha_b1"
    assert state["repos"][key_b]["findings"] == []


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
    monkeypatch.setattr(audit, "list_commits_from_url", fake_list)

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

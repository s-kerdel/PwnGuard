"""Tests for the monitor refresh cycle.

End-to-end behaviour:
  - First encounter audits HEAD (so the dashboard shows current state).
  - Identical range is a no-op (status 'unchanged', no LLM call).
  - A forward range audits every new commit oldest-first, advancing the
    pointer contiguously.
  - The per-refresh cap bounds LLM calls and reports the deferred backlog.
  - Already-cached SHAs are deduped (never re-audited).
  - A diverged (force-push) range falls back to auditing HEAD only.
  - Per-repo errors are isolated and don't abort the whole cycle.

The audit + diff-fetch + list-commits + compare layers are mocked - we
test the orchestration, not the platform plumbing (that lives in
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
    return {"version": 2, "repos": {}}


@pytest.fixture
def patched(monkeypatch):
    """Replace network + audit calls with recorders so the cycle becomes
    deterministic + offline.

    ``head``       url -> [(sha, date), ...] returned by list_commits_from_url
    ``next_range`` url -> (status, [(sha, date), ...]) for the compare call
    """
    calls = {"list": [], "range": [], "audit": []}
    calls["head"] = {}
    calls["next_range"] = {}
    calls["next_findings"] = {}
    calls["next_diff_lines"] = {}

    def fake_list(url, branch, limit=1):
        calls["list"].append((url, branch, limit))
        raw = calls["head"].get(url, [])
        return [x if isinstance(x, tuple) else (x, None) for x in raw]

    def fake_range(url, branch, base, limit=100):
        calls["range"].append((url, branch, base, limit))
        status, commits = calls["next_range"].get(url, ("identical", []))
        norm = [c if isinstance(c, tuple) else (c, None) for c in commits]
        return status, norm

    def fake_audit(repo_url, sha, config, backend):
        calls["audit"].append((repo_url, sha))
        result = audit.AuditResult()
        for f in calls["next_findings"].get((repo_url, sha), []):
            result.findings.append(f)
        diff_lines = calls["next_diff_lines"].get((repo_url, sha), {})
        return result, diff_lines

    monkeypatch.setattr(pwnguard.monitor, "list_commits_from_url", fake_list)
    monkeypatch.setattr(
        pwnguard.monitor, "list_commit_range_from_url", fake_range,
    )
    monkeypatch.setattr(
        pwnguard.monitor, "_audit_commit_for_monitor", fake_audit,
    )
    return calls


def _audited_entry(name, url, sha, findings=None):
    """A repo entry already baselined at ``sha`` (single cached commit)."""
    return {
        "name": name, "url": url, "branch": "main",
        "last_audited_sha": sha, "last_viewed_sha": sha, "head_sha": sha,
        "audited_at": "2026-05-15T09:00:00+00:00",
        "commits": {
            sha: {
                "sha": sha, "date": None,
                "audited_at": "2026-05-15T09:00:00+00:00",
                "findings": findings or [], "diff_lines": {},
            },
        },
        "order": [sha],
    }


# ---------------------------------------------------------------------------
# First encounter: audit HEAD so the dashboard shows current state
# ---------------------------------------------------------------------------

def test_first_encounter_audits_head(cfg, state, patched):
    patched["head"] = {
        "https://gitlab.com/g/alpha": [("sha_a1", "2026-05-10T22:45:40Z")],
        "https://github.com/o/beta":  [("sha_b1", None)],
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

    assert all(s["status"] == "first-seen" for s in summary.values())
    assert set(patched["audit"]) == {
        ("https://gitlab.com/g/alpha", "sha_a1"),
        ("https://github.com/o/beta",  "sha_b1"),
    }
    # The range/compare endpoint is never hit on first encounter.
    assert patched["range"] == []

    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    entry_a = state["repos"][key_a]
    assert entry_a["last_audited_sha"] == "sha_a1"
    assert entry_a["head_sha"] == "sha_a1"
    # First encounter sets viewed = audited so [updated] doesn't fire on
    # something the user is staring at right now.
    assert entry_a["last_viewed_sha"] == "sha_a1"
    assert entry_a["order"] == ["sha_a1"]
    rec = entry_a["commits"]["sha_a1"]
    assert len(rec["findings"]) == 1
    assert rec["date"] == "2026-05-10T22:45:40Z"
    # diff_lines cached under the commit, JSON-safe (string keys).
    assert rec["diff_lines"] == {"x.py": {"10": "    sql = f\"SELECT ...\""}}

    key_b = audit._repo_key("https://github.com/o/beta", "main")
    assert state["repos"][key_b]["commits"]["sha_b1"]["findings"] == []


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
        "x.py": {"10": "ok", "abc": "bad-key", "11": 12345},
    })
    assert out == {"x.py": {10: "ok", 11: ""}}


def test_deserialize_non_dict_returns_empty():
    assert audit._deserialize_diff_lines("not a dict") == {}
    assert audit._deserialize_diff_lines(None) == {}


# ---------------------------------------------------------------------------
# No-change cycle (identical range, no LLM call)
# ---------------------------------------------------------------------------

def test_identical_range_is_unchanged(cfg, state, patched):
    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    key_b = audit._repo_key("https://github.com/o/beta", "main")
    state["repos"][key_a] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "sha_a1",
    )
    state["repos"][key_b] = _audited_entry(
        "beta", "https://github.com/o/beta", "sha_b1",
    )
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("identical", []),
        "https://github.com/o/beta":  ("identical", []),
    }

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key_a]["status"] == "unchanged"
    assert summary[key_b]["status"] == "unchanged"
    assert patched["audit"] == []  # nothing re-audited


# ---------------------------------------------------------------------------
# Forward range: every new commit audited oldest-first
# ---------------------------------------------------------------------------

def test_range_audits_all_commits_oldest_first(cfg, state, patched):
    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    key_b = audit._repo_key("https://github.com/o/beta", "main")
    state["repos"][key_a] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "sha_a0",
    )
    state["repos"][key_b] = _audited_entry(
        "beta", "https://github.com/o/beta", "sha_b0",
    )
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("ok", [
            ("sha_a1", "d1"), ("sha_a2", "d2"), ("sha_a3", "d3"),
        ]),
        "https://github.com/o/beta": ("identical", []),
    }

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key_a]["status"] == "audited"
    assert summary[key_a]["audited"] == 3
    assert summary[key_a]["backlog"] == 0
    # Audited oldest -> newest.
    assert patched["audit"] == [
        ("https://gitlab.com/g/alpha", "sha_a1"),
        ("https://gitlab.com/g/alpha", "sha_a2"),
        ("https://gitlab.com/g/alpha", "sha_a3"),
    ]
    entry = state["repos"][key_a]
    # Pointer advances to the newest audited commit.
    assert entry["last_audited_sha"] == "sha_a3"
    assert entry["head_sha"] == "sha_a3"
    # order is newest-first: new commits sit ahead of the old baseline.
    assert entry["order"] == ["sha_a3", "sha_a2", "sha_a1", "sha_a0"]
    # Per-commit dates land on their own records.
    assert entry["commits"]["sha_a2"]["date"] == "d2"


# ---------------------------------------------------------------------------
# Per-refresh cap + backlog reporting (no silent truncation)
# ---------------------------------------------------------------------------

def test_cap_limits_commits_and_reports_backlog(state, patched):
    # review_everything_at_once off -> the cap is a hard stop and the
    # remainder is reported as backlog for the next [r] press.
    cfg = {"monitor": {
        "repos": [{"name": "alpha",
                   "url": "https://gitlab.com/g/alpha",
                   "branch": "main"}],
        "review_everything_at_once": False,
        "max_commits_per_refresh": 2,
    }}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "c0",
    )
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("ok", [
            ("c1", None), ("c2", None), ("c3", None),
            ("c4", None), ("c5", None),
        ]),
    }

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key]["audited"] == 2
    assert summary[key]["backlog"] == 3
    # Oldest two audited; the pointer advances only that far.
    assert [s for (_, s) in patched["audit"]] == ["c1", "c2"]
    entry = state["repos"][key]
    assert entry["last_audited_sha"] == "c2"
    # head_sha leads the pointer -> the dashboard shows a backlog chip.
    assert entry["head_sha"] == "c5"
    assert entry["pending_count"] == 3


def test_head_sha_is_true_head_when_range_exceeds_ceiling(state, patched):
    """When the compare window is truncated at the ceiling, head_sha
    resolves to the real branch HEAD (extra list call) so the backlog
    chip doesn't understate how far behind the pointer is."""
    cfg = {"monitor": {
        "repos": [
            {"name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main"},
        ],
        # Single-batch mode so the assertion targets the oldest cap-sized
        # slice; HEAD resolution runs regardless of this knob.
        "review_everything_at_once": False,
    }}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "c0",
    )
    # A full ceiling-sized window (default ceiling is 100).
    window = [(f"c{i:03d}", None) for i in range(1, 101)]
    patched["next_range"] = {"https://gitlab.com/g/alpha": ("ok", window)}
    # The true HEAD lives beyond the truncated window.
    patched["head"] = {"https://gitlab.com/g/alpha": [("REALHEAD", None)]}

    audit._run_monitor_refresh(cfg, state, "ollama")

    entry = state["repos"][key]
    assert entry["head_sha"] == "REALHEAD"
    # Default cap audits the oldest 10 of the window.
    assert [s for (_, s) in patched["audit"]] == [f"c{i:03d}" for i in range(1, 11)]


# ---------------------------------------------------------------------------
# review_everything_at_once: one refresh catches the branch fully up
# ---------------------------------------------------------------------------

def test_review_everything_at_once_drains_past_cap(state, patched):
    """With the knob on (default), a single refresh audits the whole
    window even when it exceeds max_commits_per_refresh - the cap only
    sizes the progress batch, it doesn't stop the drain."""
    cfg = {"monitor": {
        "repos": [{"name": "alpha",
                   "url": "https://gitlab.com/g/alpha",
                   "branch": "main"}],
        "max_commits_per_refresh": 2,  # smaller than the window on purpose
    }}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "c0",
    )
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("ok", [
            ("c1", None), ("c2", None), ("c3", None),
            ("c4", None), ("c5", None),
        ]),
    }

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key]["audited"] == 5
    assert summary[key]["backlog"] == 0
    assert [s for (_, s) in patched["audit"]] == ["c1", "c2", "c3", "c4", "c5"]
    entry = state["repos"][key]
    assert entry["last_audited_sha"] == "c5"
    assert entry["head_sha"] == "c5"
    assert entry["pending_count"] == 0


def test_review_everything_at_once_drains_across_windows(state, patched, monkeypatch):
    """A backlog larger than the compare-window ceiling is drained by
    re-fetching the next window from the advanced pointer until the
    branch is caught up - all in one refresh."""
    # Shrink the ceiling so two commits fill a window without needing a
    # 100-commit fixture; cap matches so ceiling == 2.
    monkeypatch.setattr(pwnguard.monitor, "_RANGE_FETCH_CEILING", 2)
    cfg = {"monitor": {
        "repos": [{"name": "alpha",
                   "url": "https://gitlab.com/g/alpha",
                   "branch": "main"}],
        "max_commits_per_refresh": 2,
    }}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "c0",
    )

    # Each window starts after the pointer's current SHA (the `base`).
    windows = {
        "c0": ("ok", [("c1", None), ("c2", None)]),
        "c2": ("ok", [("c3", None), ("c4", None)]),
        "c4": ("ok", [("c5", None)]),  # short window -> caught up
    }

    def fake_range(url, branch, base, limit=100):
        patched["range"].append((url, branch, base, limit))
        return windows[base]
    monkeypatch.setattr(
        pwnguard.monitor, "list_commit_range_from_url", fake_range,
    )
    # HEAD lookups (fired when a window fills the ceiling) point past the
    # window so the chip never understates mid-drain.
    patched["head"] = {"https://gitlab.com/g/alpha": [("c5", None)]}

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key]["audited"] == 5
    assert summary[key]["backlog"] == 0
    assert [s for (_, s) in patched["audit"]] == ["c1", "c2", "c3", "c4", "c5"]
    entry = state["repos"][key]
    assert entry["last_audited_sha"] == "c5"
    assert entry["pending_count"] == 0
    # Three windows fetched: c0.., c2.., c4...
    assert [base for (_, _, base, _) in patched["range"]] == ["c0", "c2", "c4"]


def test_review_everything_at_once_stops_on_mid_drain_diverged(state, patched, monkeypatch):
    """If history is rewritten mid-drain, the catch-up loop stops at the
    last good commit; the next refresh's diverged fallback handles it."""
    monkeypatch.setattr(pwnguard.monitor, "_RANGE_FETCH_CEILING", 2)
    cfg = {"monitor": {
        "repos": [{"name": "alpha",
                   "url": "https://gitlab.com/g/alpha",
                   "branch": "main"}],
        "max_commits_per_refresh": 2,
    }}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "c0",
    )
    windows = {
        "c0": ("ok", [("c1", None), ("c2", None)]),
        "c2": ("diverged", []),  # force-push landed while we were auditing
    }

    def fake_range(url, branch, base, limit=100):
        return windows[base]
    monkeypatch.setattr(
        pwnguard.monitor, "list_commit_range_from_url", fake_range,
    )
    patched["head"] = {"https://gitlab.com/g/alpha": [("c2", None)]}

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert [s for (_, s) in patched["audit"]] == ["c1", "c2"]
    assert state["repos"][key]["last_audited_sha"] == "c2"
    assert summary[key]["status"] == "audited"


def test_backlog_drains_on_next_refresh(state, patched):
    """A second refresh from the advanced pointer audits the next chunk -
    no commit is permanently skipped."""
    cfg = {"monitor": {
        "repos": [{"name": "alpha",
                   "url": "https://gitlab.com/g/alpha",
                   "branch": "main"}],
        "review_everything_at_once": False,
        "max_commits_per_refresh": 2,
    }}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "c0",
    )
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("ok", [
            ("c1", None), ("c2", None), ("c3", None),
        ]),
    }
    audit._run_monitor_refresh(cfg, state, "ollama")  # audits c1, c2

    # Second pass: compare now returns only what's left of the range.
    patched["audit"].clear()
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("ok", [("c3", None)]),
    }
    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert [s for (_, s) in patched["audit"]] == ["c3"]
    entry = state["repos"][key]
    assert entry["last_audited_sha"] == "c3"
    assert summary[key]["backlog"] == 0
    assert entry["pending_count"] == 0


# ---------------------------------------------------------------------------
# Dedup by SHA
# ---------------------------------------------------------------------------

def test_dedup_skips_already_cached_commits(state, patched):
    cfg = {"monitor": {"repos": [
        {"name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main"},
    ]}}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    entry = _audited_entry("alpha", "https://gitlab.com/g/alpha", "sha_a1")
    # c2 is already cached (e.g. audited in a prior, overlapping range).
    entry["commits"]["c2"] = {
        "sha": "c2", "date": None, "audited_at": "x",
        "findings": [], "diff_lines": {},
    }
    entry["order"] = ["c2", "sha_a1"]
    state["repos"][key] = entry
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("ok", [("c2", None), ("c3", None)]),
    }

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    # c2 already cached -> only c3 hits the model.
    assert patched["audit"] == [("https://gitlab.com/g/alpha", "c3")]
    assert summary[key]["audited"] == 1


def test_range_all_cached_is_unchanged_not_error(state, patched):
    """GitLab can return a compare range whose commits are all already
    cached (overlapping range). That's 'caught up', not an error - it
    must not surface as 'no commit audited'."""
    cfg = {"monitor": {"repos": [
        {"name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main"},
    ]}}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    entry = _audited_entry("alpha", "https://gitlab.com/g/alpha", "c1")
    entry["commits"]["c2"] = {
        "sha": "c2", "date": None, "audited_at": "x",
        "findings": [], "diff_lines": {},
    }
    entry["order"] = ["c2", "c1"]
    state["repos"][key] = entry
    # Compare returns only commits we've already audited.
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("ok", [("c1", None), ("c2", None)]),
    }

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key]["status"] == "unchanged"
    assert patched["audit"] == []
    assert state["repos"][key]["last_error"] is None


# ---------------------------------------------------------------------------
# Force-push / diverged fallback
# ---------------------------------------------------------------------------

def test_diverged_audits_head_only(state, patched):
    cfg = {"monitor": {"repos": [
        {"name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main"},
    ]}}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "sha_old",
    )
    patched["next_range"] = {"https://gitlab.com/g/alpha": ("diverged", [])}
    patched["head"] = {"https://gitlab.com/g/alpha": [("sha_new", "d")]}

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key]["status"] == "diverged"
    assert patched["audit"] == [("https://gitlab.com/g/alpha", "sha_new")]
    entry = state["repos"][key]
    assert entry["last_audited_sha"] == "sha_new"
    assert entry["head_sha"] == "sha_new"


def test_diverged_head_already_cached_is_unchanged(state, patched):
    cfg = {"monitor": {"repos": [
        {"name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main"},
    ]}}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "sha_x",
    )
    patched["next_range"] = {"https://gitlab.com/g/alpha": ("diverged", [])}
    patched["head"] = {"https://gitlab.com/g/alpha": [("sha_x", None)]}

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key]["status"] == "unchanged"
    assert patched["audit"] == []


# ---------------------------------------------------------------------------
# Error isolation
# ---------------------------------------------------------------------------

def test_one_repo_error_does_not_abort_others(cfg, state, patched, monkeypatch):
    # alpha errors while listing HEAD on first encounter; beta proceeds.
    def fake_list(url, branch, limit=1):
        if "alpha" in url:
            raise SystemExit("alpha listing failed")
        return [("sha_b1", None)]
    monkeypatch.setattr(pwnguard.monitor, "list_commits_from_url", fake_list)

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    key_b = audit._repo_key("https://github.com/o/beta", "main")
    assert summary[key_a]["status"] == "error"
    assert summary[key_b]["status"] == "first-seen"


def test_audit_error_mid_range_stops_batch_contiguously(state, patched, monkeypatch):
    """If a commit's audit fails partway through a range, the pointer
    stops at the last good commit (no gap) and the rest is backlog."""
    cfg = {"monitor": {"repos": [
        {"name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main"},
    ]}}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "c0",
    )
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("ok", [
            ("c1", None), ("c2", None), ("c3", None),
        ]),
    }

    def fake_audit(repo_url, sha, config, backend):
        patched["audit"].append((repo_url, sha))
        if sha == "c2":
            raise SystemExit("model exploded")
        return audit.AuditResult(), {}
    monkeypatch.setattr(
        pwnguard.monitor, "_audit_commit_for_monitor", fake_audit,
    )

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    # c1 audited, c2 failed -> stop. Pointer stays at c1.
    assert summary[key]["audited"] == 1
    assert state["repos"][key]["last_audited_sha"] == "c1"
    # c2 + c3 remain pending.
    assert summary[key]["backlog"] == 2


def test_missing_url_in_config_records_error(state, patched):
    bad_cfg = {"monitor": {"repos": [{"name": "broken", "branch": "main"}]}}
    summary = audit._run_monitor_refresh(bad_cfg, state, "ollama")
    assert summary["broken"]["status"] == "error"
    assert patched["audit"] == []


def test_refresh_records_last_error_on_entry(state, patched, monkeypatch):
    """A fetch failure is stamped on the entry so the dashboard can show
    the reason, not just count it."""
    cfg = {"monitor": {"repos": [
        {"name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main"},
    ]}}
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state["repos"][key] = _audited_entry(
        "alpha", "https://gitlab.com/g/alpha", "c0",
    )

    def boom(url, branch, base, limit=100):
        raise SystemExit("HTTP 500 from compare endpoint")
    monkeypatch.setattr(
        pwnguard.monitor, "list_commit_range_from_url", boom,
    )

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key]["status"] == "error"
    assert state["repos"][key]["last_error"] == "HTTP 500 from compare endpoint"


def test_refresh_clears_last_error_on_recovery(state, patched):
    """A repo that errored last time clears its error once a refresh
    succeeds, so the chip doesn't linger."""
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    entry = _audited_entry("alpha", "https://gitlab.com/g/alpha", "c0")
    entry["last_error"] = "stale boom from a previous refresh"
    state["repos"][key] = entry
    cfg = {"monitor": {"repos": [
        {"name": "alpha", "url": "https://gitlab.com/g/alpha", "branch": "main"},
    ]}}
    patched["next_range"] = {
        "https://gitlab.com/g/alpha": ("identical", []),
    }

    summary = audit._run_monitor_refresh(cfg, state, "ollama")

    assert summary[key]["status"] == "unchanged"
    assert state["repos"][key]["last_error"] is None


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
    patched["head"] = {
        "https://gitlab.com/g/alpha": [("sha_a1", None)],
        "https://github.com/o/beta":  [("sha_b1", None)],
    }
    seen = []

    def progress(idx, total, name, msg):
        seen.append((idx, total, name))

    audit._run_monitor_refresh(cfg, state, "ollama", progress=progress)

    names = {n for _, _, n in seen}
    assert names == {"alpha", "beta"}
    assert all(total == 2 for _, total, _ in seen)


# ---------------------------------------------------------------------------
# _summarise_refresh formatter
# ---------------------------------------------------------------------------

def test_summarise_refresh_counts_commits_and_backlog():
    summary = {
        "a": {"status": "audited", "audited": 3, "backlog": 0},
        "b": {"status": "audited", "audited": 2, "backlog": 5},
        "c": {"status": "unchanged", "audited": 0, "backlog": 0},
        "d": {"status": "error", "audited": 0, "backlog": 0, "error": "boom"},
    }
    line = audit._summarise_refresh(summary)
    assert "5 commits audited" in line
    assert "1 unchanged" in line
    assert "1 error" in line
    assert "5 pending" in line


def test_summarise_refresh_handles_empty_summary():
    assert "nothing to do" in audit._summarise_refresh({})


# ---------------------------------------------------------------------------
# _ensure_repo_entries - placeholder rows for not-yet-refreshed repos
# ---------------------------------------------------------------------------

def test_ensure_creates_placeholder_for_each_configured_repo(cfg):
    state = {"version": 2, "repos": {}}
    audit._ensure_repo_entries(state, cfg)
    key_a = audit._repo_key("https://gitlab.com/g/alpha", "main")
    key_b = audit._repo_key("https://github.com/o/beta", "main")
    assert set(state["repos"]) == {key_a, key_b}
    assert state["repos"][key_a]["name"] == "alpha"
    assert state["repos"][key_a]["url"] == "https://gitlab.com/g/alpha"
    assert state["repos"][key_a]["branch"] == "main"
    # No audit data yet: empty commit cache, null pointer.
    assert state["repos"][key_a]["last_audited_sha"] is None
    assert state["repos"][key_a]["commits"] == {}
    assert state["repos"][key_a]["order"] == []


def test_ensure_preserves_existing_entry_data(cfg):
    """Existing audited entries keep their commits + pointer after ensure."""
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    state = {"version": 2, "repos": {
        key: _audited_entry(
            "alpha", "https://gitlab.com/g/alpha", "sha_a1",
            findings=[{"severity": "HIGH", "title": "t"}],
        ),
    }}
    audit._ensure_repo_entries(state, cfg)
    assert state["repos"][key]["last_audited_sha"] == "sha_a1"
    assert state["repos"][key]["commits"]["sha_a1"]["findings"][0]["title"] == "t"


def test_ensure_refreshes_renamed_entry(cfg):
    """A config rename takes effect on the next ensure pass without
    losing audit data."""
    key = audit._repo_key("https://gitlab.com/g/alpha", "main")
    entry = _audited_entry("OLD-NAME", "https://gitlab.com/g/alpha", "sha_a1")
    state = {"version": 2, "repos": {key: entry}}
    audit._ensure_repo_entries(state, cfg)
    assert state["repos"][key]["name"] == "alpha"
    assert state["repos"][key]["last_audited_sha"] == "sha_a1"


def test_ensure_skips_malformed_config_entries():
    """Bad config entries (no url / branch) don't create placeholders
    and don't crash the loop."""
    cfg = {"monitor": {"repos": [
        {"name": "incomplete-1"},
        {"name": "incomplete-2", "url": "https://x"},
        {"name": "ok", "url": "https://github.com/o/r", "branch": "main"},
    ]}}
    state = {"version": 2, "repos": {}}
    audit._ensure_repo_entries(state, cfg)
    assert len(state["repos"]) == 1
    key = audit._repo_key("https://github.com/o/r", "main")
    assert key in state["repos"]


# ---------------------------------------------------------------------------
# _build_monitor_items: repo -> commit -> finding tree
# ---------------------------------------------------------------------------

def _state_with_commit(findings):
    key = audit._repo_key("https://github.com/o/r", "main")
    sha = "c1"
    state = {"version": 2, "repos": {
        key: {
            "name": "r", "url": "https://github.com/o/r", "branch": "main",
            "last_audited_sha": sha, "head_sha": sha, "order": [sha],
            "commits": {sha: {"sha": sha, "findings": findings}},
        }
    }}
    return state, key, sha


def test_commits_appear_only_when_repo_expanded():
    state, key, sha = _state_with_commit([{"severity": "HIGH", "title": "h"}])
    collapsed = audit._build_monitor_items(state, [key], {key: False}, {})
    assert collapsed == [("repo", key, None)]
    expanded = audit._build_monitor_items(state, [key], {key: True}, {})
    assert ("commit", key, sha) in expanded
    # Findings hidden until the commit itself is expanded.
    assert not any(kind == "finding" for kind, _, _ in expanded)


def _state_two_commits():
    """One commit with a finding (c2), one clean (c1), repo expanded."""
    key = audit._repo_key("https://github.com/o/r", "main")
    state = {"version": 2, "repos": {
        key: {
            "name": "r", "url": "https://github.com/o/r", "branch": "main",
            "last_audited_sha": "c2", "head_sha": "c2",
            "order": ["c2", "c1"],
            "commits": {
                "c2": {"sha": "c2", "findings": [
                    {"severity": "HIGH", "title": "h"},
                ]},
                "c1": {"sha": "c1", "findings": []},
            },
        }
    }}
    return state, key


def test_clean_commits_hidden_by_default():
    """Findings-first: a clean commit isn't a navigable row; the commit
    with a finding still is."""
    state, key = _state_two_commits()
    items = audit._build_monitor_items(state, [key], {key: True}, {})
    commit_shas = [ref for kind, _, ref in items if kind == "commit"]
    assert commit_shas == ["c2"]  # c1 (clean) collapsed away


def test_clean_commits_shown_with_show_all():
    """[f] / show_all surfaces every commit, clean ones included."""
    state, key = _state_two_commits()
    items = audit._build_monitor_items(
        state, [key], {key: True}, {}, {key: True},
    )
    commit_shas = [ref for kind, _, ref in items if kind == "commit"]
    assert commit_shas == ["c2", "c1"]


def test_findings_sort_by_severity_within_commit():
    state, key, sha = _state_with_commit([
        {"severity": "INFO",     "title": "info-1"},
        {"severity": "HIGH",     "title": "high-1"},
        {"severity": "INFO",     "title": "info-2"},
        {"severity": "CRITICAL", "title": "crit-1"},
        {"severity": "MEDIUM",   "title": "med-1"},
        {"severity": "HIGH",     "title": "high-2"},
    ])
    items = audit._build_monitor_items(
        state, [key], {key: True}, {(key, sha): True},
    )
    titles = [
        state["repos"][k]["commits"][ref[0]]["findings"][ref[1]]["title"]
        for kind, k, ref in items if kind == "finding"
    ]
    assert titles == [
        "crit-1", "high-1", "high-2", "med-1", "info-1", "info-2",
    ]


def test_findings_without_severity_default_to_info_at_end():
    state, key, sha = _state_with_commit([
        {"title": "missing-sev"},
        {"severity": "HIGH", "title": "high-1"},
    ])
    items = audit._build_monitor_items(
        state, [key], {key: True}, {(key, sha): True},
    )
    titles = [
        state["repos"][k]["commits"][ref[0]]["findings"][ref[1]]["title"]
        for kind, k, ref in items if kind == "finding"
    ]
    assert titles == ["high-1", "missing-sev"]


# ---------------------------------------------------------------------------
# _repo_all_findings aggregation
# ---------------------------------------------------------------------------

def test_repo_all_findings_flattens_across_commits():
    entry = {
        "order": ["c2", "c1"],
        "commits": {
            "c1": {"findings": [{"title": "a"}]},
            "c2": {"findings": [{"title": "b"}, {"title": "c"}]},
        },
    }
    titles = [f["title"] for f in audit._repo_all_findings(entry)]
    # newest commit (c2) first, in order.
    assert titles == ["b", "c", "a"]


# ---------------------------------------------------------------------------
# _format_relative_time edge cases
# ---------------------------------------------------------------------------

def test_relative_time_handles_z_suffix():
    assert audit._format_relative_time("2026-05-13T10:00:00Z") != ""


def test_relative_time_returns_empty_on_garbage():
    assert audit._format_relative_time(None) == ""
    assert audit._format_relative_time("") == ""
    assert audit._format_relative_time("not a date") == ""


def test_relative_time_clock_skew_returns_zero():
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
    assert keys[0] == audit._repo_key("https://gitlab.com/g/alpha", "main")
    assert keys[1] == audit._repo_key("https://github.com/o/beta", "main")
    assert audit._repo_key("https://gitlab.com/g/old", "main") in keys[2:]

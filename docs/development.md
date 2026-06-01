# Development & testing

[← Back to README](../README.md)

## Running the test suite

Tests live in `tests/` and cover the anchor pipeline, JSON parse +
repair stages, diff input validation, box-card width math, the
security primitives (`_sanitize`, `_is_safe_ref`), the CI-gate
dataclass methods (`AuditResult.exceeds_threshold` etc.), the
`filter_diff` ignore-pattern + language-focus + truncation paths,
and `--from-url` routing. Set up an editable install with the dev
extras, then run pytest from the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python3 -m pytest tests/ -v
```

No network, no LLM calls — the deterministic pieces are exercised
directly so a regression in the anchor system or the parser
fallbacks fails fast.

**URL routing tests use mocked HTTP, not real requests.** The
`--from-url` tests replace `_http_get` with a recorder via pytest's
`monkeypatch` fixture, then assert that each URL shape (GitLab MR /
commit / GitHub PR / commit) routes to the correct API endpoint and
forwards the right auth header from the right env var. This catches
regex / dispatch regressions and header-name mistakes (`PRIVATE-TOKEN`
vs `Authorization` mix-ups), but **does not** validate platform-side
behaviour: self-hosted GitLab path differences, GitHub Enterprise
host suffixes, rate-limit responses, TLS errors, and API schema
changes all remain things a live integration test would need to
catch separately.

Two convenience entry points:

- `pwnguard --self-test` — same suite, callable from anywhere the
  `pwnguard` CLI is reachable. Useful for verifying a fresh install
  is healthy. Requires `pytest` in the active environment
  (`pip install -e ".[dev]"` for an editable clone, or
  `pipx inject pwnguard pytest` for a pipx install).
- **Pre-commit auto-run (PwnGuard's own repo only)** — when this
  repo's pre-commit hook fires, it runs `pytest tests/` *before* the
  security scan. Test failures block the commit, since a regressed
  auditor produces unreliable findings. Detected by the standalone
  layout (`audit.py` at repo root + `tests/test_anchors.py` present),
  so consumer projects never see this step.

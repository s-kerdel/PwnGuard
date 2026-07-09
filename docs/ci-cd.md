# Using PwnGuard in CI/CD

PwnGuard gates a pipeline by **exit code**: one job runs it on the change,
and a non-zero exit fails the build. No plugin or integration needed.

| Exit | Meaning | Pipeline |
|------|---------|----------|
| `0` | Clean, or every finding suppressed | pass |
| `1` | Findings above the threshold remain | fail (blocked) |
| `2` | Could not run (config error, backend unreachable) | fail; investigate, do not treat as approved |

## Rehearse the gate locally (no pipeline needed)

Run the same command a CI job runs, against your branch, and read the
exit code:

```bash
pwnguard --mode ci --backend openai-compat
echo "pipeline would $([ $? -eq 0 ] && echo PASS || echo FAIL)"
```

`--mode ci` diffs `origin/main...HEAD` (override the target branch with
the `CI_MERGE_REQUEST_TARGET_BRANCH_NAME` env var). Run outside GitLab it
prints a harmless "skipping MR comment" warning; the exit code is the gate.

No remote, or you just want the staged changes? Use the hook path:

```bash
pwnguard --mode hook --backend openai-compat ; echo "exit=$?"
```

Inspect findings and suppressions as data:

```bash
pwnguard --mode ci --json | jq '{blocked, suppressed}'
```

### Try it with the sample fixture

[`demo/suppression_demo.py`](../demo/suppression_demo.py) is an
intentionally vulnerable file: three findings carry a `pwnguard:ignore`
marker (one per form: CWE, keyword, bare) and two do not. Scanning it
shows suppression and the gate together:

```bash
git add demo/suppression_demo.py
pwnguard --mode hook --backend openai-compat ; echo "exit=$?"
# -> the marked findings are dropped ("N finding(s) suppressed inline"),
#    and exit=1 from the unmarked command-injection and SSRF findings.
#    Mark those two as well to reach exit=0.
```

## GitHub Actions

There is no MR-diff helper for GitHub, so diff the PR range with `git` and
pass it via `--diff-file`:

```yaml
name: security
on: [pull_request]
jobs:
  pwnguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }          # need the base branch to diff
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install "pwnguard[claude-api]" --quiet
      - env: { ANTHROPIC_API_KEY: "${{ secrets.ANTHROPIC_API_KEY }}" }
        run: |
          git diff "origin/${{ github.base_ref }}...HEAD" > pr.diff
          pwnguard --diff-file pr.diff --backend claude-api
```

The non-zero exit fails the step. Use `--backend openai-compat` (with
`OPENAI_API_KEY` + `openai.url`) for a hosted or self-hosted model instead.

## GitLab CI

Paste the stage from [`.gitlab-ci.example.yml`](../.gitlab-ci.example.yml)
(self-hosted Ollama runner, or Claude API). It runs
`pwnguard --mode ci --mr-diff` and posts findings as MR comments when
`GITLAB_TOKEN` is set.

The job image needs `git` (PwnGuard shells out to it to build the MR
diff). `python:3.12-slim` doesn't include it, so use the full
`python:3.12` image or `apt-get install -y git` in `before_script`.

Add `ANTHROPIC_API_KEY` (and `GITLAB_TOKEN` for MR comments) as masked
CI/CD variables. Leave them unprotected, or a feature-branch MR pipeline
won't receive them.

## Log output: overview + collapsible findings

In a pipeline, PwnGuard prints a **findings overview** (one severity-ordered
row per finding) above the detailed cards, then wraps each detailed card in
a **collapsible log section** that is folded by default - so the log opens on
a scannable index and you expand only the finding you care about.

This is driven by `--platform`, which **auto-detects** the CI from its own
environment variables and needs no wiring:

| `--platform` | Behaviour |
|--------------|-----------|
| `auto` (default) | `gitlab` when `GITLAB_CI` is set, `github` when `GITHUB_ACTIONS` is set, else `plain` |
| `gitlab` | GitLab `section_start`/`section_end` collapsible sections |
| `github` | GitHub Actions `::group::` log groups |
| `plain` | overview only, no section markers (the right choice for a local terminal) |

The overview table prints on every platform, including locally. Only the
section markers are platform-specific; pass `--platform plain` to force them
off, or name a platform explicitly if auto-detection guesses wrong.

## Suppress a false positive

Do **not** reach for `allow_failure: true` or `--no-verify`: those drop
the gate for everything. Add a `pwnguard:ignore` comment in the code under
review instead (see the README's "Suppress a false positive" section). It
travels in the PR/MR diff, so the next run re-scans and that one finding
no longer blocks while the rest still count. The job log prints
`N finding(s) suppressed inline` and `--json` includes a `suppressed` count.

## Tuning

- `--threshold CRITICAL` raises the bar for the whole job (blunt; prefer
  `pwnguard:ignore` for a single false positive).
- `--report findings.md` writes a Markdown report to upload as an artifact.
- Large diffs auto-split in chunked mode (see [ollama-guide.md](ollama-guide.md)).
- An unreachable backend fails fast (exit 2) via `connect_timeout`
  (default 5s), so a down model host never hangs the job.

# PwnGuard

> **Status: Proof of Concept (`v0.2.4`).**
> PwnGuard is an open-source security tool by Shiva Kerdel (Power to Logic).
> It flags risky code when committing your work, so issues surface during
> development instead of in production. Proof of concept: flags and config
> may change before `1.0`. It points you in the right direction, but it's
> not a substitute for proper security review.

AI-powered security review for your git workflow. Catches insecure code
before it gets your organization pwned. Runs as a pre-commit hook, in
CI/CD, or against open merge requests / pull requests.

Scans git diffs (not full repos) for security issues.

## Quick start

```bash
pipx install pwnguard       # or: uv tool install pwnguard
cd your-project
pwnguard --install-hook     # scans staged changes on every git commit
```

Needs Python 3.9+ and one backend — the `claude` CLI, a local Ollama
server, or an API key. See [Setup](#setup) for the full picture.

To remove it again:

```bash
pwnguard --uninstall-hook   # run inside any repo where you installed the hook
pipx uninstall pwnguard     # removes the CLI itself
```

## Table of contents

- [Quick start](#quick-start)
- [What it does](#what-it-does)
- [Current focus](#current-focus)
- [Backends](#backends)
- [Setup](#setup)
- [Configuration files](#configuration-files)
- [Common workflows](#common-workflows)
- [CLI reference](#cli-reference)
- [Configuration reference (`pwnguard.yaml`)](#configuration-reference-pwnguardyaml)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)
- [Output modes](#output-modes)
- [Remote fetching from GitLab / GitHub](#remote-fetching-from-gitlab--github)
- [GitLab CI](#gitlab-ci)
- [Enforcement](#enforcement)
- [Limitations](#limitations)
- [Security](#security)
- [Further documentation](#further-documentation)
- [Acknowledgments](#acknowledgments)

## What it does

PwnGuard sits between you and a `git commit` (or between a contributor
and a merge-able MR) and asks a language model to look for security
issues in the **diff** of what's changing. It returns structured findings
with severity, location, description, recommendation, and (when the
backend can produce them) the offending lines and a suggested fix snippet.

You can also point it at:

- A local file (manual scan)
- A pre-saved diff on disk (offline testing)
- A live GitLab MR / commit or GitHub PR / commit (via API)

For the architecture pipeline and how findings are anchored back to
file/line, see [docs/architecture.md](docs/architecture.md).

## Current focus

The system prompt is tuned for **PHP**, **Shopware 6**, and
**CakePHP 3/4/5**, with generic coverage for common web-app vulnerability
classes across other languages. The framework hints help the model spot
ecosystem-specific patterns; the generic coverage list keeps it useful
elsewhere. Other languages / frameworks will land as configurable
"profiles" in a future release.

## Backends

| Backend | Auth | Cost | Best for |
|---------|------|------|----------|
| `claude-code` | Claude Pro subscription | Included in Pro | Local default; broad context, high recall |
| `ollama` | None | Free | CI/CD, offline, small machines |
| `claude-api` | `ANTHROPIC_API_KEY` | Pay per token | Orgs with API access; CI without runner |
| `openai-compat` | `OPENAI_API_KEY` | Depends on provider | Any OpenAI-compatible endpoint: LiteLLM, vLLM, OpenRouter, Groq, Together, Fireworks, llama.cpp server, LM Studio, etc. |

Auto-detection: locally the tool checks for the `claude` CLI first and
falls back to Ollama. In CI it uses Ollama by default; if
`ANTHROPIC_API_KEY` is set, it uses claude-api. The `openai-compat`
backend is always opt-in via `--backend openai-compat`.

For picking an Ollama model by VRAM tier, see
[docs/ollama-guide.md](docs/ollama-guide.md).

## Setup

### 1. Install PwnGuard

Recommended (isolated CLI on PATH, no PEP 668 friction):

```bash
pipx install pwnguard
# or:
uv tool install pwnguard
```

Or into a project venv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pwnguard
```

For the Anthropic API backend, pull in the optional dependency:

```bash
pipx install "pwnguard[claude-api]"
# or, on an existing pipx install:
pipx inject pwnguard anthropic
```

### 2. Install the pre-commit hook

From the root of the git repository you want to protect:

```bash
pwnguard --install-hook
```

Every `git commit` now scans the staged diff. The hook is per-clone, so
each contributor runs this once after cloning the project.

### Optional: composer auto-install (PHP projects)

To install the hook automatically when each developer runs
`composer install`, add to your `composer.json`:

```json
{
    "scripts": {
        "setup-pwnguard": "pwnguard --install-hook || echo '[pwnguard] not installed; run: pipx install pwnguard'",
        "post-install-cmd": ["@setup-pwnguard"],
        "post-update-cmd": ["@setup-pwnguard"]
    }
}
```

If you already have a `post-install-cmd`, add `"@setup-pwnguard"` to the
existing array.

### Requirements

Python 3.9+ and **one** of the backends below — pick the row that matches
your situation. Anything not in the "Required setup" column is optional;
PwnGuard ships with sensible defaults for every other knob.

| Your situation | Required setup |
|---|---|
| Default: `claude` CLI is logged in **or** Ollama is running locally | Nothing else — `pwnguard` auto-detects and uses built-in defaults |
| Anthropic API backend | `ANTHROPIC_API_KEY` env var (or a line in `.pwnguard.env`); `pipx install "pwnguard[claude-api]"` to pull in the `anthropic` package |
| Any OpenAI-compatible endpoint (LiteLLM, vLLM, OpenRouter, Groq, …) | `OPENAI_API_KEY` env var **and** an `openai:` block in `pwnguard.yaml` setting `url` and `model` |
| Scanning a GitLab MR / GitHub PR via `--from-url` | `GITLAB_TOKEN` (required for GitLab) and/or `GITHUB_TOKEN` (required for private GitHub repos) |
| Monitor mode (`--monitor`) | A `monitor.repos:` block in `pwnguard.yaml` — see [docs/monitor-mode.md](docs/monitor-mode.md) |
| Custom severity threshold, ignore patterns, model, etc. | A `pwnguard.yaml` containing only the keys you want to override — deep-merged on top of defaults |

For developing PwnGuard itself or running the test suite, see
[docs/development.md](docs/development.md).

## Configuration files

PwnGuard auto-loads config from the current working directory at startup —
the same directory `git commit` runs in, so the pre-commit hook picks up
project-local files automatically. **None of these files are required**;
without any of them, built-in defaults kick in and a one-line notice
prints to stderr.

| File | Purpose | Committed? |
|---|---|---|
| `pwnguard.yaml` (or `.pwnguard.yaml`) | Project config shared with the team | Yes |
| `pwnguard.local.yaml` (or `.pwnguard.local.yaml`) | Personal overrides, deep-merged on top of `pwnguard.yaml` | No (already in `.gitignore`) |
| `.pwnguard.env` | API tokens as `KEY=value` lines | No (already in `.gitignore`) |
| `.env` | Generic env file, lower precedence than `.pwnguard.env` | No |
| `~/.config/pwnguard/config.yaml` | Global yaml fallback across every project | n/a (home dir) |
| `~/.config/pwnguard/.pwnguard.env` | Global token fallback across every project | n/a (home dir) |

**Precedence** (highest wins): `--config <PATH>` / `--env-file <PATH>` CLI flags
→ process env vars → project file → home-dir file → built-in defaults.
`pwnguard.local.yaml` is always deep-merged on top of whichever yaml loaded.

Starter templates for `pwnguard.yaml` and `.pwnguard.env.example` live in
the [GitHub repo](https://github.com/s-kerdel/PwnGuard); copy the keys you
need rather than the whole file.

## Common workflows

> All examples below use the installed `pwnguard` CLI (from
> `pipx install pwnguard`). The pre-commit hook installed by
> `pwnguard --install-hook` runs the same command under the hood.

### Local pre-commit (default)
Hook fires automatically on `git commit`. Scans only the staged diff.
```bash
git add src/Controller/UserController.php
git commit -m "feat: add user lookup"
# PwnGuard runs, blocks if HIGH/CRITICAL findings
```

### Manual scan of one or more files
```bash
pwnguard --mode manual --files src/Foo.php src/Bar.php
```

### Scan a GitLab merge request
```bash
export GITLAB_TOKEN=glpat-...
pwnguard --from-url "https://gitlab.com/grp/proj/-/merge_requests/123"
```

### Scan only one commit of a large MR
```bash
pwnguard --from-url \
  "https://gitlab.com/grp/proj/-/merge_requests/123/diffs?commit_id=abc1234def"
```

### Scan a GitHub pull request
```bash
export GITHUB_TOKEN=ghp_...   # optional for public repos, required for private
pwnguard --from-url "https://github.com/owner/repo/pull/42"
```

### Offline review of a saved diff
```bash
git diff origin/main...HEAD > /tmp/branch.diff
pwnguard --diff-file /tmp/branch.diff --review
```

### Interactive walk through findings
```bash
pwnguard --from-url "<URL>" --review
# Use arrow keys to navigate, right/left to expand/collapse,
# space to mark, q to quit. Full key bindings: docs/review-tui.md
```

### Watch what the model is doing in real time
```bash
pwnguard --backend ollama --files src/Foo.php --debug
# Or against any OpenAI-compatible endpoint (LiteLLM, vLLM, etc.):
pwnguard --backend openai-compat --files src/Foo.php --debug
# Shows a "Waiting for response / Model is thinking" spinner during
# prompt processing, then streams tokens to stderr as they arrive,
# then prints per-request stats (tokens, t/s, stop reason).
```

### Save findings to a Markdown report
```bash
pwnguard --from-url "<URL>" --report /tmp/findings.md
```

### Bypass the hook for one commit
```bash
PWNGUARD_SKIP=1 git commit -m "WIP (intentionally skipping PwnGuard)"
# OR skip every hook for this commit:
git commit --no-verify
```

## CLI reference

Every flag accepted by `pwnguard`. Default values come from
`DEFAULT_CONFIG` unless overridden in `pwnguard.yaml`.

### Run mode + diff source

| Flag | Default | Purpose |
|------|---------|---------|
| `--mode {hook,ci,manual}` | `hook` | Source of the diff. `hook` = staged diff, `ci` = MR target-branch diff, `manual` = files you pass with `--files`. |
| `--files <PATH ...>` | (none) | Files to scan in `manual` mode. Multiple paths allowed. |
| `--mr-diff` | off | In `hook` mode, fetch the MR target-branch diff (same as `--mode ci`). |
| `--diff-file <PATH>` | (none) | Read a unified diff from disk instead of running git. Useful for offline testing or replaying a saved diff. Input is validated up front: a file that doesn't look like a unified diff (no `diff --git` / `+++ b/` headers) is refused with a precise hint pointing to `--mode manual --files <PATH>` instead. |
| `--from-url <URL>` | (none) | Fetch the diff from a GitLab MR / GitHub PR / commit URL via API. See [Remote fetching](#remote-fetching-from-gitlab--github). Same shape-check as `--diff-file`: if the platform returns HTML (auth failure, rate limit, outage) instead of a diff, the run aborts with a preview of what came back rather than silently scanning nothing. |

### Backend + model

| Flag | Default | Purpose |
|------|---------|---------|
| `--backend {claude-code,ollama,claude-api,openai-compat}` | auto-detected | Which AI backend to use. Auto-detection picks claude-code if the `claude` CLI is present, otherwise ollama. `openai-compat` is opt-in. |
| `--model <NAME>` | from config | Override the model for the active backend (e.g. `qwen2.5-coder:14b`, `claude-opus-4-7`, `claude-sonnet-4-6`). |
| `--config <PATH>` | `pwnguard.yaml` in cwd | Use a different config file. |

### Output + presentation

| Flag | Default | Purpose |
|------|---------|---------|
| `--json` | off | Emit findings as JSON on stdout. Mutually useful with `--dry-run` / piping. |
| `--quiet` | off | One-line-per-finding output. Good for terse CI logs. |
| `--no-color` | off | Disable ANSI color and OSC 8 hyperlinks. Also auto-disabled when stdout is not a TTY or when `NO_COLOR` is set. |
| `--code-preview {auto,on,off}` | `auto` | Show the affected-code block + `Example:` fix snippet. `auto` = on for claude backends, off for ollama (smaller models give imprecise line numbers and skip fix examples). |
| `--report <PATH>` | (none) | Write the findings as a Markdown report to `<PATH>`. |
| `--debug` | off | Stream the model's output live to stderr (ollama + openai-compat backends). During prompt processing a "Waiting for response..." / "Model is thinking..." spinner shows that the server is active; once tokens start arriving the spinner exits and the stream takes over. Prints per-request stats at the end (token count, tokens-per-second, stop reason). Useful when scans return empty or stop unexpectedly. |
| `--show-observations` | off | Also surface a short list (max 5) of neutral observations about defensive patterns the model noticed in the diff (e.g. "parameterised query used", "output escaped"). Opt-in and additive: never replaces findings, never claims code is secure. Rendered dim and clearly labelled "informational only" so it can't compete with HIGH/CRITICAL signal. Adds a small number of prompt + output tokens. |

### Decision flow

| Flag | Default | Purpose |
|------|---------|---------|
| `--threshold {CRITICAL,HIGH,MEDIUM,LOW,INFO}` | from config (`HIGH`) | Severity threshold that blocks (exit 1). |
| `--dry-run` | off | Show what would be sent to the AI (files, diff size, token estimate) without making the API call. |
| `--review` | off | After the scan, drop into an interactive TUI to step through findings. See [docs/review-tui.md](docs/review-tui.md). |
| `--explain <N>` | (none) | Re-query the AI for a deeper explanation of finding number `N` (1-indexed). Adds one extra AI call. |

### Performance / handling for large diffs

| Flag | Default | Purpose |
|------|---------|---------|
| `--chunk-per-file` | off (auto-enabled on overflow) | Split the diff at `diff --git` boundaries and scan each file separately, then merge findings. Auto-enabled when the estimated prompt+response exceeds Ollama's `num_ctx`. See [docs/ollama-guide.md](docs/ollama-guide.md). |
| `--ollama-format {json,raw}` | `json` | Ollama output mode. `json` forces valid JSON via constrained generation (reliable, ~2x slower on 7B). `raw` lets the model emit freely (faster, relies on PwnGuard's parse fallbacks). |

### Environment / credentials

| Flag | Default | Purpose |
|------|---------|---------|
| `--env-file <PATH>` | (none) | Load `KEY=VALUE` pairs from `<PATH>` into the environment before running. `.env` and `.pwnguard.env` in the current directory are also auto-loaded; existing process env vars always take precedence. |

### Meta

| Flag | Default | Purpose |
|------|---------|---------|
| `--version` | - | Print version and exit. |
| `-h, --help` | - | Show help and exit. |

## Configuration reference (`pwnguard.yaml`)

Every config key, its default, and what it controls. PwnGuard looks for
`pwnguard.yaml` in the current directory, then `.pwnguard.yaml`, then
`~/.config/pwnguard/config.yaml`. Override with `--config <PATH>`.

### Top-level

| Key | Default | Purpose |
|-----|---------|---------|
| `severity_threshold` | `HIGH` | Minimum severity that blocks commits / merges. One of CRITICAL / HIGH / MEDIUM / LOW / INFO. |
| `backend` | (auto-detect) | Pin the AI backend for this project (overrides hook/ci auto-detection). One of `claude-code`, `ollama`, `claude-api`, `openai-compat`. The `--backend` CLI flag always wins; per-developer override goes in `pwnguard.local.yaml`. |
| `ignore_patterns` | see source | Glob patterns to skip (per file). Defaults skip `vendor/`, `node_modules/`, `*.min.js/css/map`, lock files, common test paths. |
| `language_focus` | `[php, js, ts, twig, python]` | File extensions to scan (others are filtered out). Empty list = scan all. |
| `max_diff_lines` | `500` | Cap on unified-diff lines sent to the AI (non-chunked mode only). Lines beyond the cap are dropped with a `[TRUNCATED]` marker. Chunked mode skips this cap because per-file splitting handles size. |
| `max_file_size_kb` | `100` | Cap on a single file's size (KB) in `--mode manual`. Files larger than this are skipped with a `[SKIPPED]` marker. |

### `claude_code:` (uses the `claude` CLI)

| Key | Default | Purpose |
|-----|---------|---------|
| `timeout` | `120` | Wall-clock seconds for one `claude` invocation. |

### `claude_api:` (uses the Anthropic API)

| Key | Default | Purpose |
|-----|---------|---------|
| `model` | `claude-opus-4-7` | Model to call. Pick from Anthropic's available IDs. |
| `max_tokens` | `4096` | Output budget per response. |

### `ollama:` (uses a local Ollama server)

| Key | Default | Purpose |
|-----|---------|---------|
| `model` | `qwen2.5-coder:7b` | Ollama model tag. |
| `url` | `http://localhost:11434` | Ollama server URL. |
| `allow_remote` | `false` | Safety: only localhost / 127.0.0.1 / ::1 are allowed unless this is set true. Prevents an attacker-controlled `pwnguard.yaml` from redirecting diffs to a remote endpoint. |
| `timeout` | `600` | Wall-clock seconds per Ollama request. Higher than other backends because large diffs on 7B models can take several minutes for prompt processing alone. |
| `keep_alive` | (model default) | How long Ollama keeps the model resident in VRAM after a request. Set e.g. `"30m"` to skip the model-reload tax on back-to-back scans. |
| `num_ctx` | (model default) | Context window size. Bigger fits more diff but uses more VRAM. Note: changing this at request-time forces Ollama to reload the model; for a stable large context build a Modelfile. |
| `num_predict` | (model default) | Cap on output tokens. Useful for predictable wall time. |
| `temperature` | (model default) | Lower = more deterministic. PwnGuard's shipped config uses `0.5` for exploration. |
| `seed` | (random) | Pin the RNG for fully reproducible runs. Comment out for variation. |

### `openai:` (uses any OpenAI-compatible Chat Completions endpoint)

Works against LiteLLM, vLLM, OpenRouter, Groq, Together, Fireworks,
llama.cpp server, LM Studio, Ollama's `/v1` mode, etc. Activate with
`--backend openai-compat`.

| Key | Default | Purpose |
|-----|---------|---------|
| `url` | `https://api.openai.com` | Base URL. `/v1/chat/completions` is appended automatically. |
| `model` | `gpt-4o-mini` | Model name as the upstream endpoint expects it. |
| `api_key_env` | `OPENAI_API_KEY` | Name of the env var to read the Bearer token from. The key never lives in the yaml. |
| `allow_insecure` | `false` | Allow plaintext HTTP to non-loopback hosts. Default blocks it so the Bearer token + diff can't be intercepted on the wire. Loopback (localhost / 127.0.0.1 / ::1) is always allowed regardless. |
| `timeout` | `600` | Wall-clock seconds per request. Raise for very large diffs or slow proxies. |
| `num_predict` | (server default) | Max output tokens (maps to OpenAI's `max_tokens`). |
| `temperature` | (server default) | Lower = more deterministic. |
| `seed` | (server default) | Pin the RNG for reproducible runs (only honored by some providers). |
| `top_p` | (server default) | Nucleus-sampling cutoff. |

Security guards: the URL scheme is restricted to `http` / `https` (no
`file://` / `ftp://`); HTTP redirects are refused so the Bearer token
can never be forwarded across hosts; the destination host is printed
on every run so a stealth yaml edit is visible.

### Local override (`pwnguard.local.yaml`)

PwnGuard also auto-loads a gitignored `pwnguard.local.yaml` (or
`.pwnguard.local.yaml`) and deep-merges it on top of the main config.
Use it for machine-specific values that shouldn't land in the
committed config:

```yaml
# pwnguard.local.yaml  (gitignored)
openai:
  url: https://litellm.internal.example.com
  model: qwen3-coder-480b
```

Both file names are in the shipped `.gitignore`. The same pattern
works for any config key, not just `openai:`.

## Environment variables

PwnGuard auto-loads `.pwnguard.env` and `.env` from the current directory
at startup. You can also pass `--env-file <PATH>` for an explicit file.
Process env always wins over what's loaded from a file.

| Var | Required when | Purpose |
|-----|---------------|---------|
| `ANTHROPIC_API_KEY` | using `--backend claude-api` | Anthropic API token. |
| `OPENAI_API_KEY` (or the var named by `openai.api_key_env`) | using `--backend openai-compat` | Bearer token sent to the OpenAI-compatible endpoint. Required - PwnGuard never reads it from the yaml. |
| `GITLAB_TOKEN` (or `PWNGUARD_GITLAB_TOKEN`) | using `--from-url` against a GitLab URL | Personal Access Token with `api` or `read_api` scope. |
| `GITHUB_TOKEN` (or `PWNGUARD_GITHUB_TOKEN`) | private GitHub repos + rate-limit lift | GitHub PAT or fine-grained token. Optional for public repos. |
| `PWNGUARD_SKIP` | one-off | If set to `1`, the pre-commit hook exits 0 immediately. Bypasses just PwnGuard, leaves other hooks running. |
| `PWNGUARD_NO_PROMPT` | one-off | Suppress the "large prompt" confirmation that claude-api shows when a scan would exceed ~50k tokens. Useful for non-interactive scripts. |
| `NO_COLOR` | one-off | Standard convention. When set, ANSI styling is disabled (same as `--no-color`). |
| `CI_MERGE_REQUEST_TARGET_BRANCH_NAME` | `--mode ci` | GitLab CI provides this automatically. PwnGuard validates it and uses `git diff origin/<branch>...HEAD`. |
| `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`, `CI_SERVER_URL`, `GITLAB_TOKEN` / `CI_JOB_TOKEN` | posting comments back to a GitLab MR | All needed to post the audit result as an MR comment. |

A starter `.pwnguard.env.example` is in the repo with every variable
listed and links to where to generate the tokens.

## Exit codes

| Exit | Meaning |
|------|---------|
| `0`  | No findings at or above threshold; commit/merge may proceed. |
| `1`  | Findings exceed threshold; commit blocked. |
| `2`  | Audit could not complete (config error, AI backend failure, malformed response). |

Wire CI accordingly: treat `2` as "investigate", not as "approved".

## Output modes

The same scan can produce different output shapes based on the flags.

### Default (text, grouped by file)

Bold severity badge on the left, title, dim path:line / CWE on the right.
Body shows the affected code lines, the description, and a bold-green
`Fix:` recommendation inside a dashed card.

### `--quiet`

Same title row layout, but no body block. One line per finding. Good
for CI logs where the description doesn't add value.

### `--json`

Machine-readable. Useful for piping into other tools:

```json
{
  "findings": [
    {
      "severity": "HIGH",
      "confidence": "high",
      "title": "sql injection via user_id in lookup_user",
      "file": "app/users.py",
      "line": 244,
      "anchor": "a10",
      "description": "...",
      "recommendation": "...",
      "cwe": "CWE-89",
      "fix_example": "cur.execute('SELECT ... WHERE id = ?', (user_id,))",
      "hunk_context": "def lookup_user(user_id):"
    }
  ],
  "summary": { "HIGH": 1, "MEDIUM": 2 },
  "files_scanned": 3,
  "threshold": "HIGH",
  "blocked": true,
  "elapsed_seconds": 4.2
}
```

`file` and `line` are populated by the host after the model echoes back
its `anchor` token; consumers can rely on them. The `anchor` itself is
included for debugging / traceability.

### `--report <PATH>`

Writes the same content as the GitLab MR comment to a Markdown file.
Useful for archiving scans or attaching to issues.

### `--show-observations` (opt-in)

When set, the model is also asked to list up to 5 neutral observations
about defensive patterns it spotted in the diff (e.g. "parameterised
SELECT", "htmlspecialchars before echo", "CSRF token compared with
session"). The block is rendered dim under the findings (or under the
`PASS` line when there are none) and labelled "informational only,
not security validation":

```
Observations  ·  informational only, not security validation
  · parameterised SELECT       src/User.php:38   user_id bound via PDO
  · htmlspecialchars on output src/Show.php:92   HTML-escape before echo
```

Why opt-in: the model is forbidden from claiming code is "secure" or
"safe" - observations only describe patterns observed. Even so, a list
of "good things" can subtly give a reviewer a reason to discount real
findings, so the default behaviour stays "silent on success" and this
feature must be turned on per run. Adds a small number of prompt and
output tokens. Works best on Claude backends; 7B Ollama models may
produce noisy observations.

### `--debug`

Stream-style. Live model output to stderr while the scan runs.
Supported on the `ollama` and `openai-compat` backends. Three phases:

1. **Waiting for response** - spinner with elapsed seconds (request in flight, server hasn't replied yet).
2. **Model responding / Model is thinking** - spinner label flips once any chunk arrives; "thinking" specifically when a reasoning model (DeepSeek R1, Qwen-thinking, etc.) is emitting `reasoning_content` before its actual answer.
3. **Live token stream** - spinner exits, tokens echo to stderr as they're generated.

Per-request stats print at the end:

```
PwnGuard: prompt: 6,142 tokens  ·  output: 423 tokens  ·  84.2 t/s  ·  stop: stop
```

## Remote fetching from GitLab / GitHub

`--from-url <URL>` fetches the diff via the platform API. Auto-detects
the type from URL shape:

| URL shape | Effect |
|-----------|--------|
| `https://<gl>/<group>/<proj>/-/merge_requests/<n>` | Full MR diff |
| `https://<gl>/<group>/<proj>/-/merge_requests/<n>/diffs?commit_id=<sha>` | One commit inside the MR (handy for chunked review of big MRs) |
| `https://<gl>/<group>/<proj>/-/commit/<sha>` | Standalone commit |
| `https://github.com/<owner>/<repo>/pull/<n>` | GitHub PR |
| `https://github.com/<owner>/<repo>/commit/<sha>` | GitHub commit |

Self-hosted GitLab works (any host with the standard `/-/` URL shape).
GitHub Enterprise works via `/api/v3` on the same host.

Tokens are read from env vars (see above) or from `.pwnguard.env`.

## GitLab CI

Add the security stage from `.gitlab-ci.example.yml` to your pipeline.
Two options:

**Option A: Self-hosted runner with Ollama (no API key needed)**

- Install Ollama on the runner
- Pull the model: `ollama pull qwen2.5-coder:7b`
- Tag the runner as `security-runner`

**Option B: Claude API (if your org has API access)**

- Add `ANTHROPIC_API_KEY` to CI/CD Variables (masked, protected)

Both block merge on HIGH/CRITICAL findings and post results as MR
comments. For comment posting, set `GITLAB_TOKEN` (or use the
auto-provided `CI_JOB_TOKEN` for project-internal access).

## Enforcement

| Layer | Threshold | Bypassable |
|-------|-----------|------------|
| Pre-commit (local) | HIGH | Yes (`--no-verify` or `PWNGUARD_SKIP=1`) |
| GitLab CI (pipeline) | HIGH | No |

Both enforce the same threshold. Local is fast feedback. CI is the
hard gate.

## Limitations

- AI produces false positives. Review findings before acting.
- Cannot see runtime behaviour, only static code.
- Large diffs may be truncated on non-chunked runs (`max_diff_lines`);
  chunked mode handles this by splitting per file / per hunk.
- Cross-file context is reduced in chunked mode; cross-hunk context is
  reduced when a single file is sub-split.
- Ollama (especially 7B) is less accurate than Claude for security
  review. `--code-preview auto` hides the affected-code block on the
  ollama backend so missing-fix-example fields don't leave empty
  cards. The red `-` target marker on the exact line is currently
  suppressed globally (the model can still anchor to a function
  header instead of the inner statement); the ±3-line context window
  still renders so you see the area. File and line themselves are
  resolved via opaque anchor tokens and are reliable - the marker
  suppression is only about which row inside the window the model
  picked, not about whether the location is correct.
- Reproducibility on Ollama depends on `seed` + `temperature`; without
  pinning the seed, the same diff can produce different findings
  across runs.
- Does not replace penetration testing or manual code review.
- Currently tuned for PHP / Shopware / CakePHP, with generic coverage
  for other languages. A profile system for full multi-stack support
  is on the roadmap.

## Security

Please report vulnerabilities privately via the process in
[SECURITY.md](SECURITY.md).

## Further documentation

In-depth guides live under `docs/`:

- [Architecture & opaque anchor tokens](docs/architecture.md) — how the diff is tagged, sent to the model, and resolved back to file/line.
- [Interactive review TUI](docs/review-tui.md) — `--review` key bindings and workflow.
- [Monitor mode (`--monitor`)](docs/monitor-mode.md) — dashboard for watching remote repos and auditing each new commit as it lands.
- [Choosing an Ollama model & handling large diffs](docs/ollama-guide.md) — local-model picks by VRAM tier, plus the chunked-mode trade-off when a diff overflows the context window.
- [Development & testing](docs/development.md) — running the pytest suite, the `--self-test` entry point, and the pre-commit auto-run for this repo.

## Acknowledgments

PwnGuard is built and maintained by [Power to Logic](https://powertologic.com),
originally created at [Let's Talk](https://www.letstalk.nl) and open-sourced with
their kind permission.

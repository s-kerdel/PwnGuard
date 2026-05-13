# PwnGuard

> **Status: Proof of Concept (`v0.1.0`).**
> PwnGuard is published as a reference / portfolio piece. It works end-to-end,
> but the config schema, prompt format, and CLI flags may change without
> notice before a `1.0` release. Don't rely on it as your only line of defence.

AI-powered security review for your git workflow. Catches insecure code before
it gets your organization pwned. Runs as a pre-commit hook, in CI/CD, or
against open merge requests.

Scans git diffs (not full repos) for security issues. Installs automatically
via `composer install`.

## Current focus

The system prompt is currently tuned for **PHP**, **Shopware 6**, and
**CakePHP 3/4/5**. Other languages and frameworks will be added as configurable
"profiles" in a future release.

## Backends

| Backend | Auth | Cost | Best for |
|---------|------|------|----------|
| `claude-code` | Claude Pro subscription | Included in Pro | Local (default) |
| `ollama` | None | Free | CI/CD, offline |
| `claude-api` | ANTHROPIC_API_KEY | Pay per token | Orgs with API access |

Auto-detection: locally the tool checks for Claude Code first, falls back to
Ollama. In CI it uses Ollama by default.

## Setup

### 1. Add to your project

Copy the `pwnguard/` folder into your project root.

### 2. Merge into composer.json

Add to your existing `composer.json` scripts section:

```json
{
    "scripts": {
        "setup-pwnguard": "python3 pwnguard/install-hook.py || python pwnguard/install-hook.py || echo '[pwnguard] Python not found'",
        "post-install-cmd": [
            "@setup-pwnguard"
        ],
        "post-update-cmd": [
            "@setup-pwnguard"
        ]
    }
}
```

If you already have `post-install-cmd`, add `"@setup-pwnguard"` to the
existing array.

### 3. Run composer install

```bash
composer install
```

The pre-commit hook is now installed. Every developer who runs
`composer install` gets it automatically.

### Requirements

- Python 3.7+ (Python 2 is **not** supported; EOL since 2020)
- `pyyaml==6.0.2` (install with `pip install --user pyyaml`)
- Claude Code or Ollama for the AI backend

## How it works

```
git commit
    |
    v
pre-commit hook runs audit.py
    |
    v
Extracts staged diff (only changed files)
    |
    v
Sends to Claude Code or Ollama
    |
    v
Parses JSON response for findings
    |
    v
HIGH or CRITICAL found? --> Block commit
Otherwise                --> Allow commit
```

## Usage

```bash
# Automatic: runs on every git commit (after composer install)

# Manual scan of specific files
python3 pwnguard/audit.py --mode manual --files src/Controller/MyController.php

# Dry run (see what would be scanned)
python3 pwnguard/audit.py --mode hook --dry-run

# Force a specific backend
python3 pwnguard/audit.py --mode hook --backend ollama

# JSON output
python3 pwnguard/audit.py --mode hook --json

# Show version
python3 pwnguard/audit.py --version

# Skip the hook for one commit (just this hook, not all hooks)
PWNGUARD_SKIP=1 git commit -m "WIP"

# Skip ALL git hooks for one commit
git commit --no-verify
```

## Exit codes

| Exit | Meaning |
|------|---------|
| `0`  | No findings at or above threshold; commit/merge may proceed. |
| `1`  | Findings exceed threshold; commit blocked. |
| `2`  | Audit could not complete (config error, AI backend failure, malformed response). |

Wire CI accordingly: treat `2` as "investigate", not as "approved".

## GitLab CI

Add the security stage from `.gitlab-ci.example.yml` to your pipeline. Two
options:

**Option A: Self-hosted runner with Ollama (no API key needed)**
- Install Ollama on the runner
- Pull the model: `ollama pull qwen2.5-coder:7b`
- Tag the runner as `security-runner`

**Option B: Claude API (if org has API access)**
- Add `ANTHROPIC_API_KEY` to CI/CD Variables (masked, protected)

Both block merge on HIGH/CRITICAL findings and post results as MR comments.

## Enforcement

| Layer | Threshold | Bypassable |
|-------|-----------|------------|
| Pre-commit (local) | HIGH | Yes (`--no-verify` or `PWNGUARD_SKIP=1`) |
| GitLab CI (pipeline) | HIGH | No |

Both enforce the same threshold. Local is fast feedback. CI is the hard gate.

## Configuration

Edit `pwnguard.yaml`:

```yaml
severity_threshold: HIGH
claude_api:
  model: claude-opus-4-7
claude_code:
  timeout: 120
ollama:
  model: qwen2.5-coder:7b
  url: http://localhost:11434
  # SAFETY: only localhost is allowed by default. Set true to permit a
  # remote Ollama host (your diffs will leave the local machine).
  allow_remote: false
ignore_patterns:
  - "vendor/*"
  - "*.test.php"
language_focus:
  - php
  - js
  - ts
  - twig
```

If no config file is found, PwnGuard runs on built-in defaults and prints a
notice to stderr so you're aware.

## Limitations

- AI produces false positives. Review findings before acting.
- Cannot see runtime behaviour, only static code.
- Large diffs are truncated. Keep commits focused.
- Ollama is less accurate than Claude for security review.
- Does not replace penetration testing or manual code review.
- Currently tuned for PHP / Shopware / CakePHP. Other stacks work but with
  more false negatives until a profile system is added.

## Security

Please report vulnerabilities privately via the process in [SECURITY.md](SECURITY.md).

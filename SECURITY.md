# Security Policy

PwnGuard is currently a proof of concept. If you spot a security issue,
please **open a GitHub issue** so it can be triaged and fixed quickly.

Always run the latest commit on `main` - older versions do not receive
backports.

## Out of scope

- False positives or false negatives produced by the LLM (these are model
  limitations, not vulnerabilities - file a regular issue).
- Findings that require the attacker to already have write access to
  `pwnguard.yaml` *and* commit access *and* the ability to merge - that's
  the trust boundary for any local config file.
- DoS via extremely large diffs (mitigated by `max_diff_lines`; tune in
  `pwnguard.yaml`).
- Issues in upstream dependencies (`pyyaml`, `anthropic`, Ollama, Claude
  Code CLI) - report those upstream.

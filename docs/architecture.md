# How it works

[← Back to README](../README.md)

```
git commit
    |
    v
pre-commit hook runs `pwnguard --mode hook`
    |
    v
Extracts staged diff (only changed files)
    |
    v
Filters by ignore_patterns + language_focus
    |
    v
Tags each content line with an opaque anchor token  ([a1] [a2] ...)
and builds an anchor -> (file, line) lookup table
    |
    v
Sends to Claude Code / Claude API / Ollama / OpenAI-compat
    |
    v
Parses JSON response. Each finding carries its anchor;
the host resolves it back to (file, line) via the table
    |
    v
HIGH or CRITICAL found? --> Block commit (exit 1)
Otherwise                --> Allow commit (exit 0)
```

## Locating findings: opaque anchor tokens

Every added / context line in the diff is prefixed with a short
**opaque token** (`[a1]`, `[a2]`, ...) before it is sent to the model.
The model is told to report each finding's location by **echoing the
token back** in an `anchor` field; it does **not** report file paths
or line numbers itself. The host then resolves the anchor against the
table it built during tagging - a single dict lookup per finding.

Why it matters:

- **No line-counting drift.** Tokens are opaque - they can only be
  copied, not regenerated from "where this code probably is", which
  was the failure mode of plain line-number prefixes on smaller
  models past ~30 rows.
- **Cross-file collisions cannot happen.** Two functions named
  `lookup_user` in two files get distinct anchors, so a finding's
  file/line is never inferred by string-matching.
- **Loud failure on fabrication.** If the model invents an unknown
  token, the finding is dropped with a stderr warning instead of
  being silently mis-located.

The pipeline degrades gracefully: if a model genuinely cannot tie a
finding to one line (a project-wide config concern, missing-file
issue), it omits `anchor` and supplies a bare `file` instead. Those
file-level findings are kept; everything else must resolve through
the table.

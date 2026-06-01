# Choosing an Ollama model and handling large diffs

[← Back to README](../README.md)

## Choosing an Ollama model

Local quality scales with model size and VRAM. PwnGuard's prompt asks
the model to return JSON with optional fields (like a `fix_example` code
snippet); larger models follow the schema more reliably, smaller models
catch the obvious stuff but skip optional fields and miss subtle bugs.

Rule of thumb by VRAM (Q4 quantization):

| VRAM   | Suggested model | Realistic expectation |
|--------|-----------------|------------------------|
| 6 GB   | `qwen2.5-coder:7b` | Obvious vulns (SQLi, eval, missing CSRF); few optional fields populated |
| 8 GB   | `qwen2.5-coder:7b` (sweet spot) | Same as above with comfortable headroom for context |
| 12 GB  | `qwen2.5-coder:14b` | Better recall; more optional fields populated |
| 16 GB+ | `qwen2.5-coder:32b` / `codestral:22b` | Closest local quality to Claude; still trails on subtle / auth-bypass logic |

What lower-B models do well:

- Pattern-matching obvious sinks: `eval()`, `unserialize()` without
  allowlist, raw SQL interpolation, `file_get_contents()` on user input.
- Spotting missing escaping in templates.

What lower-B models miss:

- Multi-step / second-order vulnerabilities (data flows from A through B
  to dangerous sink C).
- Framework-specific auth bypass patterns (Shopware ACL, CakePHP
  `allowUnauthenticated`).
- Optional JSON fields like `fix_example` are frequently dropped.
- **Anchor choice quality** - the file and line themselves are always
  correct (resolved from the opaque-token table, not the model's own
  counting), but a 7B model may anchor to a function header instead
  of the exact statement inside the function. The ±3-line context
  window around the anchored line keeps the real sink visible.

If the local quality isn't enough for your codebase, switch to the
`claude-code` backend (uses your Pro subscription, no local VRAM, much
smarter). Local Ollama remains the right call for CI and offline work.

## When the diff doesn't fit in the local model

For diffs that exceed your Ollama `num_ctx` (typically big MRs touching
many files), PwnGuard auto-falls-back to **chunked mode** - splitting
the diff at `diff --git` boundaries and scanning each file
independently, then merging findings.

You can also force this manually with `--chunk-per-file`.

If a single file's diff is *itself* too big to fit in `num_ctx` (e.g.
a single file with several hundred changed lines), the chunker falls
back further: it splits that file at hunk (`@@`) boundaries and scans
each hunk group as its own sub-chunk. Each sub-chunk repeats the file
header so it parses as a self-contained mini-diff. You'll see this in
the progress output as `path/to/file.php  (part 2/4)`.

Single hunks that are themselves over budget (rare, but possible for
auto-generated code or unusually large change blocks) get sent in one
piece anyway - PwnGuard doesn't slice inside a hunk because that would
corrupt the hunk's `@@ -X,Y +A,B @@` line arithmetic.

The honest trade-off - chunked mode is **less precise but more complete**:

- **You gain**: every file actually gets reviewed, instead of half the
  MR being silently dropped at the context boundary. With hunk-level
  fallback, even a single oversized file gets scanned in pieces rather
  than truncated.
- **You lose**: cross-file context. The model sees one file at a time,
  so it doesn't know whether the sanitizer in `Helpers.php` wraps a
  call in `Controller.php`, or whether an auth helper called
  correctly-looking is actually broken upstream. With hunk-level
  fallback, you also lose cross-hunk context within the same file.
  Expect a few more false positives and the occasional missed
  cross-file (or cross-hunk) bug.

Priority hierarchy:

1. **Best**: full diff fits in context → one AI call with full
   cross-file awareness (the default when there's no overflow).
2. **Acceptable fallback**: diff overflows → chunked mode runs
   automatically. Some precision loss, but coverage beats truncation.
3. **Worst (what we avoid)**: diff overflows AND we don't chunk →
   Ollama silently truncates, half the MR is invisible.

If you want option-1 quality on a big MR, switch to
`--backend claude-code` (200k context, no chunking needed regardless
of size).

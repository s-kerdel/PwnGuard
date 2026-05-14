"""Process-wide runtime toggles set by the CLI before any work runs.

Centralised so every backend / renderer reads from the same place and
the CLI has a single import for setters. Modules read these as
``runtime.show_code_preview`` etc. (no `from runtime import X` because
that would bind a local copy that doesn't update when the CLI flips
the toggle at startup).
"""

# Whether to render the affected-code block + fix_example block.
# Backends that produce reliable line numbers and code snippets (Claude
# variants) flip this on; smaller local models default to off because
# their line numbers drift and they tend to skip fix_example anyway.
# Resolved in cli.main() based on --code-preview.
show_code_preview = True

# Whether to request Ollama's structured JSON output mode. On gives
# valid JSON guaranteed but roughly doubles generation time on 7B
# models because the constraint engine has to validate every token.
# Off is faster but relies on the model staying in schema voluntarily.
ollama_json_mode = True

# Debug mode: when enabled, the Ollama and openai-compat backends use
# streaming so the model's output appears on stderr as it's generated.
# The spinner is replaced by the live token stream - useful to see
# whether the model is actually producing findings, is stuck, or
# stopped mid-token. (Claude Code / Claude API run as single calls.)
debug_mode = False

# Whether to ask the model to also surface neutral observations about
# patterns in the diff (e.g. "parameterised SQL", "output escaped").
# Opt-in only via --show-observations: defaults off so the hook stays
# silent on success and the findings list never gets diluted.
show_observations = False


def set_code_preview(enabled: bool) -> None:
    """Toggle whether the affected-lines block and fix_example block
    are rendered. cli.main() resolves the flag/default and calls this
    once before rendering anything."""
    global show_code_preview
    show_code_preview = enabled


def set_ollama_json_mode(enabled: bool) -> None:
    """Toggle Ollama's constrained-JSON output mode. cli.main() resolves
    the flag once before any backend dispatch."""
    global ollama_json_mode
    ollama_json_mode = enabled


def set_debug_mode(enabled: bool) -> None:
    """Toggle verbose debug output (live token stream on stderr)."""
    global debug_mode
    debug_mode = enabled


def set_show_observations(enabled: bool) -> None:
    """Toggle the opt-in observations block. Resolved once in cli.main()."""
    global show_observations
    show_observations = enabled

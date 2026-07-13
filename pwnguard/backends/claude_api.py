"""Anthropic API backend (requires ``ANTHROPIC_API_KEY``).

This is the only paid path PwnGuard supports directly, so the
"large prompt" confirmation gate lives here.
"""

import os
import sys

from pwnguard import ui
from pwnguard.constants import LARGE_PROMPT_TOKEN_THRESHOLD
from pwnguard.diff import estimate_tokens
from pwnguard.prompts import SYSTEM_PROMPT
from pwnguard.security import _sanitize


def maybe_confirm_large_prompt(prompt: str, backend: str) -> None:
    """Warn before sending a very large prompt to a paid backend.

    Only prompts for confirmation on the claude-api backend (the one with
    direct per-token cost) and only when the prompt clearly crosses our
    arbitrary "this is big" threshold. The user can disable the prompt by
    setting PWNGUARD_NO_PROMPT=1 (e.g. for non-interactive scripts).
    """
    if backend != "claude-api":
        return
    if os.environ.get("PWNGUARD_NO_PROMPT") == "1":
        return
    tokens = estimate_tokens(prompt)
    if tokens < LARGE_PROMPT_TOKEN_THRESHOLD:
        return
    if not sys.stdin.isatty():
        # Non-interactive (CI) - log the size but don't block.
        print(
            ui.dim(f"PwnGuard: large prompt (~{tokens:,} tokens)."),
            file=sys.stderr,
        )
        return
    print(
        f"\nPwnGuard: estimated ~{tokens:,} input tokens for this scan.",
        file=sys.stderr,
    )
    answer = input("Send to claude-api anyway? [y/N] ").strip().lower()
    if answer != "y":
        sys.exit("Aborted by user.")


def query_claude_api(diff: str, config: dict, system_prompt: str = SYSTEM_PROMPT) -> str:
    """Send diff to Claude API for analysis (requires ANTHROPIC_API_KEY)."""
    try:
        import anthropic
    except ImportError:
        sys.exit("Error: 'anthropic' package not installed. Run: pip install anthropic")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        sys.exit("Error: ANTHROPIC_API_KEY environment variable not set")

    client = anthropic.Anthropic(api_key=api_key)
    claude_config = config.get("claude_api", {})

    user_content = f"Review this git diff for security vulnerabilities:\n\n{diff}"
    maybe_confirm_large_prompt(system_prompt + user_content, backend="claude-api")

    # TODO: parameterize thinking and max_tokens via claude_api config.
    # Adaptive thinking works on current models (4.6+) and improves recall,
    # but needs a larger max_tokens so the reasoning does not crowd out the
    # findings JSON.
    try:
        message = client.messages.create(
            model=claude_config.get("model", "claude-sonnet-5"),
            max_tokens=claude_config.get("max_tokens", 4096),
            # Thinking off; some models (e.g. claude-sonnet-5) run adaptive
            # thinking by default when omitted and prepend a ThinkingBlock.
            thinking={"type": "disabled"},
            system=system_prompt,
            messages=[{"role": "user", "content": user_content}],
        )
    except anthropic.APIConnectionError as e:
        sys.exit(f"Error: could not reach claude-api - {_sanitize(str(e))}")
    except anthropic.APIStatusError as e:
        # 400 (bad model/thinking config), 401/403 (auth), 404, 429, 5xx.
        # Sanitize the server message before printing it to the terminal.
        sys.exit(f"Error: claude-api returned {e.status_code} - {_sanitize(e.message)}")

    # Collect the text block(s); content[0] may be a non-text block.
    text = "".join(
        block.text for block in message.content if getattr(block, "type", None) == "text"
    )
    if text:
        return text

    # No text means the scan did not complete. Abort with the stop reason
    # rather than returning empty findings, which would read as a clean repo.
    reason = getattr(message, "stop_reason", None)
    if reason == "max_tokens":
        detail = "hit the max_tokens limit (raise claude_api.max_tokens)"
    elif reason == "refusal":
        detail = "model refused the request"
    else:
        detail = f"model returned no text (stop_reason={reason!r})"
    sys.exit(f"Error: claude-api scan produced no result - {detail}.")

"""Claude Code CLI backend (uses the user's Pro subscription).

The CLI is shelled out and the prompt is fed via stdin. Detection is
cached so we don't probe ``claude --version`` on every invocation.
"""

import subprocess
import sys
from typing import Optional

from pwnguard.prompts import SYSTEM_PROMPT


# Cache so we don't shell out to `claude --version` more than once per run.
_claude_code_available: Optional[bool] = None


def claude_code_available() -> bool:
    """Detect whether the `claude` CLI is installed. Cached after first call."""
    global _claude_code_available
    if _claude_code_available is not None:
        return _claude_code_available
    try:
        result = subprocess.run(
            ["claude", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        _claude_code_available = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        _claude_code_available = False
    return _claude_code_available


def query_claude_code(diff: str, config: dict, system_prompt: str = SYSTEM_PROMPT) -> str:
    """Send diff to Claude Code CLI for analysis (uses Pro subscription)."""
    if not claude_code_available():
        sys.exit(
            "Error: 'claude' CLI not found. "
            "Install Claude Code: https://docs.anthropic.com/en/docs/claude-code"
        )

    cc_config = config.get("claude_code", {})
    timeout = cc_config.get("timeout", 120)

    # Combine system prompt and user prompt for -p mode. ``diff`` arrives
    # pre-wrapped (in <diff_to_review>...</diff_to_review> with anchor
    # tokens) from dispatch_backend; the system prompt's input-format
    # rules already cover that envelope.
    full_prompt = (
        f"{system_prompt}\n\n"
        f"Review this git diff for security vulnerabilities:\n\n{diff}"
    )

    try:
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text"],
            input=full_prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        sys.exit(f"Error: Claude Code timed out after {timeout}s")
    except FileNotFoundError:
        sys.exit("Error: 'claude' command not found in PATH")

    if result.returncode != 0:
        msg = f"Error: Claude Code returned exit code {result.returncode}"
        if result.stderr:
            msg += f"\nstderr: {result.stderr[:500]}"
        sys.exit(msg)

    return result.stdout

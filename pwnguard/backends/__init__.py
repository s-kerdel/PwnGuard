"""AI backend dispatch.

Each backend lives in its own submodule (one ``query_X`` function plus
any backend-specific helpers). ``dispatch_backend`` is the single
entry point used by ``scan`` and ``monitor`` so the wrap-diff /
anchor-table contract is enforced in one place.
"""

from typing import Optional

from pwnguard import runtime
from pwnguard.anchors import wrap_diff
from pwnguard.prompts import build_system_prompt

from pwnguard.backends.claude_api import query_claude_api
from pwnguard.backends.claude_code import claude_code_available, query_claude_code
from pwnguard.backends.ollama import query_ollama
from pwnguard.backends.openai_compat import query_openai_compat


__all__ = [
    "claude_code_available",
    "dispatch_backend",
    "query_claude_api",
    "query_claude_code",
    "query_ollama",
    "query_openai_compat",
]


def dispatch_backend(
    backend: str,
    diff: str,
    config: dict,
    system_prompt: Optional[str] = None,
    pre_wrapped: bool = False,
) -> tuple:
    """Run the requested backend. Centralizes the dispatch logic.

    Wraps ``diff`` (assigning anchor tokens) and ships only the
    wrapped text to the backend; returns ``(response, anchor_table)``
    so the caller can resolve each finding's ``anchor`` field with a
    single dict lookup.

    Set ``pre_wrapped=True`` when the caller has already embedded a
    wrapped diff inside its own custom ``system_prompt`` (the
    --explain path is the only current case). In that mode the
    anchor table comes back empty - explain is a re-query for one
    already-resolved finding, so it doesn't need anchors.

    When no system_prompt is given, builds one from the current code-preview
    setting: if the caller won't render fix_example, we don't ask the model
    to generate it (saves a few hundred tokens of prompt + output time on
    7B local models).
    """
    if system_prompt is None:
        system_prompt = build_system_prompt(
            include_preview_fields=runtime.show_code_preview,
            include_observations=runtime.show_observations,
        )
    if pre_wrapped:
        wrapped, anchors = diff, {}
    else:
        wrapped, anchors = wrap_diff(diff)
    if backend == "claude-api":
        response = query_claude_api(wrapped, config, system_prompt)
    elif backend == "claude-code":
        response = query_claude_code(wrapped, config, system_prompt)
    elif backend == "openai-compat":
        response = query_openai_compat(wrapped, config, system_prompt)
    else:
        response = query_ollama(wrapped, config, system_prompt)
    return response, anchors

"""Security primitives shared across the package.

These boundary defences protect what the auditor surfaces and what gets
handed to ``git``. A regression here is a security regression, not a
feature regression.
"""

import re
from typing import Optional


# Matches ANSI/C0 control characters that could be used for terminal injection
# (cursor moves, color, clear screen, line-overwrite via CR, etc.). Tab (0x09)
# and LF (0x0a) are preserved so multi-line descriptions still wrap normally.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _sanitize(text: Optional[str]) -> Optional[str]:
    """Strip control characters from AI-supplied text.

    The model is told not to include special characters, but a prompt-injected
    diff could coax it into emitting \\x1b[31m and friends. Printing those raw
    would let an attacker recolor / hide / fake content in the dev's terminal
    or in CI logs viewed via tail. We strip control chars at the parse layer
    so every downstream consumer (terminal, markdown, JSON, report) gets
    pre-cleaned data.
    """
    if not text:
        return text
    return _CONTROL_CHAR_RE.sub("", text)


def _is_safe_ref(ref: str) -> bool:
    """Reject branch names that could be parsed as a git option or path traversal.

    CI_MERGE_REQUEST_TARGET_BRANCH_NAME is set by GitLab from the MR's target
    branch, which an attacker who can open MRs partly controls. Without this
    check, a name like ``--upload-pack=evil`` would land as a git flag.
    """
    if not ref or ref.startswith("-") or ref.startswith("/"):
        return False
    if ".." in ref or "\n" in ref or "\x00" in ref:
        return False
    return True

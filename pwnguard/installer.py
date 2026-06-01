"""Install the PwnGuard git pre-commit hook into a project's .git/hooks/.

Reachable from two entry points:

  * ``pwnguard --install-hook`` (the supported path after the pip /
    pipx migration). Run from inside the consumer's git repository.
  * ``install-hook.py`` at the PwnGuard repo root (legacy shim kept
    for the standalone-clone dev workflow).
"""

from __future__ import annotations

import os
import stat
import subprocess
from importlib import resources
from typing import Optional

# Bump the version suffix when the shipped hook script changes in an
# incompatible way; older installs are then refreshed on next run.
HOOK_SENTINEL = "PWNGUARD_HOOK_V3"

# Prefix used to detect "this hook was previously installed by PwnGuard
# (at any version)". A version-pinned check would refuse to overwrite
# older PwnGuard hooks during an upgrade.
HOOK_OWNED_PREFIX = "PWNGUARD_HOOK_"


def _git_toplevel(start: str) -> Optional[str]:
    """Return the git repository root containing ``start``, or None."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start,
            capture_output=True,
            text=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    toplevel = result.stdout.strip()
    return toplevel or None


def install_hook(project_root: Optional[str] = None) -> int:
    """Install the PwnGuard pre-commit hook into ``project_root/.git/hooks/``.

    If ``project_root`` is None, defaults to the git toplevel of the
    current working directory. Returns 0 on success, non-zero on
    failures the caller should surface as an exit code.
    """
    if project_root is None:
        project_root = _git_toplevel(os.getcwd())
        if project_root is None:
            print("  [pwnguard] Not inside a git repository. Run from your project root.")
            return 1

    git_hooks_dir = os.path.join(project_root, ".git", "hooks")
    target_hook = os.path.join(git_hooks_dir, "pre-commit")

    if not os.path.isdir(os.path.join(project_root, ".git")):
        print("  [pwnguard] Not a git repo, skipping hook install")
        return 1

    os.makedirs(git_hooks_dir, exist_ok=True)

    hook_source = (
        resources.files("pwnguard.data")
        .joinpath("pre-commit")
        .read_text(encoding="utf-8")
    )

    if os.path.exists(target_hook):
        try:
            with open(target_hook, "r") as f:
                existing = f.read()
        except OSError:
            existing = ""
        if HOOK_OWNED_PREFIX not in existing:
            print("  [pwnguard] Existing pre-commit hook found, not overwriting")
            print("  [pwnguard] Add this line to your hook:")
            print("    pwnguard --mode hook")
            return 0
        if HOOK_SENTINEL in existing:
            print("  [pwnguard] Pre-commit hook already up to date")
        else:
            print(f"  [pwnguard] Upgrading pre-commit hook to {HOOK_SENTINEL}")
    else:
        print("  [pwnguard] Installing pre-commit hook")

    with open(target_hook, "w") as f:
        f.write(hook_source)

    if os.name != "nt":
        st = os.stat(target_hook)
        os.chmod(target_hook, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print("  [pwnguard] Pre-commit hook installed")
    return 0


def uninstall_hook(project_root: Optional[str] = None) -> int:
    """Remove the PwnGuard pre-commit hook from ``project_root/.git/hooks/``.

    Only removes the hook when PwnGuard owns it (detected via the
    ``PWNGUARD_HOOK_`` sentinel). A user-owned or third-party hook is
    left untouched. Returns 0 on success or when there's nothing to do,
    non-zero only when not inside a git repository.
    """
    if project_root is None:
        project_root = _git_toplevel(os.getcwd())
        if project_root is None:
            print("  [pwnguard] Not inside a git repository. Run from your project root.")
            return 1

    target_hook = os.path.join(project_root, ".git", "hooks", "pre-commit")

    if not os.path.exists(target_hook):
        print("  [pwnguard] No pre-commit hook to remove")
        return 0

    try:
        with open(target_hook, "r") as f:
            existing = f.read()
    except OSError:
        existing = ""

    if HOOK_OWNED_PREFIX not in existing:
        print("  [pwnguard] pre-commit hook is not owned by PwnGuard, leaving it in place")
        return 0

    os.remove(target_hook)
    print("  [pwnguard] Pre-commit hook removed")
    return 0

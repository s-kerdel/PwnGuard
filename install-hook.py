#!/usr/bin/env python3
"""
Install the PwnGuard git pre-commit hook.
Called automatically by composer post-install-cmd / post-update-cmd.
Works on Windows, Linux, and macOS.
"""

import os
import shutil
import stat

# Bump the version suffix when the shipped hook script changes in an
# incompatible way; older installs are then refreshed on next composer run.
HOOK_SENTINEL = "PWNGUARD_HOOK_V1"


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    git_hooks_dir = os.path.join(project_root, ".git", "hooks")
    source_hook = os.path.join(script_dir, "hooks", "pre-commit")
    target_hook = os.path.join(git_hooks_dir, "pre-commit")

    if not os.path.isdir(os.path.join(project_root, ".git")):
        print("  [pwnguard] Not a git repo, skipping hook install")
        return

    os.makedirs(git_hooks_dir, exist_ok=True)

    if os.path.exists(target_hook):
        try:
            with open(target_hook, "r") as f:
                content = f.read()
        except OSError:
            content = ""
        if HOOK_SENTINEL not in content:
            print("  [pwnguard] Existing pre-commit hook found, not overwriting")
            print("  [pwnguard] Add this line to your hook:")
            print("    python3 pwnguard/audit.py --mode hook")
            return
        print("  [pwnguard] Updating pre-commit hook")
    else:
        print("  [pwnguard] Installing pre-commit hook")

    shutil.copy2(source_hook, target_hook)

    if os.name != "nt":
        st = os.stat(target_hook)
        os.chmod(target_hook, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print("  [pwnguard] Pre-commit hook installed")


if __name__ == "__main__":
    main()

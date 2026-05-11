#!/usr/bin/env python3
"""
Install the PwnGuard git pre-commit hook.
Called automatically by composer post-install-cmd / post-update-cmd.
Works on Windows, Linux, and macOS.
"""

import os
import sys
import shutil
import stat

HOOK_MARKER = "pwnguard"


def main():
    # Find project root (where composer.json lives)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    git_hooks_dir = os.path.join(project_root, ".git", "hooks")
    source_hook = os.path.join(script_dir, "hooks", "pre-commit")
    target_hook = os.path.join(git_hooks_dir, "pre-commit")

    # Check we're in a git repo
    if not os.path.isdir(os.path.join(project_root, ".git")):
        print("  [pwnguard] Not a git repo, skipping hook install")
        return

    # Create hooks dir if needed
    os.makedirs(git_hooks_dir, exist_ok=True)

    # Check for existing hook that isn't ours
    if os.path.exists(target_hook):
        with open(target_hook, 'r') as f:
            content = f.read()
        if HOOK_MARKER not in content:
            print("  [pwnguard] Existing pre-commit hook found, not overwriting")
            print(f"  [pwnguard] Add this line to your hook: python3 pwnguard/audit.py --mode hook")
            return
        # Our hook already installed, update it
        print("  [pwnguard] Updating pre-commit hook")
    else:
        print("  [pwnguard] Installing pre-commit hook")

    # Copy hook
    shutil.copy2(source_hook, target_hook)

    # Make executable (Linux/macOS)
    if os.name != 'nt':
        st = os.stat(target_hook)
        os.chmod(target_hook, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print("  [pwnguard] Pre-commit hook installed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Legacy shim. Delegates to ``pwnguard.installer.install_hook``.

Kept so the existing composer ``post-install-cmd`` flow and any
documented ``python3 install-hook.py`` invocations keep working
against a clone of the PwnGuard repository. New consumers should
use ``pwnguard --install-hook`` after ``pipx install pwnguard``.
"""

import os
import sys


def main() -> int:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    from pwnguard.installer import install_hook
    return install_hook(project_root=script_dir)


if __name__ == "__main__":
    sys.exit(main())

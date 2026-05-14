"""Configuration loading: pwnguard.yaml + local overrides + env files."""

import os
import sys

import yaml

from pwnguard import ui
from pwnguard.constants import DEFAULT_CONFIG

from typing import Optional


def load_config(config_path: Optional[str] = None) -> dict:
    """Load config from yaml file, falling back to defaults.

    Prints a one-line notice to stderr if no config file was found so users
    are aware they're running on built-in defaults (e.g. the wrong model,
    or the default severity threshold).
    """
    config = DEFAULT_CONFIG.copy()

    paths_to_try = [
        config_path,
        "pwnguard.yaml",
        ".pwnguard.yaml",
        os.path.expanduser("~/.config/pwnguard/config.yaml"),
    ]

    loaded_from = None
    for path in paths_to_try:
        if path and os.path.exists(path):
            with open(path) as f:
                user_config = yaml.safe_load(f) or {}
            deep_merge(config, user_config)
            loaded_from = path
            break

    if loaded_from is None:
        print(
            ui.dim("PwnGuard: no pwnguard.yaml found; using built-in defaults."),
            file=sys.stderr,
        )

    # Local, gitignored override. Lets a developer set machine-specific
    # values (e.g. their own openai.url + model) without leaking into the
    # committed pwnguard.yaml. Deep-merges on top, so it can override any
    # subset of keys.
    for local_path in ("pwnguard.local.yaml", ".pwnguard.local.yaml"):
        if os.path.exists(local_path):
            with open(local_path) as f:
                local_config = yaml.safe_load(f) or {}
            deep_merge(config, local_config)
            print(
                ui.dim(f"PwnGuard: merged local overrides from {local_path}"),
                file=sys.stderr,
            )
            break

    return config


def deep_merge(base: dict, override: dict) -> None:
    """Recursively merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value


# ---------------------------------------------------------------------------
# Env file loading (.env, .pwnguard.env)
# ---------------------------------------------------------------------------

def _load_env_file(path: str) -> int:
    """Load KEY=VALUE lines from ``path`` into os.environ.

    Returns the number of variables actually set. Does NOT overwrite
    existing process env vars - anything you already ``export``-ed
    takes precedence. Skips blank lines, ``#`` comments, and malformed
    rows. Strips a single leading ``export`` and surrounding quotes
    around the value.
    """
    if not os.path.exists(path):
        return 0
    loaded = 0
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # Allow `export KEY=value` for shell-script compatibility.
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if not key:
                    continue
                # Strip a matched pair of surrounding quotes.
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                if key in os.environ:
                    # Process env wins; env files are only a fallback so
                    # `GITLAB_TOKEN=… python audit.py …` keeps working
                    # even with a stale .env on disk.
                    continue
                os.environ[key] = value
                loaded += 1
    except OSError as e:
        print(
            ui.dim(f"PwnGuard: could not read env file {path}: {e}"),
            file=sys.stderr,
        )
        return 0
    return loaded


def _maybe_load_env_files(explicit_path: Optional[str]) -> None:
    """Auto-load .pwnguard.env / .env from cwd plus any --env-file path.

    Order is deliberate: the explicit --env-file is processed first so
    it gets the lowest-precedence slot among files but the highest
    among files-vs-files (it sets keys before the auto-detected files
    have a chance to). Process env always overrides everything via the
    ``key in os.environ`` guard inside _load_env_file().
    """
    sources = []
    if explicit_path:
        n = _load_env_file(explicit_path)
        if n > 0:
            sources.append(f"{explicit_path} ({n})")
    for path in (".pwnguard.env", ".env"):
        n = _load_env_file(path)
        if n > 0:
            sources.append(f"{path} ({n})")
    if sources:
        print(
            ui.dim(f"PwnGuard: loaded env from {', '.join(sources)}"),
            file=sys.stderr,
        )

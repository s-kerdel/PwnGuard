"""Shared backend networking helper.

Keeps the connect-reachability check in one place so the Ollama and
openai-compat backends fail fast on an unreachable host instead of
blocking on their (deliberately large) request timeout.
"""

import socket
import sys
import urllib.parse

from pwnguard.security import _sanitize


def preflight_connect(url: str, connect_timeout: float, label: str) -> None:
    """TCP-connect to the URL's host:port with a short timeout.

    The request timeout is sized for slow generation (minutes), so on its
    own an unreachable host would hang that long before failing. A quick
    connect probe up front turns "server down / wrong host" into a clear
    error in seconds. Exits on failure; returns on success. A reachable
    host that is merely slow to respond is still covered by the request
    timeout afterwards.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host:
        return  # URL validation in the caller surfaces a clearer error.
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=connect_timeout):
            return
    except OSError as e:
        sys.exit(
            f"Error: cannot reach the {label} server at "
            f"{_sanitize(host)}:{port} ({e.__class__.__name__}: {e}). "
            f"Check the server is running and the url is correct, or raise "
            f"{label}.connect_timeout if it is just slow to accept."
        )

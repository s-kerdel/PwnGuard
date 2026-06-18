"""Tests for the backend connect pre-flight.

The model request timeout is sized for slow generation (minutes), so an
unreachable host must be caught by a separate short connect probe rather
than blocking on that full timeout.
"""
import socket
import time

import pytest

from pwnguard.backends._net import preflight_connect


def test_preflight_succeeds_against_a_listening_socket():
    # Bind an ephemeral port and listen so the connect succeeds.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        # Returns (no SystemExit) when the host:port accepts a connection.
        preflight_connect(f"http://127.0.0.1:{port}", 2, "ollama")
    finally:
        srv.close()


def test_preflight_exits_fast_on_refused_connection():
    # Bind then close so the port is almost certainly not listening.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()

    start = time.monotonic()
    with pytest.raises(SystemExit) as exc:
        preflight_connect(f"http://127.0.0.1:{port}", 5, "ollama")
    # Refused connections come back immediately, well under the timeout.
    assert time.monotonic() - start < 2
    # The message names the backend and points at the connect-timeout knob.
    assert "ollama" in str(exc.value)
    assert "connect_timeout" in str(exc.value)


def test_preflight_no_host_is_a_noop():
    # A URL with no hostname returns without connecting; the caller's URL
    # validation surfaces a clearer error.
    preflight_connect("not-a-url", 1, "openai")

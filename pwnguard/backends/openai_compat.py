"""OpenAI-compatible Chat Completions backend.

Targets the de-facto-standard OpenAI API shape so the same backend
works against LiteLLM, vLLM, OpenRouter, Groq, Together, Fireworks,
llama.cpp server, LM Studio, Ollama's /v1 mode, etc. API key is read
from an env var (default ``OPENAI_API_KEY``) so it never lands in the
committed yaml.

Security guards:
- URL scheme restricted to http/https.
- HTTP redirects refused so the Bearer token can't be forwarded
  across hosts.
- Plaintext HTTP refused to non-loopback hosts unless the user opts
  in via ``openai.allow_insecure``.
"""

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from pwnguard import runtime, ui
from pwnguard.constants import LOOPBACK_HOSTS
from pwnguard.prompts import SYSTEM_PROMPT
from pwnguard.security import _sanitize


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse to follow HTTP redirects.

    urllib's default behaviour forwards the Authorization header to the
    redirect target, even across origins - a 302 from the configured
    endpoint to attacker.example would leak the Bearer token. Returning
    None here makes urllib raise the redirect status as an HTTPError,
    which our caller surfaces cleanly.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Built once: a no-redirect opener for the openai-compat backend. Reusing
# it across requests is cheap and avoids re-installing handlers globally.
_openai_opener = urllib.request.build_opener(_NoRedirectHandler())


def query_openai_compat(diff: str, config: dict, system_prompt: str = SYSTEM_PROMPT) -> str:
    """Send diff to an OpenAI-compatible Chat Completions endpoint.

    Targets the de-facto-standard OpenAI API shape so the same backend
    works against LiteLLM, vLLM, OpenRouter, Groq, Together, Fireworks,
    llama.cpp server, LM Studio, etc. API key is read from an env var
    (default OPENAI_API_KEY) so it never lands in the committed yaml.
    """
    openai_config = config.get("openai", {})
    base_url = (openai_config.get("url") or "https://api.openai.com").rstrip("/")
    model = openai_config.get("model", "gpt-4o-mini")
    timeout = openai_config.get("timeout", 600)
    key_env = openai_config.get("api_key_env", "OPENAI_API_KEY")
    allow_insecure = bool(openai_config.get("allow_insecure", False))

    # Validate the URL before we do anything else. urllib happily accepts
    # file:// (read local file), ftp://, and data:// schemes - none of
    # which belong here and which a hostile yaml could exploit. urlparse
    # itself can raise on malformed input (e.g. stray '[' from an ANSI
    # escape in the yaml), so wrap it.
    try:
        parsed = urllib.parse.urlparse(base_url)
    except ValueError as e:
        sys.exit(
            f"Error: openai.url is malformed ({e}). Got: "
            f"{_sanitize(base_url)!r}"
        )
    if parsed.scheme not in ("http", "https"):
        sys.exit(
            f"Error: openai.url scheme must be http or https, got "
            f"{parsed.scheme!r}. Refusing to send to {_sanitize(base_url)!r}."
        )
    host = parsed.hostname or ""
    if not host:
        sys.exit(
            f"Error: openai.url has no hostname: {_sanitize(base_url)!r}."
        )
    # Block plaintext HTTP unless loopback (key/diff can't be intercepted
    # locally) or the user has explicitly opted in. Sending a Bearer token
    # and an entire repo diff over the clear is a real, easy-to-miss leak.
    if parsed.scheme == "http" and host not in LOOPBACK_HOSTS and not allow_insecure:
        sys.exit(
            f"Error: refusing to send diff + API key over plaintext HTTP to "
            f"{_sanitize(host)!r}. Use https://, or set "
            f"openai.allow_insecure: true to override (you accept that the "
            f"diff and Bearer token travel unencrypted)."
        )

    api_key = os.environ.get(key_env)
    if not api_key:
        sys.exit(
            f"Error: {key_env} environment variable not set. "
            f"Set it (or change openai.api_key_env in pwnguard.yaml) "
            f"before using --backend openai-compat."
        )

    # The "PwnGuard: sending diff to <host> (model: <name>)" heads-up
    # is printed by run_scan's pre-flight block (and similarly before
    # explain_finding's re-query if needed) so it appears BEFORE the
    # spinner, not after "Scanning with openai-compat..." has already
    # started. Validation above still gates the actual request.

    payload_dict: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"Review this git diff for security vulnerabilities:\n\n{diff}",
            },
        ],
        "stream": bool(runtime.debug_mode),
    }
    # Same JSON-output toggle as the Ollama backend: when on, ask the
    # server to constrain output to a JSON object. Supported by OpenAI,
    # LiteLLM, vLLM (with guided_json), and most other proxies, but not
    # universal - so openai-compat defaults this off (see cli.main) and
    # users opt in with --format json on servers that support it.
    if runtime.json_output_mode:
        payload_dict["response_format"] = {"type": "json_object"}

    # Forward optional tunables. num_predict -> max_tokens to match
    # OpenAI's naming while keeping the same yaml key the user already
    # knows from the Ollama block.
    if (np := openai_config.get("num_predict")) is not None:
        payload_dict["max_tokens"] = np
    for opt_key in ("temperature", "seed", "top_p"):
        if opt_key in openai_config:
            payload_dict[opt_key] = openai_config[opt_key]

    # In streaming mode, request the final usage chunk so we can print
    # the same prompt/output-token metrics the Ollama backend shows.
    if payload_dict["stream"]:
        payload_dict["stream_options"] = {"include_usage": True}

    payload = json.dumps(payload_dict).encode()
    req = urllib.request.Request(
        f"{base_url}/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    try:
        if runtime.debug_mode:
            return _query_openai_compat_stream(req, timeout, base_url)
        with _openai_opener.open(req, timeout=timeout) as resp:
            raw_body = resp.read()
    except urllib.error.HTTPError as e:
        # Surface the server's error body when present (LiteLLM and
        # OpenAI both return useful JSON error messages here). A 3xx
        # also lands here because we refuse redirects - that's
        # intentional, the message tells the user to update the URL.
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        if 300 <= e.code < 400:
            sys.exit(
                f"Error: {_sanitize(base_url)} responded with redirect "
                f"HTTP {e.code} (refused - Bearer token must not be "
                f"forwarded across hosts). Update openai.url to the "
                f"final endpoint."
            )
        sys.exit(
            f"Error: {_sanitize(base_url)} returned HTTP {e.code}: "
            f"{_sanitize(body) or e.reason}"
        )
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        msg = str(e)
        if "timed out" in msg.lower():
            sys.exit(
                f"Request timed out after {timeout}s. Raise openai.timeout "
                f"in pwnguard.yaml for large diffs or slower proxies."
            )
        sys.exit(f"Error: cannot reach {_sanitize(base_url)}: {e}")

    # Decode + parse defensively: misconfigured proxies often return
    # HTML error pages or empty bodies on 200, which would otherwise
    # raise a cryptic JSONDecodeError mid-pipeline.
    try:
        data = json.loads(raw_body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        snippet = _sanitize(raw_body[:300].decode("utf-8", errors="replace")) or "(empty)"
        sys.exit(
            f"Error: {_sanitize(base_url)} returned a non-JSON response "
            f"({e.__class__.__name__}). First bytes: {snippet!r}"
        )

    # OpenAI-shaped response: choices[0].message.content
    choices = data.get("choices") if isinstance(data, dict) else None
    if not choices or not isinstance(choices, list):
        err = data.get("error") if isinstance(data, dict) else None
        snippet = _sanitize(str(err or data)[:300]) or "(empty)"
        sys.exit(f"Error: unexpected OpenAI-compatible response: {snippet}")
    message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
    content = message.get("content")
    if not content:
        # Empty content is what OpenAI returns on safety-stop refusals
        # or some proxies' rate-limit/quota responses. Treat as no findings
        # rather than crashing the whole scan.
        return '{"findings": []}'
    return content


def _query_openai_compat_stream(req: urllib.request.Request, timeout: int, base_url: str) -> str:
    """Stream an OpenAI-compatible SSE response, echoing tokens to stderr.

    Mirrors _query_ollama_stream but parses Server-Sent Events
    (`data: {...}\\n\\n` with a `data: [DONE]` sentinel) instead of
    NDJSON. Returns the accumulated content so the rest of the
    pipeline treats it identically to a non-streamed response.

    Shows a "waiting for first token" spinner during TTFT. LiteLLM and
    other proxies fronting large models can sit silent for many seconds
    while prompt processing runs before the first delta arrives.
    """
    full_content = ""
    final_usage: dict = {}
    finish_reason: Optional[str] = None
    waiting = ui.Spinner("Waiting for response (openai-compat)")
    waiting.__enter__()
    first_token_seen = False
    any_chunk_seen = False
    thinking_seen = False
    try:
        # Same no-redirect opener as the non-stream path: never allow
        # the Authorization header to be forwarded to a different host.
        with _openai_opener.open(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.strip()
                if not line or not line.startswith(b"data:"):
                    continue
                data_str = line[len(b"data:"):].strip()
                if data_str == b"[DONE]":
                    break
                try:
                    chunk = json.loads(data_str.decode())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                # First sign of life from the server: switch the spinner
                # label so the user sees "model is working", not just
                # "still waiting". The spinner thread reads .label every
                # frame so a plain assignment is enough.
                if not any_chunk_seen:
                    any_chunk_seen = True
                    waiting.label = "Model responding (openai-compat)"
                # Usage-only chunks (sent last when stream_options.include_usage
                # is set) carry no choices; capture and continue.
                if usage := chunk.get("usage"):
                    final_usage = usage
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta", {}) if isinstance(choices[0], dict) else {}
                # Reasoning models (DeepSeek R1, Qwen-thinking, etc.) emit
                # `reasoning_content` (or `reasoning`) deltas before any
                # real content. Surface that explicitly so the user knows
                # the model is in its thinking phase, not stalled.
                reasoning = delta.get("reasoning_content") or delta.get("reasoning") or ""
                if reasoning and not thinking_seen:
                    thinking_seen = True
                    waiting.label = "Model is thinking (openai-compat)"
                content = delta.get("content", "") or ""
                if content:
                    if not first_token_seen:
                        first_token_seen = True
                        waiting.__exit__(None, None, None)
                        print(ui.dim("--- begin model output ---"), file=sys.stderr)
                    full_content += content
                    sys.stderr.write(ui.dim(content))
                    sys.stderr.flush()
                if (fr := choices[0].get("finish_reason")) is not None:
                    finish_reason = fr
    except urllib.error.HTTPError as e:
        if not first_token_seen:
            waiting.__exit__(None, None, None)
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        if 300 <= e.code < 400:
            sys.exit(
                f"\nError: {_sanitize(base_url)} responded with redirect "
                f"HTTP {e.code} (refused - Bearer token must not be "
                f"forwarded across hosts). Update openai.url to the "
                f"final endpoint."
            )
        sys.exit(
            f"\nError: {_sanitize(base_url)} returned HTTP {e.code}: "
            f"{_sanitize(body) or e.reason}"
        )
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        if not first_token_seen:
            waiting.__exit__(None, None, None)
        msg = str(e)
        if "timed out" in msg.lower():
            sys.exit(
                f"\nRequest timed out after {timeout}s. Raise openai.timeout "
                f"in pwnguard.yaml for large diffs or slower proxies."
            )
        sys.exit(f"\nError: cannot reach {_sanitize(base_url)}: {e}")
    finally:
        # Stream ended without ever producing a token (server closed
        # cleanly, empty response, refusal, etc.): stop the spinner
        # thread so the program can exit.
        if not first_token_seen:
            waiting.__exit__(None, None, None)

    # Capture elapsed since the first token arrived (waiting.elapsed
    # reflects the TTFT phase; subtracting it from total gives a fair
    # generation-time figure for the t/s estimate).
    total_elapsed = time.monotonic() - (waiting._start or time.monotonic())
    gen_elapsed = max(0.001, total_elapsed - waiting.elapsed)

    sys.stderr.write("\n")
    print(ui.dim("--- end model output ---"), file=sys.stderr)
    # Per-request diagnostics, same shape as the Ollama summary line.
    bits = []
    if final_usage:
        if pt := final_usage.get("prompt_tokens"):
            bits.append(f"prompt: {pt} tokens")
        if ct := final_usage.get("completion_tokens"):
            bits.append(f"output: {ct} tokens")
            bits.append(f"{ct / gen_elapsed:.1f} t/s")
    if finish_reason:
        bits.append(f"stop: {finish_reason}")
    if bits:
        print(ui.dim("PwnGuard: " + "  ·  ".join(bits)), file=sys.stderr)
    return full_content

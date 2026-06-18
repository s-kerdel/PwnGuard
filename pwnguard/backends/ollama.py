"""Local Ollama backend.

Refuses to ship the diff to a non-loopback host unless the user has
explicitly opted in (``ollama.allow_remote: true``) - otherwise an
attacker-controlled ``pwnguard.yaml`` could redirect every diff to
an external endpoint.
"""

import json
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

from pwnguard import runtime, ui
from pwnguard.constants import SAFE_OLLAMA_HOSTS
from pwnguard.prompts import SYSTEM_PROMPT
from pwnguard.security import _sanitize


def query_ollama(diff: str, config: dict, system_prompt: str = SYSTEM_PROMPT) -> str:
    """Send diff to local Ollama instance for analysis."""
    ollama_config = config.get("ollama", {})
    url = ollama_config.get("url", "http://localhost:11434")
    model = ollama_config.get("model", "qwen2.5-coder:7b")
    allow_remote = ollama_config.get("allow_remote", False)
    timeout = ollama_config.get("timeout", 600)

    # Refuse to send the diff to a non-local host unless explicitly opted in.
    # Otherwise a committed pwnguard.yaml pointing ollama.url at an external
    # endpoint would silently exfiltrate every diff at the next CI run.
    host = urllib.parse.urlparse(url).hostname or ""
    if host not in SAFE_OLLAMA_HOSTS and not allow_remote:
        sys.exit(
            f"Refusing to send diff to non-local Ollama host: {host!r}.\n"
            f"Set ollama.allow_remote: true in pwnguard.yaml to override "
            f"(you accept that diffs leave the local machine)."
        )

    payload_dict = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"Review this git diff for security vulnerabilities:\n\n{diff}",
            },
        ],
    }
    # Ollama's "format": "json" mode constrains every generated token to
    # produce valid JSON. Reliable but slow (~2x on 7B). When the user
    # opts out, parse_response's regex-extract + escape-fix fallbacks
    # are what catch any non-JSON preamble / markdown fences.
    if runtime.json_output_mode:
        payload_dict["format"] = "json"

    # Forward optional model tunables. Each is opt-in via config so the
    # default behaviour matches whatever the model's own defaults are.
    keep_alive = ollama_config.get("keep_alive")
    if keep_alive:
        payload_dict["keep_alive"] = keep_alive
    options = {}
    for opt_key in ("num_ctx", "num_predict", "temperature", "seed"):
        if opt_key in ollama_config:
            options[opt_key] = ollama_config[opt_key]
    if options:
        payload_dict["options"] = options

    # Debug mode uses streaming so the user sees the model's output as it
    # arrives. Non-debug mode keeps the single-blob request (works with
    # the spinner and stays quieter for normal use).
    payload_dict["stream"] = bool(runtime.debug_mode)
    payload = json.dumps(payload_dict).encode()

    req = urllib.request.Request(
        f"{url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        if runtime.debug_mode:
            return _query_ollama_stream(req, timeout, url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        msg = str(e)
        if "timed out" in msg.lower():
            sys.exit(
                f"Ollama request timed out after {timeout}s. For large "
                f"diffs, raise ollama.timeout in pwnguard.yaml or switch "
                f"to --backend claude-code (much faster on large inputs)."
            )
        sys.exit(
            f"Error: cannot reach Ollama at {url}: {e}\n"
            f"Is Ollama running (ollama serve)?"
        )

    # Ollama returns {"message": {"content": ...}} on success, but error
    # responses or unexpected shapes would otherwise raise a bare KeyError.
    message = data.get("message") if isinstance(data, dict) else None
    if not isinstance(message, dict) or "content" not in message:
        err = data.get("error") if isinstance(data, dict) else None
        # Sanitize before printing: an Ollama error blob is attacker-shaped
        # data and would otherwise inject ANSI escapes straight into the
        # user's terminal when sys.exit prints the message.
        snippet = _sanitize(err or str(data)[:300]) or "(empty)"
        sys.exit(f"Error: unexpected Ollama response: {snippet}")
    return message["content"]


def _query_ollama_stream(req: urllib.request.Request, timeout: int, url: str) -> str:
    """Stream Ollama's chat response, echoing each token chunk to stderr.

    Used in --debug mode so the user can watch the model's output in
    real time and spot truncation, refusals, or stalls. Returns the
    full accumulated content string after the stream is done so the
    rest of the pipeline (parse_response, etc.) can treat it the same
    as a non-streamed response.

    Shows a "waiting for first token" spinner during prompt processing
    so the user sees something is happening (large diffs on local 7B
    models can sit silent for many seconds while Ollama tokenises and
    runs prompt eval before any output token is emitted).
    """
    full_content = ""
    final_meta: dict = {}
    waiting = ui.Spinner("Waiting for response (ollama)")
    waiting.__enter__()
    first_token_seen = False
    any_chunk_seen = False
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line.decode())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                # First sign of life from Ollama: prompt eval is running.
                # Update the label so the user sees activity rather than
                # a static "waiting" message while the server processes.
                if not any_chunk_seen:
                    any_chunk_seen = True
                    waiting.label = "Model responding (ollama)"
                content = chunk.get("message", {}).get("content", "")
                if content:
                    if not first_token_seen:
                        first_token_seen = True
                        waiting.__exit__(None, None, None)
                        print(ui.dim("--- begin model output ---"), file=sys.stderr)
                    full_content += content
                    sys.stderr.write(ui.dim(content))
                    sys.stderr.flush()
                if chunk.get("done"):
                    final_meta = chunk
                    break
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        if not first_token_seen:
            waiting.__exit__(None, None, None)
        msg = str(e)
        if "timed out" in msg.lower():
            sys.exit(
                f"\nOllama request timed out after {timeout}s. For large "
                f"diffs, raise ollama.timeout in pwnguard.yaml or switch "
                f"to --backend claude-code."
            )
        sys.exit(f"\nError: cannot reach Ollama at {url}: {e}")
    finally:
        # Stream ended without ever producing a token (server closed
        # cleanly, empty response, etc.): make sure the spinner thread
        # is stopped so the program can exit.
        if not first_token_seen:
            waiting.__exit__(None, None, None)

    sys.stderr.write("\n")
    print(ui.dim("--- end model output ---"), file=sys.stderr)
    # Surface Ollama's per-request metrics when present (handy diagnostic
    # for why a run was slow or stopped early).
    if final_meta:
        eval_count = final_meta.get("eval_count")
        eval_duration = final_meta.get("eval_duration")
        prompt_eval = final_meta.get("prompt_eval_count")
        done_reason = final_meta.get("done_reason")
        bits = []
        if prompt_eval:
            bits.append(f"prompt: {prompt_eval} tokens")
        if eval_count:
            bits.append(f"output: {eval_count} tokens")
        if eval_count and eval_duration:
            t_per_s = eval_count / (eval_duration / 1e9)
            bits.append(f"{t_per_s:.1f} t/s")
        if done_reason:
            bits.append(f"stop: {done_reason}")
        if bits:
            print(ui.dim("PwnGuard: " + "  ·  ".join(bits)), file=sys.stderr)
    return full_content

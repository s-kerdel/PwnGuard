"""Cross-cutting named constants for the PwnGuard package.

Anything that is read by more than one module and never mutated at
runtime lives here. Per-feature constants (rendering, monitor state
file name, etc.) stay close to their consumer when they are used in
only one place.
"""

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Hosts that are allowed to receive a diff without an explicit opt-in.
# Prevents an attacker-controlled pwnguard.yaml from redirecting diffs to a
# remote endpoint (SSRF / data exfiltration).
SAFE_OLLAMA_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Loopback hosts where plaintext HTTP is acceptable for the openai-compat
# backend. Traffic never leaves the host, so the Bearer token can't be
# intercepted on the wire. Any non-loopback HTTP target requires the user
# to set openai.allow_insecure: true (acknowledging the plaintext risk).
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Backends that actually stream tokens to stderr in --debug mode. The
# spinner is suppressed for these because the live stream replaces it;
# for any other backend the spinner stays on in debug mode too so the
# user isn't staring at a frozen terminal while a long Claude run finishes.
STREAMING_BACKENDS = {"ollama", "openai-compat"}

# Wrapper tags around untrusted diff content in the prompt. The system prompt
# instructs the model to treat anything inside as data, not instructions, so
# prompt-injection attempts written inside a diff are isolated.
DIFF_WRAPPER_OPEN = "<diff_to_review>"
DIFF_WRAPPER_CLOSE = "</diff_to_review>"

# Subprocess timeouts for git operations.
GIT_TIMEOUT = 30
FETCH_TIMEOUT = 60

# Conservative timeout for remote diff fetching. API responses can be slow
# for big MRs, but a hung request shouldn't stall the audit indefinitely.
REMOTE_FETCH_TIMEOUT = 30

# Rough token estimate threshold above which we warn before sending to a
# paid API. ~4 characters per token is the typical heuristic for code+English.
LARGE_PROMPT_TOKEN_THRESHOLD = 50_000

# Monitor mode state-file constants.
MONITOR_STATE_FILENAME = ".pwnguard-monitor.json"
MONITOR_STATE_VERSION = 1


DEFAULT_CONFIG = {
    "severity_threshold": "HIGH",
    "claude_api": {
        # Default to the latest Opus at the time of writing. Override in
        # pwnguard.yaml when a newer/cheaper model becomes appropriate.
        "model": "claude-opus-4-7",
        "max_tokens": 4096,
    },
    "claude_code": {
        "timeout": 120,
    },
    "ollama": {
        "model": "qwen2.5-coder:7b",
        "url": "http://localhost:11434",
        "allow_remote": False,
        # Wall-clock cap for the HTTP request. Defaults to 10 minutes
        # because large diffs on local 7B models can take several
        # minutes just for prompt processing. Override per project as
        # appropriate. The Claude backends have their own (shorter)
        # timeout in claude_code.timeout.
        "timeout": 600,
        # Optional model tunables forwarded to Ollama's `options` field.
        # Omit any of these to use the model's own default. Common picks:
        #   keep_alive: "30m"  - keep the model resident in VRAM
        #   num_ctx: 32768     - context window; bigger = fits more diff
        #   num_predict: 2048  - cap output length
        #   temperature: 0.2   - lower = more consistent
    },
    "openai": {
        # Any OpenAI-compatible Chat Completions endpoint: LiteLLM proxy,
        # vLLM, OpenRouter, Groq, Together, Fireworks, llama.cpp server,
        # LM Studio, Ollama's /v1 mode, etc. `/v1/chat/completions` is
        # appended to `url`, so set the base (no trailing path).
        "url": "https://api.openai.com",
        "model": "gpt-4o-mini",
        "timeout": 600,
        # API key is read from the OPENAI_API_KEY env var (never the yaml,
        # so the repo stays committable). Override the env var name here
        # if your project uses a different one (e.g. for multiple proxies).
        "api_key_env": "OPENAI_API_KEY",
        # Optional tunables (omit any to use the server's default):
        #   num_predict: 4096  - max output tokens
        #   temperature: 0.2   - lower = more consistent
        #   seed: 42           - pin RNG for reproducible runs
    },
    "ignore_patterns": [
        "*.min.js",
        "*.min.css",
        "*.lock",
        "*.map",
        "vendor/*",
        "node_modules/*",
        "*.test.php",
        "*.spec.js",
    ],
    "max_diff_lines": 500,
    "max_file_size_kb": 100,
    "language_focus": ["php", "js", "ts", "twig"],
}

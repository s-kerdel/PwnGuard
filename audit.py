#!/usr/bin/env python3
"""
PwnGuard - AI-powered code security review for git commits.

Usage:
    Pre-commit hook:  python audit.py --mode hook
    CI pipeline:      python audit.py --mode ci
    Manual scan:      python audit.py --mode manual --files src/MyFile.php
    Full diff (MR):   python audit.py --mode ci --mr-diff

Backends:
    --backend claude-code  (local, uses Claude Code CLI from Pro subscription)
    --backend ollama       (local, requires running Ollama instance)
    --backend claude-api   (requires ANTHROPIC_API_KEY, for orgs with API access)

Configuration:
    See pwnguard.yaml for severity thresholds, model settings, and ignore patterns.
"""

import argparse
import json
import os
import subprocess
import sys
import yaml
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH": "\033[93m",      # yellow
    "MEDIUM": "\033[33m",    # orange
    "LOW": "\033[36m",       # cyan
    "INFO": "\033[90m",      # gray
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "GREEN": "\033[92m",
}

DEFAULT_CONFIG = {
    "severity_threshold": "HIGH",
    "claude_api": {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 4096,
    },
    "claude_code": {
        "timeout": 120,
    },
    "ollama": {
        "model": "qwen2.5-coder:7b",
        "url": "http://localhost:11434",
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

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str
    title: str
    file: str
    line: Optional[int]
    description: str
    recommendation: str
    cwe: Optional[str] = None
    confidence: str = "high"

    def to_terminal(self) -> str:
        color = COLORS.get(self.severity, "")
        reset = COLORS["RESET"]
        bold = COLORS["BOLD"]
        loc = f":{self.line}" if self.line else ""
        conf = f" (confidence: {self.confidence})" if self.confidence != "high" else ""
        return (
            f"{color}{bold}[{self.severity}]{reset}{conf} {self.title}\n"
            f"  {bold}File:{reset} {self.file}{loc}\n"
            f"  {bold}Issue:{reset} {self.description}\n"
            f"  {bold}Fix:{reset} {self.recommendation}"
            + (f"\n  {bold}CWE:{reset} {self.cwe}" if self.cwe else "")
        )

    def to_gitlab_markdown(self) -> str:
        emoji = {
            "CRITICAL": ":red_circle:",
            "HIGH": ":orange_circle:",
            "MEDIUM": ":yellow_circle:",
            "LOW": ":blue_circle:",
            "INFO": ":white_circle:",
        }
        loc = f":{self.line}" if self.line else ""
        conf = f" _(confidence: {self.confidence})_" if self.confidence != "high" else ""
        return (
            f"### {emoji.get(self.severity, '')} {self.severity}: {self.title}{conf}\n\n"
            f"**File:** `{self.file}{loc}`\n\n"
            f"**Issue:** {self.description}\n\n"
            f"**Fix:** {self.recommendation}\n"
            + (f"\n**CWE:** {self.cwe}\n" if self.cwe else "")
        )


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    error: Optional[str] = None

    @property
    def blocking_findings(self) -> list[Finding]:
        """Only high and medium confidence findings can block commits."""
        return [f for f in self.findings if f.confidence in ("high", "medium")]

    @property
    def max_severity(self) -> int:
        blocking = self.blocking_findings
        if not blocking:
            return 0
        return max(SEVERITY_ORDER.get(f.severity, 0) for f in blocking)

    def exceeds_threshold(self, threshold: str) -> bool:
        return self.max_severity >= SEVERITY_ORDER.get(threshold, 3)

    @property
    def summary(self) -> dict:
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(config_path: Optional[str] = None) -> dict:
    """Load config from yaml file, falling back to defaults."""
    config = DEFAULT_CONFIG.copy()

    paths_to_try = [
        config_path,
        "pwnguard.yaml",
        ".pwnguard.yaml",
        os.path.expanduser("~/.config/pwnguard/config.yaml"),
    ]

    for path in paths_to_try:
        if path and os.path.exists(path):
            with open(path) as f:
                user_config = yaml.safe_load(f) or {}
            deep_merge(config, user_config)
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
# Git operations
# ---------------------------------------------------------------------------

def get_staged_diff() -> str:
    """Get the diff of staged files (for pre-commit hook)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--diff-filter=ACMR", "-U3"],
        capture_output=True, text=True
    )
    return result.stdout


def get_mr_diff() -> str:
    """Get the diff against the MR target branch (for CI)."""
    # Detect target branch from GitLab CI environment
    target = os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")

    # Fetch target branch if not available
    subprocess.run(
        ["git", "fetch", "origin", target],
        capture_output=True, text=True
    )

    result = subprocess.run(
        ["git", "diff", f"origin/{target}...HEAD", "--diff-filter=ACMR", "-U3"],
        capture_output=True, text=True
    )
    return result.stdout


def get_file_contents(files: list[str]) -> str:
    """Read specific files and format as a diff-like output."""
    output = []
    for filepath in files:
        if os.path.exists(filepath):
            with open(filepath) as f:
                content = f.read()
            output.append(f"--- /dev/null\n+++ b/{filepath}\n{content}")
    return "\n".join(output)


def parse_diff_files(diff: str) -> list[str]:
    """Extract file paths from a unified diff."""
    files = []
    for line in diff.split("\n"):
        if line.startswith("+++ b/"):
            files.append(line[6:])
    return files


def filter_diff(diff: str, config: dict) -> str:
    """Filter diff based on ignore patterns and language focus."""
    import fnmatch

    ignore = config.get("ignore_patterns", [])
    focus = config.get("language_focus", [])
    max_lines = config.get("max_diff_lines", 500)

    filtered_chunks = []
    current_chunk = []
    current_file = None
    include = True

    for line in diff.split("\n"):
        if line.startswith("diff --git"):
            # Save previous chunk
            if current_chunk and include:
                filtered_chunks.extend(current_chunk)

            current_chunk = [line]
            # Extract filename
            parts = line.split(" b/")
            current_file = parts[-1] if len(parts) > 1 else ""

            # Check ignore patterns
            include = not any(fnmatch.fnmatch(current_file, p) for p in ignore)

            # Check language focus (if configured)
            if include and focus:
                ext = Path(current_file).suffix.lstrip(".")
                include = ext in focus or not ext

        else:
            current_chunk.append(line)

    # Don't forget last chunk
    if current_chunk and include:
        filtered_chunks.extend(current_chunk)

    result = "\n".join(filtered_chunks)

    # Truncate if too large
    lines = result.split("\n")
    if len(lines) > max_lines:
        result = "\n".join(lines[:max_lines])
        result += f"\n\n[TRUNCATED: {len(lines) - max_lines} lines omitted]"

    return result


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a security code auditor. You review git diffs for security vulnerabilities.

RULES:
1. Only report actual security issues, not style or quality concerns.
2. Focus on vulnerabilities that are exploitable or represent defence-in-depth failures.
3. Consider the context: a function that sanitizes input is not vulnerable just because it handles dangerous data.
4. Do not flag test files, migrations, or configuration that is clearly for development only.
5. Be specific about WHERE the issue is (file + line if possible) and HOW it could be exploited.
6. Do not report the same issue multiple times if it appears in similar code.

DO NOT FLAG (these are secure patterns, not vulnerabilities):
- Parameterized queries / prepared statements with bind parameters
- json_decode() / json_encode() used instead of unserialize()
- unserialize() WITH an allowed_classes whitelist
- URL validation that checks scheme, host allowlist, AND private IP ranges
- Input that is escaped or sanitized before use
- Authorization using an in_array() allowlist approach
- Text interpolation {{ }} instead of v-html
- file_get_contents() on hardcoded or validated URLs
- Code that HANDLES dangerous input safely is not the same as code that IS dangerous

Before reporting a finding, verify: is this actually exploitable, or has the developer already applied a fix? If the dangerous function is wrapped in proper validation, do not report it.

WRITING STYLE:
- Write for developers, not security specialists.
- Title: short, lowercase, describes the bug (e.g. "SQL injection via string interpolation").
- Description: 1-2 plain sentences. What is wrong and what can happen. No jargon.
- Recommendation: 1-2 sentences. The specific fix. Include a short code snippet if it helps.
- Keep it short. Do not over-explain. Do not use words like "adversary", "threat actor", "attack vector", "exploitation surface", or pentest terminology.
- Use simple cause and effect: "X allows Y" or "X can lead to Y".
- IMPORTANT: Do not include code snippets, backticks, or special characters in any JSON field values. Describe fixes in plain words only. Say "use parameterized queries" not "use $stmt->prepare('SELECT ...')". The JSON must be valid without escaping issues.

SEVERITY DEFINITIONS:
- CRITICAL: Remote code execution, authentication bypass, direct data breach.
- HIGH: SQL injection, SSRF, stored XSS, insecure deserialization, privilege escalation.
- MEDIUM: Missing input validation, CSRF, information disclosure, missing access controls, open redirect.
- LOW: Missing security headers, verbose error messages, minor hardening issues.
- INFO: Code quality issues with minor security implications.

FOCUS AREAS (PHP/Shopware):
- unserialize() without allowed_classes
- SQL string interpolation or concatenation (vs parameterized queries)
- Missing ACL/route protection annotations
- v-html in Vue/Twig templates (XSS sink)
- file_get_contents / curl with user-controlled URLs (SSRF)
- eval(), exec(), system(), passthru(), shell_exec()
- FILTER_VALIDATE_URL used as security validation (it is not)
- serialize()/unserialize() vs json_encode()/json_decode()
- OR-logic in authorization checks (common bypass pattern)
- Missing _loginRequired on storefront routes
- Direct file operations with user-controlled paths
- Hardcoded credentials or API keys

RESPOND WITH ONLY valid JSON in this exact format, no markdown fences, no preamble:
{
    "findings": [
        {
            "severity": "HIGH",
            "confidence": "high",
            "title": "Short descriptive title",
            "file": "path/to/file.php",
            "line": 42,
            "description": "What the vulnerability is and how it could be exploited",
            "recommendation": "Specific fix with code example if applicable",
            "cwe": "CWE-XXX"
        }
    ]
}

Confidence levels:
- "high": clearly vulnerable, no protective code around it
- "medium": likely vulnerable, but some context is missing
- "low": might be a false positive, some mitigation may be in place

If no security issues are found, respond with:
{"findings": []}
"""

# ---------------------------------------------------------------------------
# AI backends
# ---------------------------------------------------------------------------

def query_claude_api(diff: str, config: dict) -> str:
    """Send diff to Claude API for analysis (requires ANTHROPIC_API_KEY)."""
    try:
        import anthropic
    except ImportError:
        print("Error: 'anthropic' package not installed. Run: pip install anthropic")
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable not set")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    claude_config = config.get("claude_api", {})

    message = client.messages.create(
        model=claude_config.get("model", "claude-sonnet-4-20250514"),
        max_tokens=claude_config.get("max_tokens", 4096),
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Review this git diff for security vulnerabilities:\n\n{diff}"
            }
        ],
    )

    return message.content[0].text


def query_claude_code(diff: str, config: dict) -> str:
    """Send diff to Claude Code CLI for analysis (uses Pro subscription)."""
    # Check if claude is available
    check = subprocess.run(
        ["claude", "--version"],
        capture_output=True, text=True
    )
    if check.returncode != 0:
        print("Error: 'claude' CLI not found.")
        print("Install Claude Code: https://docs.anthropic.com/en/docs/claude-code")
        sys.exit(1)

    cc_config = config.get("claude_code", {})
    timeout = cc_config.get("timeout", 120)

    # Combine system prompt and user prompt for -p mode
    full_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"Review this git diff for security vulnerabilities:\n\n{diff}"
    )

    # Write prompt to temp file to avoid shell escaping issues
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(full_prompt)
        prompt_file = f.name

    try:
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text"],
            input=full_prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            print(f"Error: Claude Code returned exit code {result.returncode}")
            if result.stderr:
                print(f"stderr: {result.stderr[:500]}")
            sys.exit(1)

        return result.stdout

    except subprocess.TimeoutExpired:
        print(f"Error: Claude Code timed out after {timeout}s")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: 'claude' command not found in PATH")
        print("Install Claude Code: https://docs.anthropic.com/en/docs/claude-code")
        sys.exit(1)
    finally:
        os.unlink(prompt_file)


def query_ollama(diff: str, config: dict) -> str:
    """Send diff to local Ollama instance for analysis."""
    import urllib.request
    import urllib.error

    ollama_config = config.get("ollama", {})
    url = ollama_config.get("url", "http://localhost:11434")
    model = ollama_config.get("model", "qwen2.5-coder:7b")

    payload = json.dumps({
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Review this git diff for security vulnerabilities:\n\n{diff}",
            },
        ],
    }).encode()

    req = urllib.request.Request(
        f"{url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode())
            return data["message"]["content"]
    except urllib.error.URLError as e:
        print(f"Error: cannot reach Ollama at {url}: {e}")
        print("Is Ollama running? Start it with: ollama serve")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def parse_response(response: str) -> AuditResult:
    """Parse AI response JSON into AuditResult."""
    result = AuditResult()

    # Strip markdown fences if present
    cleaned = response.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    # Extract JSON if surrounded by other text
    json_start = cleaned.find("{")
    json_end = cleaned.rfind("}") + 1
    if json_start >= 0 and json_end > json_start:
        cleaned = cleaned[json_start:json_end]

    # Try parsing as-is first
    data = None
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # If that failed, fix common escape issues from smaller models
    if data is None:
        try:
            # Fix unescaped backslashes (PHP code in recommendations)
            # Replace single backslashes that aren't valid JSON escapes
            import re
            fixed = re.sub(
                r'\\(?!["\\/bfnrtu])',
                r'\\\\',
                cleaned,
            )
            data = json.loads(fixed)
        except json.JSONDecodeError:
            pass

    # Last resort: try to fix unescaped control characters
    if data is None:
        try:
            fixed = cleaned
            # Remove control characters that break JSON
            fixed = re.sub(r'[\x00-\x1f\x7f]', ' ', fixed)
            # Fix unescaped backslashes again after cleanup
            fixed = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', fixed)
            data = json.loads(fixed)
        except (json.JSONDecodeError, Exception) as e:
            result.error = (
                f"Failed to parse AI response: {e}\n"
                f"Raw response:\n{response[:500]}"
            )
            return result

    for item in data.get("findings", []):
        finding = Finding(
            severity=item.get("severity", "INFO").upper(),
            title=item.get("title", "Untitled finding"),
            file=item.get("file", "unknown"),
            line=item.get("line"),
            description=item.get("description", ""),
            recommendation=item.get("recommendation", ""),
            cwe=item.get("cwe"),
            confidence=item.get("confidence", "high").lower(),
        )
        # Validate severity
        if finding.severity not in SEVERITY_ORDER:
            finding.severity = "INFO"
        # Validate confidence
        if finding.confidence not in ("high", "medium", "low"):
            finding.confidence = "high"
        result.findings.append(finding)

    return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_terminal(result: AuditResult, threshold: str) -> None:
    """Print findings to terminal with colors."""
    bold = COLORS["BOLD"]
    reset = COLORS["RESET"]
    green = COLORS["GREEN"]

    if result.error:
        print(f"\n{COLORS['CRITICAL']}Error: {result.error}{reset}\n")
        return

    print(f"\n{bold}{'=' * 60}{reset}")
    print(f"{bold}  PwnGuard Results{reset}")
    print(f"{bold}{'=' * 60}{reset}\n")

    if not result.findings:
        print(f"  {green}No security issues found.{reset}\n")
        return

    # Sort by severity (highest first)
    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )

    for f in sorted_findings:
        print(f.to_terminal())
        print()

    # Summary
    summary = result.summary
    print(f"{bold}Summary:{reset} ", end="")
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in summary:
            color = COLORS.get(sev, "")
            parts.append(f"{color}{summary[sev]} {sev}{reset}")
    print(" | ".join(parts))

    # Threshold check
    if result.exceeds_threshold(threshold):
        print(f"\n{COLORS['CRITICAL']}{bold}BLOCKED: "
              f"Findings meet or exceed {threshold} threshold.{reset}")
        print(f"Fix the issues above before committing.\n")
    else:
        print(f"\n{green}PASSED: No findings at or above "
              f"{threshold} threshold.{reset}\n")


def format_gitlab_comment(result: AuditResult) -> str:
    """Format findings as a GitLab MR comment in markdown."""
    if result.error:
        return f"## :warning: PwnGuard Error\n\n```\n{result.error}\n```"

    if not result.findings:
        return "## :white_check_mark: PwnGuard Passed\n\nNo security issues found."

    lines = ["## :shield: PwnGuard Findings\n"]

    summary = result.summary
    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in summary:
            summary_parts.append(f"**{summary[sev]}** {sev}")
    lines.append(" | ".join(summary_parts))
    lines.append("")

    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )

    for f in sorted_findings:
        lines.append(f.to_gitlab_markdown())

    return "\n".join(lines)


def post_gitlab_comment(comment: str) -> bool:
    """Post a comment to the GitLab MR via API."""
    import urllib.request
    import urllib.error

    project_id = os.environ.get("CI_PROJECT_ID")
    mr_iid = os.environ.get("CI_MERGE_REQUEST_IID")
    token = os.environ.get("GITLAB_TOKEN") or os.environ.get("CI_JOB_TOKEN")
    gitlab_url = os.environ.get("CI_SERVER_URL", "https://gitlab.com")

    if not all([project_id, mr_iid, token]):
        print("Warning: GitLab CI environment variables not set, skipping MR comment")
        return False

    url = f"{gitlab_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
    payload = json.dumps({"body": comment}).encode()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "PRIVATE-TOKEN": token,
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status == 201
    except urllib.error.URLError as e:
        print(f"Warning: Failed to post GitLab comment: {e}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="pwnguard",
        description="PwnGuard - AI-powered security audit for git commits",
    )
    parser.add_argument(
        "--mode",
        choices=["hook", "ci", "manual"],
        default="hook",
        help="Run mode: hook (pre-commit), ci (GitLab pipeline), manual (specific files)",
    )
    parser.add_argument(
        "--backend",
        choices=["claude-code", "ollama", "claude-api"],
        default=None,
        help="AI backend (default: claude-code for hook, ollama for ci)",
    )
    parser.add_argument(
        "--model",
        help="Override model (e.g. qwen2.5-coder:14b, claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--config",
        help="Path to config file",
    )
    parser.add_argument(
        "--files",
        nargs="+",
        help="Specific files to scan (manual mode only)",
    )
    parser.add_argument(
        "--mr-diff",
        action="store_true",
        help="Use MR diff instead of staged diff (CI mode)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of formatted text",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be sent to AI without sending",
    )
    parser.add_argument(
        "--threshold",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Override severity threshold from config",
    )

    args = parser.parse_args()

    # Load config
    config = load_config(args.config)

    # Determine backend
    if args.backend:
        backend = args.backend
    elif args.mode == "ci":
        # CI: default to ollama (self-hosted runner), claude-api if available
        if os.environ.get("ANTHROPIC_API_KEY"):
            backend = "claude-api"
        else:
            backend = "ollama"
    else:
        # Local: prefer claude-code (Pro subscription), fall back to ollama
        claude_check = subprocess.run(
            ["claude", "--version"], capture_output=True, text=True
        )
        if claude_check.returncode == 0:
            backend = "claude-code"
        else:
            backend = "ollama"

    # Determine threshold
    threshold = args.threshold or config.get("severity_threshold", "HIGH")

    # Override model if specified
    if args.model:
        config.setdefault("ollama", {})["model"] = args.model
        config.setdefault("claude_api", {})["model"] = args.model

    # Get the diff
    if args.mode == "manual" and args.files:
        diff = get_file_contents(args.files)
    elif args.mode == "ci" or args.mr_diff:
        diff = get_mr_diff()
    else:
        diff = get_staged_diff()

    if not diff.strip():
        print("No changes to audit.")
        sys.exit(0)

    # Filter diff
    diff = filter_diff(diff, config)

    if not diff.strip():
        print("No relevant changes to audit (all filtered).")
        sys.exit(0)

    # Dry run
    if args.dry_run:
        files = parse_diff_files(diff)
        print(f"Would scan {len(files)} file(s) using {backend}:")
        for f in files:
            print(f"  {f}")
        print(f"\nDiff size: {len(diff)} characters, {len(diff.splitlines())} lines")
        print(f"Threshold: {threshold}")
        sys.exit(0)

    # Query AI
    print(f"Scanning with {backend}...", file=sys.stderr)

    if backend == "claude-api":
        response = query_claude_api(diff, config)
    elif backend == "claude-code":
        response = query_claude_code(diff, config)
    else:
        response = query_ollama(diff, config)

    # Parse response
    result = parse_response(response)
    result.files_scanned = len(parse_diff_files(diff))

    # Output
    if args.json:
        output = {
            "findings": [asdict(f) for f in result.findings],
            "summary": result.summary,
            "files_scanned": result.files_scanned,
            "threshold": threshold,
            "blocked": result.exceeds_threshold(threshold),
        }
        if result.error:
            output["error"] = result.error
        print(json.dumps(output, indent=2))
    elif args.mode == "ci":
        # Terminal output for CI logs
        print_terminal(result, threshold)
        # Post to GitLab MR
        comment = format_gitlab_comment(result)
        post_gitlab_comment(comment)
    else:
        print_terminal(result, threshold)

    # Exit code
    if result.error:
        sys.exit(2)
    if result.exceeds_threshold(threshold):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

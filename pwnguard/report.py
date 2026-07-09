"""Markdown / GitLab-comment / exported-findings output.

The terminal renderer in ``pwnguard.render`` produces ANSI-coloured
output for human eyes; this module produces persisted text (markdown,
report files, GitLab MR comments) that other tools and humans-via-PR
read.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime

from pwnguard import ui
from pwnguard.constants import SEVERITY_ORDER
from pwnguard.models import AuditResult, Finding


def _finding_markdown(f: Finding) -> str:
    """Markdown block for one finding (GitLab MR comment)."""
    loc = f":{f.line}" if f.line else ""
    conf = f" _(confidence: {f.confidence})_" if f.confidence != "high" else ""
    cwe_url = f.cwe_url()
    if not f.cwe:
        cwe_md = ""
    elif cwe_url:
        cwe_md = f"\n**CWE:** [{f.cwe}]({cwe_url})\n"
    else:
        cwe_md = f"\n**CWE:** {f.cwe}\n"
    return (
        f"### {f.severity}: {f.title}{conf}\n\n"
        f"**File:** `{f.file}{loc}`\n\n"
        f"**Issue:** {f.description}\n\n"
        f"**Fix:** {f.recommendation}\n"
        + cwe_md
    )


def _ordered_for_export(findings: list) -> list:
    """Stable sort: severity (desc) -> file -> line. Matches the on-screen
    order so a Markdown export reads the same way as the terminal output."""
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_ORDER.get(f.severity, 0),
            f.file or "",
            f.line or 0,
        ),
    )


def format_gitlab_comment(result: AuditResult, *, collapsed: bool = False) -> str:
    """Format findings as a GitLab MR comment in markdown.

    With ``collapsed`` the per-finding detail is wrapped in a ``<details>``
    block, so the posted comment shows only the heading and the severity
    tally until the reader expands "Show Findings". The error / passed
    messages are short and never collapsed.
    """
    if result.error:
        return f"## PwnGuard Error\n\n```\n{result.error}\n```"

    if not result.findings:
        return "## PwnGuard Passed\n\nNo security issues found."

    summary_line = _severity_summary_line(result.findings)
    findings_md = "\n".join(
        _finding_markdown(f) for f in _ordered_for_export(result.findings)
    )

    if collapsed:
        return (
            "## PwnGuard Findings\n\n"
            f"{summary_line}\n"
            "<details>\n<summary>Show Findings</summary>\n\n"
            f"{findings_md}\n"
            "</details>"
        )

    return f"## PwnGuard Findings\n\n{summary_line}\n\n{findings_md}"


def post_gitlab_comment(comment: str, *, as_thread: bool = False) -> bool:
    """Post a comment to the GitLab MR via API.

    ``as_thread`` posts a resolvable discussion (``/discussions``) instead
    of a plain note (``/notes``); the thread must then be resolved before
    the MR can merge when the project requires all threads resolved. Both
    endpoints take ``{"body": ...}`` and return 201 on success.
    """
    project_id = os.environ.get("CI_PROJECT_ID")
    mr_iid = os.environ.get("CI_MERGE_REQUEST_IID")
    token = os.environ.get("GITLAB_TOKEN") or os.environ.get("CI_JOB_TOKEN")
    gitlab_url = os.environ.get("CI_SERVER_URL", "https://gitlab.com")

    if not all([project_id, mr_iid, token]):
        print("Warning: GitLab CI environment variables not set, skipping MR comment")
        return False

    endpoint = "discussions" if as_thread else "notes"
    url = (
        f"{gitlab_url}/api/v4/projects/{project_id}"
        f"/merge_requests/{mr_iid}/{endpoint}"
    )
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
        # Bounded timeout so a hung GitLab API can't stall the whole CI job.
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 201
    except urllib.error.URLError as e:
        print(f"Warning: Failed to post GitLab comment: {e}")
        return False


def write_report(result: AuditResult, path: str) -> None:
    """Persist findings as a markdown report at ``path``."""
    body = format_gitlab_comment(result)
    with open(path, "w") as f:
        f.write(body + "\n")
    print(ui.dim(f"PwnGuard: report written to {path}"), file=sys.stderr)


def _default_findings_export_path(prefix: str = "pwnguard-findings") -> str:
    """Timestamped filename in the current directory for TUI exports."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{ts}.md"


def _severity_summary_line(findings: list) -> str:
    """``N CRITICAL | N HIGH | ...`` skipping severities with zero count."""
    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            parts.append(f"**{counts[sev]}** {sev}")
    return " | ".join(parts)


def export_findings_markdown(findings: list, path: str) -> None:
    """Write a flat markdown findings report (used by --review export).

    Sorted by severity then file/line, matching the on-screen order.
    """
    ordered = _ordered_for_export(findings)
    lines = [
        "# PwnGuard Findings",
        "",
        f"_Exported {datetime.now().isoformat(timespec='seconds')}_",
        "",
    ]
    summary = _severity_summary_line(ordered)
    if summary:
        lines.append(summary)
        lines.append("")
    if not ordered:
        lines.append("_No findings to export._")
    else:
        for f in ordered:
            lines.append(_finding_markdown(f))
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def export_monitor_findings_markdown(
    grouped: list, path: str,
) -> None:
    """Write a per-repo grouped findings report for monitor mode.

    ``grouped`` is ``[(repo_label, [Finding, ...]), ...]`` in display
    order. Repos with no findings are skipped entirely.
    """
    total = sum(len(fs) for _, fs in grouped)
    n_repos = sum(1 for _, fs in grouped if fs)
    lines = [
        "# PwnGuard Monitor Findings",
        "",
        f"_Exported {datetime.now().isoformat(timespec='seconds')}_",
        "",
        f"{total} finding{'s' if total != 1 else ''} across "
        f"{n_repos} repo{'s' if n_repos != 1 else ''}.",
        "",
    ]
    if total == 0:
        lines.append("_No findings to export._")
    else:
        for name, fs in grouped:
            if not fs:
                continue
            lines.append(f"## {name}")
            lines.append("")
            summary = _severity_summary_line(fs)
            if summary:
                lines.append(summary)
                lines.append("")
            for f in _ordered_for_export(fs):
                lines.append(_finding_markdown(f))
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")

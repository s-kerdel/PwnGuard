"""Remote diff fetching for GitLab MRs / GitHub PRs / individual commits.

Auto-detects the platform from the URL shape and dispatches to a
platform-specific helper that returns a unified diff. The diff
reassembly path (GitLab's JSON commit-diff API does NOT return raw
unified format) reconstructs the standard ``diff --git`` headers so
the rest of the pipeline (anchor tagger, filter, renderer) sees the
same shape it sees for a local ``git diff``.
"""

import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from pwnguard.constants import REMOTE_FETCH_TIMEOUT


def _platform_token(*env_names) -> Optional[str]:
    """Return the first non-empty env var from ``env_names``, or None.

    Used by every GitLab / GitHub call site to look up a token under
    its primary name (``GITLAB_TOKEN``) with a PwnGuard-specific
    fallback (``PWNGUARD_GITLAB_TOKEN``). Centralised so adding a new
    fallback name is a one-line change.
    """
    for name in env_names:
        v = os.environ.get(name)
        if v:
            return v
    return None


def _http_get(url: str, headers: dict) -> bytes:
    """Plain GET with explicit timeout. Centralised so error handling
    stays consistent across the GitLab / GitHub helpers, and so a
    network failure never bubbles up as a Python traceback."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=REMOTE_FETCH_TIMEOUT) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        sys.exit(f"HTTP {e.code} from {url}\n{body}")
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        msg = str(e)
        if "timed out" in msg.lower():
            sys.exit(
                f"Request to {url} timed out after {REMOTE_FETCH_TIMEOUT}s. "
                f"Try again or use a smaller MR / commit."
            )
        sys.exit(f"Network error fetching {url}: {e}")


def _fetch_gitlab_mr(parsed: urllib.parse.ParseResult) -> str:
    """GitLab MR -> unified diff via /raw_diffs endpoint.

    Works for gitlab.com and self-hosted GitLab (any host with the
    standard /-/merge_requests/ URL shape). Requires GITLAB_TOKEN.
    """
    head, sep, tail = parsed.path.partition("/-/merge_requests/")
    if not sep:
        sys.exit(f"Malformed GitLab MR URL: {parsed.geturl()}")
    project_path = head.strip("/")
    iid = tail.rstrip("/").split("/")[0]
    if not iid.isdigit():
        sys.exit(f"Invalid MR IID in {parsed.geturl()!r}")

    token = _platform_token("GITLAB_TOKEN", "PWNGUARD_GITLAB_TOKEN")
    if not token:
        sys.exit("GitLab fetch requires GITLAB_TOKEN env var (api or read_api scope).")

    encoded = urllib.parse.quote(project_path, safe="")
    api_url = f"{parsed.scheme}://{parsed.netloc}/api/v4/projects/{encoded}/merge_requests/{iid}/raw_diffs"
    body = _http_get(api_url, {"PRIVATE-TOKEN": token})
    return body.decode("utf-8", errors="replace")


def _gitlab_commit_diff(parsed: urllib.parse.ParseResult, project_path: str, sha: str) -> str:
    """Common logic: fetch a unified diff for one GitLab commit.

    Shared by both standalone commit URLs (``/-/commit/SHA``) and
    MR-with-commit-id URLs (``/-/merge_requests/N/diffs?commit_id=SHA``).
    GitLab returns per-file changes as a JSON array; we reassemble
    them with ``diff --git`` headers so the rest of the pipeline sees
    the same format as a local ``git diff``.
    """
    if not re.match(r"^[a-f0-9]{4,}$", sha):
        sys.exit(f"Invalid commit SHA: {sha!r}")

    token = _platform_token("GITLAB_TOKEN", "PWNGUARD_GITLAB_TOKEN")
    if not token:
        sys.exit("GitLab fetch requires GITLAB_TOKEN env var (api or read_api scope).")

    encoded = urllib.parse.quote(project_path, safe="")
    api_url = f"{parsed.scheme}://{parsed.netloc}/api/v4/projects/{encoded}/repository/commits/{sha}/diff"
    body = _http_get(api_url, {"PRIVATE-TOKEN": token})
    try:
        data = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        sys.exit(f"GitLab returned non-JSON for commit diff: {e}")

    chunks = []
    for change in data:
        old_path = change.get("old_path", "") or "/dev/null"
        new_path = change.get("new_path", "") or "/dev/null"
        diff_body = change.get("diff", "")
        if not diff_body:
            continue
        # GitLab's commit-diff API strips the ``--- a/X`` and
        # ``+++ b/X`` header lines; the body starts at ``@@``. Without
        # ``+++ b/`` the anchor tagger has no file context, so
        # reconstruct the missing headers here.
        if diff_body.lstrip("\n").startswith("@@"):
            if change.get("new_file"):
                header_lines = f"--- /dev/null\n+++ b/{new_path}\n"
            elif change.get("deleted_file"):
                header_lines = f"--- a/{old_path}\n+++ /dev/null\n"
            else:
                header_lines = f"--- a/{old_path}\n+++ b/{new_path}\n"
        else:
            # Older / self-hosted GitLab versions occasionally include
            # the headers already - pass through unchanged.
            header_lines = ""
        chunks.append(
            f"diff --git a/{old_path} b/{new_path}\n"
            f"{header_lines}{diff_body}"
        )
    return "\n".join(chunks)


def _fetch_gitlab_commit(parsed: urllib.parse.ParseResult) -> str:
    """Standalone GitLab commit URL: /group/project/-/commit/SHA."""
    head, sep, tail = parsed.path.partition("/-/commit/")
    if not sep:
        sys.exit(f"Malformed GitLab commit URL: {parsed.geturl()}")
    project_path = head.strip("/")
    sha = tail.rstrip("/").split("/")[0]
    if not sha:
        sys.exit(f"Missing commit SHA in {parsed.geturl()!r}")
    return _gitlab_commit_diff(parsed, project_path, sha)


def _fetch_gitlab_mr_commit(parsed: urllib.parse.ParseResult, sha: str) -> str:
    """GitLab MR URL with ?commit_id=SHA - scan just that one commit
    inside the MR, not the whole MR. Useful for reviewing big MRs in
    smaller chunks."""
    head, _, _ = parsed.path.partition("/-/merge_requests/")
    project_path = head.strip("/")
    return _gitlab_commit_diff(parsed, project_path, sha)


def _github_api_base(parsed: urllib.parse.ParseResult) -> str:
    """Pick the right API host for github.com vs GitHub Enterprise."""
    if parsed.netloc.endswith("github.com"):
        return "https://api.github.com"
    return f"{parsed.scheme}://{parsed.netloc}/api/v3"


def _github_headers(accept: str) -> dict:
    """Build standard GitHub request headers. Bearer token is optional
    (anon works for public repos but is heavily rate-limited)."""
    headers = {"Accept": accept}
    token = _platform_token("GITHUB_TOKEN", "PWNGUARD_GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_github_pr(parsed: urllib.parse.ParseResult) -> str:
    """GitHub PR -> unified diff via the v3.diff Accept header.

    Public PRs work without a token, but anonymous requests are rate-
    limited heavily. Setting GITHUB_TOKEN avoids that and is required
    for private repos.
    """
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 4 or parts[2] != "pull":
        sys.exit(f"Malformed GitHub PR URL: {parsed.geturl()}")
    owner, repo, _, number = parts[:4]
    if not number.isdigit():
        sys.exit(f"Invalid PR number in {parsed.geturl()!r}")

    api_url = f"{_github_api_base(parsed)}/repos/{owner}/{repo}/pulls/{number}"
    return _http_get(api_url, _github_headers("application/vnd.github.v3.diff")).decode("utf-8", errors="replace")


def _fetch_github_commit(parsed: urllib.parse.ParseResult) -> str:
    """GitHub commit -> unified diff via the v3.diff Accept header."""
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 4 or parts[2] != "commit":
        sys.exit(f"Malformed GitHub commit URL: {parsed.geturl()}")
    owner, repo, _, sha = parts[:4]
    api_url = f"{_github_api_base(parsed)}/repos/{owner}/{repo}/commits/{sha}"
    return _http_get(api_url, _github_headers("application/vnd.github.v3.diff")).decode("utf-8", errors="replace")


def _format_relative_time(iso_date: Optional[str]) -> str:
    """Render an ISO 8601 timestamp as a short ``Nd``-style relative
    string for the monitor dashboard.

    Granularities: ``Ns`` < 1min, ``Nm`` < 1h, ``Nh`` < 1d, ``Nd`` < 1w,
    ``Nw`` < 1mo, ``Nmo`` < 1y, then ``YYYY-MM-DD``. Returns an empty
    string on parse failure so missing or malformed dates render as
    no chip at all.
    """
    if not iso_date:
        return ""
    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "0s"  # clock skew - treat as "just now"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    days = seconds // 86400
    if days < 7:
        return f"{days}d"
    if days < 30:
        return f"{days // 7}w"
    if days < 365:
        return f"{days // 30}mo"
    return dt.strftime("%Y-%m-%d")


def _list_gitlab_commits(
    parsed: urllib.parse.ParseResult,
    branch: str,
    limit: int = 1,
) -> list:
    """Return up to ``limit`` most-recent commits on ``branch`` as
    ``(sha, committed_date_iso_or_None)`` tuples, newest first.

    URL shape is ``https://<host>/<group>/<project>`` - the repo root,
    no /-/<thing> suffix. The function tolerates a trailing slash and
    will also accept a URL that still carries ``/-/...`` from a copy-
    paste by taking the part before ``/-/``.
    """
    head = parsed.path.split("/-/")[0]
    project_path = head.strip("/")
    if not project_path or "/" not in project_path:
        sys.exit(f"Invalid GitLab project URL: {parsed.geturl()!r}")

    token = _platform_token("GITLAB_TOKEN", "PWNGUARD_GITLAB_TOKEN")
    if not token:
        sys.exit("GitLab list-commits requires GITLAB_TOKEN env var (api or read_api).")

    encoded = urllib.parse.quote(project_path, safe="")
    api_url = (
        f"{parsed.scheme}://{parsed.netloc}/api/v4/projects/{encoded}/"
        f"repository/commits"
        f"?ref_name={urllib.parse.quote(branch)}&per_page={int(limit)}"
    )
    body = _http_get(api_url, {"PRIVATE-TOKEN": token})
    try:
        data = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        sys.exit(f"GitLab returned non-JSON for commit list: {e}")
    if not isinstance(data, list):
        sys.exit(f"GitLab commit list: expected array, got {type(data).__name__}")
    out = []
    for item in data:
        if not isinstance(item, dict) or "id" not in item:
            continue
        out.append((item["id"], item.get("committed_date")))
    return out


def _list_github_commits(
    parsed: urllib.parse.ParseResult,
    branch: str,
    limit: int = 1,
) -> list:
    """Return up to ``limit`` most-recent commits on ``branch`` as
    ``(sha, committer_date_iso_or_None)`` tuples, newest first.

    URL shape is ``https://github.com/<owner>/<repo>`` (or the GitHub
    Enterprise equivalent under ``/api/v3``).
    """
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        sys.exit(f"Invalid GitHub URL: {parsed.geturl()!r}")
    owner, repo = parts[:2]

    api_url = (
        f"{_github_api_base(parsed)}/repos/{owner}/{repo}/commits"
        f"?sha={urllib.parse.quote(branch)}&per_page={int(limit)}"
    )

    body = _http_get(api_url, _github_headers("application/vnd.github+json"))
    try:
        data = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        sys.exit(f"GitHub returned non-JSON for commit list: {e}")
    if not isinstance(data, list):
        sys.exit(f"GitHub commit list: expected array, got {type(data).__name__}")
    out = []
    for item in data:
        if not isinstance(item, dict) or "sha" not in item:
            continue
        commit = item.get("commit") or {}
        committer = commit.get("committer") or {}
        out.append((item["sha"], committer.get("date")))
    return out


def _build_commit_url(repo_url: str, sha: str) -> str:
    """Compose a per-commit URL the existing ``fetch_from_url`` accepts,
    given a repo base URL and a commit SHA.

    Platform is inferred from the hostname (same heuristic as
    ``list_commits_from_url``).
    """
    parsed = urllib.parse.urlparse(repo_url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit(f"Invalid repo URL: {repo_url!r}")
    host = parsed.netloc.lower()
    base = repo_url.rstrip("/")
    if "gitlab" in host:
        return f"{base}/-/commit/{sha}"
    if "github" in host:
        return f"{base}/commit/{sha}"
    sys.exit(
        f"Cannot determine platform from URL: {repo_url!r}\n"
        f"Hostname must contain 'gitlab' or 'github'."
    )


def list_commits_from_url(url: str, branch: str, limit: int = 1) -> list:
    """Dispatch list-commits to the right platform based on URL host.

    Returns a list of ``(sha, committed_date_iso_or_None)`` tuples,
    newest first. Hostname heuristic: substring "gitlab" -> GitLab,
    "github" -> GitHub. Covers gitlab.com / github.com plus common
    self-hosted naming (gitlab.example.com, github.internal).
    Custom-domain self-hosted installs would need a ``platform:``
    config knob - deferred.
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit(f"Invalid URL: {url!r} (expected http(s)://...)")
    host = parsed.netloc.lower()
    if "gitlab" in host:
        return _list_gitlab_commits(parsed, branch, limit)
    if "github" in host:
        return _list_github_commits(parsed, branch, limit)
    sys.exit(
        f"Cannot determine platform from URL: {url!r}\n"
        f"Hostname must contain 'gitlab' or 'github'. Custom-domain "
        f"self-hosted instances are not yet supported in monitor mode."
    )


def fetch_from_url(url: str) -> str:
    """Fetch a unified diff from a GitLab MR / GitHub PR / commit URL.

    Auto-detects the platform from URL shape:
      - ``/-/merge_requests/<n>``                       -> GitLab MR (full)
      - ``/-/merge_requests/<n>/diffs?commit_id=<sha>`` -> GitLab MR, single commit
      - ``/-/commit/<sha>``                             -> GitLab commit (standalone)
      - ``/pull/<n>``                                   -> GitHub PR
      - ``/commit/<sha>`` (no /-/)                      -> GitHub commit

    Reads tokens from environment:
      - GITLAB_TOKEN (or PWNGUARD_GITLAB_TOKEN) - required for GitLab
      - GITHUB_TOKEN (or PWNGUARD_GITHUB_TOKEN) - optional for public,
        required for private repos and to lift rate limits
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit(f"Invalid URL: {url!r} (expected http(s)://...)")

    path = parsed.path
    if "/-/merge_requests/" in path:
        # A commit_id query param means "scan just this one commit of the
        # MR" - much smaller than the full MR diff, handy for chunked review.
        query_params = urllib.parse.parse_qs(parsed.query)
        commit_id = query_params.get("commit_id", [None])[0]
        if commit_id:
            return _fetch_gitlab_mr_commit(parsed, commit_id)
        return _fetch_gitlab_mr(parsed)
    if "/-/commit/" in path:
        return _fetch_gitlab_commit(parsed)
    if "/pull/" in path:
        return _fetch_github_pr(parsed)
    if "/commit/" in path:
        return _fetch_github_commit(parsed)

    sys.exit(
        f"Unrecognised URL shape: {url!r}\n"
        f"Supported: GitLab MR (/-/merge_requests/N), GitLab MR commit "
        f"(/-/merge_requests/N/diffs?commit_id=SHA), GitLab commit "
        f"(/-/commit/SHA), GitHub PR (/pull/N), GitHub commit (/commit/SHA)."
    )

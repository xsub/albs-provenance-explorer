"""On-demand git-commit inspection for the GUI inspector (D144).

A ``git_commit`` node carries the commit SHA, and its repository node carries the
ALBS git URL -- ``https://git.almalinux.org/rpms/<pkg>.git``, a public **Gitea**
instance. This queries Gitea's public REST API for the commit (message + changed
files) and the raw unified diff, so the workbench can answer "what changed in
this commit?" and, per file, show the diff.

Gitea endpoints used (both public, no auth):
  - ``GET {base}/api/v1/repos/{owner}/{repo}/git/commits/{sha}`` -> commit JSON
    (``commit.message``, ``files[].filename``/``status``).
  - ``GET {base}/{owner}/{repo}/commit/{sha}.diff`` -> the raw unified diff,
    which :func:`split_unified_diff` slices per file.

The fetcher is injectable and the parse/split functions are pure, so no test
ever hits the network. It shares the live-feed GET (macOS-safe SSL + descriptive
User-Agent) and the on-disk ``HttpCache`` with the CVE feed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Any, Callable

from albs_graph.adapters._http_cache import HttpCache, default_cache_root
from albs_graph.security.live_feeds import _default_http_get

Fetcher = Callable[[str], bytes]

__all__ = [
    "GitRemote",
    "GitFileChange",
    "GitCommit",
    "parse_git_remote",
    "commit_api_url",
    "commit_web_url",
    "commit_diff_url",
    "parse_gitea_commit",
    "fetch_git_commit",
    "fetch_commit_diff",
    "split_unified_diff",
    "file_diff_from",
]

# scp-like remote: git@host:owner/repo(.git)
_SCP_RE = re.compile(r"^[^@/]+@([^:/]+):(.+)$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
# a per-file section header in a unified diff: "diff --git a/<old> b/<new>"
_DIFF_HEADER_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")


@dataclass(frozen=True)
class GitRemote:
    """A Gitea repo coordinate parsed from an ALBS git URL."""

    base_url: str  # e.g. https://git.almalinux.org
    owner: str  # e.g. rpms
    repo: str  # e.g. nginx

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True)
class GitFileChange:
    path: str
    status: str = ""  # added / modified / deleted / renamed / "" (unknown)


@dataclass(frozen=True)
class GitCommit:
    sha: str
    message: str = ""
    author: str = ""
    date: str = ""
    html_url: str = ""
    files: tuple[GitFileChange, ...] = ()

    @property
    def short_sha(self) -> str:
        return self.sha[:12]

    @property
    def subject(self) -> str:
        return self.message.splitlines()[0] if self.message else ""

    @property
    def has_content(self) -> bool:
        return bool(self.message or self.files)


def parse_git_remote(url: str) -> GitRemote | None:
    """Parse an ALBS git URL into a :class:`GitRemote`, or ``None`` when it is not
    a usable ``host/owner/repo`` (e.g. the ``unknown-albs-source:<pkg>`` placeholder
    ALBS emits when it has no repository). Handles https / scp-like / scheme-less
    forms and a trailing ``.git``."""

    text = (url or "").strip()
    if not text:
        return None
    scp = _SCP_RE.match(text)
    if scp is not None:
        host, path = scp.group(1), scp.group(2)
    else:
        without_scheme = _SCHEME_RE.sub("", text)
        without_scheme = without_scheme.split("#", 1)[0].split("?", 1)[0]
        host, _, path = without_scheme.partition("/")
    host = host.strip("/")
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    segments = [seg for seg in path.split("/") if seg]
    if not host or len(segments) < 2:
        return None
    owner, repo = segments[-2], segments[-1]
    return GitRemote(base_url=f"https://{host}", owner=owner, repo=repo)


def commit_api_url(remote: GitRemote, sha: str) -> str:
    return f"{remote.base_url}/api/v1/repos/{remote.owner}/{remote.repo}/git/commits/{sha}"


def commit_web_url(remote: GitRemote, sha: str) -> str:
    return f"{remote.base_url}/{remote.owner}/{remote.repo}/commit/{sha}"


def commit_diff_url(remote: GitRemote, sha: str) -> str:
    return f"{commit_web_url(remote, sha)}.diff"


def parse_gitea_commit(payload: dict[str, Any], fallback_sha: str = "") -> GitCommit:
    """Build a :class:`GitCommit` from a Gitea ``GetSingleCommit`` JSON payload."""

    commit = payload.get("commit") or {}
    author = commit.get("author") or {}
    files = tuple(
        GitFileChange(path=str(entry.get("filename")), status=str(entry.get("status") or ""))
        for entry in (payload.get("files") or [])
        if isinstance(entry, dict) and entry.get("filename")
    )
    return GitCommit(
        sha=str(payload.get("sha") or fallback_sha),
        message=str(commit.get("message") or ""),
        author=str(author.get("name") or ""),
        date=str(author.get("date") or ""),
        html_url=str(payload.get("html_url") or ""),
        files=files,
    )


def fetch_git_commit(
    repo_url: str,
    sha: str,
    *,
    fetcher: Fetcher | None = None,
    cache: HttpCache | None = None,
) -> GitCommit:
    """Fetch one commit's message + changed-file list from Gitea. Always returns a
    record (empty content, but with the web URL filled in, when the repo URL is
    unusable or the server is unreachable) so the caller can still offer a link."""

    remote = parse_git_remote(repo_url)
    sha = (sha or "").strip()
    if remote is None or not sha:
        return GitCommit(sha=sha)
    get = _cached_getter(fetcher, cache)
    web_url = commit_web_url(remote, sha)
    try:
        payload = _json(get(commit_api_url(remote, sha)))
    except (OSError, ValueError):
        return GitCommit(sha=sha, html_url=web_url)
    commit = parse_gitea_commit(payload, sha)
    if not commit.html_url:
        commit = replace(commit, html_url=web_url)
    return commit


def fetch_commit_diff(
    repo_url: str,
    sha: str,
    *,
    fetcher: Fetcher | None = None,
    cache: HttpCache | None = None,
) -> str:
    """Fetch the raw unified diff for a whole commit (all files), or ``""`` when
    the repo URL is unusable or the server is unreachable."""

    remote = parse_git_remote(repo_url)
    sha = (sha or "").strip()
    if remote is None or not sha:
        return ""
    get = _cached_getter(fetcher, cache)
    try:
        return get(commit_diff_url(remote, sha)).decode("utf-8", "replace")
    except OSError:
        return ""


def split_unified_diff(diff_text: str) -> dict[str, str]:
    """Slice a multi-file unified diff into ``{new_path: section}`` keyed by each
    file's ``b/`` path (the new path), preserving every ``diff --git`` header."""

    sections: dict[str, str] = {}
    current_key: str | None = None
    current_lines: list[str] = []

    def flush() -> None:
        if current_key is not None:
            sections[current_key] = "\n".join(current_lines)

    for line in diff_text.splitlines():
        header = _DIFF_HEADER_RE.match(line)
        if header is not None:
            flush()
            current_key = header.group(2)
            current_lines = [line]
            continue
        if current_key is not None:
            current_lines.append(line)
    flush()
    return sections


def file_diff_from(diff_text: str, path: str) -> str:
    """The diff section for ``path`` out of a whole-commit diff, or ``""``. Tries
    an exact ``b/`` path match first, then a sub-path / basename match (so a
    rename whose new path differs still resolves)."""

    sections = split_unified_diff(diff_text)
    if path in sections:
        return sections[path]
    for key, body in sections.items():
        if key.endswith(f"/{path}") or path.endswith(f"/{key}"):
            return body
    base = path.rsplit("/", 1)[-1]
    for key, body in sections.items():
        if key.rsplit("/", 1)[-1] == base:
            return body
    return ""


def _cached_getter(fetcher: Fetcher | None, cache: HttpCache | None) -> Fetcher:
    if fetcher is not None:
        return fetcher
    store = cache or HttpCache(root=default_cache_root() / "git-commits")
    return lambda url: store.get_or_fetch(url, lambda: _default_http_get(url))


def _json(body: bytes) -> dict[str, Any]:
    data = json.loads(body.decode("utf-8"))
    return data if isinstance(data, dict) else {}

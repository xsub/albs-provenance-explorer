"""Offline tests for the git-commit inspection adapter (D144).

The Gitea fetcher is injected, so nothing here touches the network; the parse /
split helpers are pure.
"""

from __future__ import annotations

import json

import pytest

from albs_graph.adapters.git_source import (
    GitFileChange,
    commit_api_url,
    commit_diff_url,
    commit_web_url,
    fetch_commit_diff,
    fetch_git_commit,
    file_diff_from,
    parse_git_remote,
    parse_gitea_commit,
    split_unified_diff,
)

_COMMIT_PAYLOAD = {
    "sha": "911945c71710c83cf6f760447c32d8d6cae737dc",
    "html_url": "https://git.almalinux.org/rpms/nginx/commit/911945c",
    "commit": {
        "message": "Update to 1.20.1\n\nRebase the patches.",
        "author": {"name": "AlmaLinux Packager", "date": "2021-05-25T00:00:00Z"},
    },
    "files": [
        {"filename": "SPECS/nginx.spec", "status": "modified"},
        {"filename": "SOURCES/fix.patch", "status": "added"},
    ],
}

_DIFF = """diff --git a/SPECS/nginx.spec b/SPECS/nginx.spec
index 1111111..2222222 100644
--- a/SPECS/nginx.spec
+++ b/SPECS/nginx.spec
@@ -1,2 +1,2 @@
-Version: 1.20.0
+Version: 1.20.1
diff --git a/SOURCES/fix.patch b/SOURCES/fix.patch
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/SOURCES/fix.patch
@@ -0,0 +1,1 @@
+patched
"""


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://git.almalinux.org/rpms/nginx.git", ("https://git.almalinux.org", "rpms", "nginx")),
        ("git.almalinux.org/rpms/synthetic", ("https://git.almalinux.org", "rpms", "synthetic")),
        ("git@git.almalinux.org:rpms/zlib.git", ("https://git.almalinux.org", "rpms", "zlib")),
        ("https://git.almalinux.org/rpms/nginx.git/", ("https://git.almalinux.org", "rpms", "nginx")),
    ],
)
def test_parse_git_remote_handles_https_scp_and_schemeless(
    url: str, expected: tuple[str, str, str]
) -> None:
    remote = parse_git_remote(url)
    assert remote is not None
    assert (remote.base_url, remote.owner, remote.repo) == expected


@pytest.mark.parametrize("url", ["", "unknown-albs-source:nginx", "git.almalinux.org", "nope"])
def test_parse_git_remote_rejects_unusable_urls(url: str) -> None:
    assert parse_git_remote(url) is None


def test_commit_urls_target_the_gitea_api_and_diff_routes() -> None:
    remote = parse_git_remote("https://git.almalinux.org/rpms/nginx.git")
    assert remote is not None
    assert commit_api_url(remote, "deadbeef") == (
        "https://git.almalinux.org/api/v1/repos/rpms/nginx/git/commits/deadbeef"
    )
    assert commit_web_url(remote, "deadbeef") == "https://git.almalinux.org/rpms/nginx/commit/deadbeef"
    assert commit_diff_url(remote, "deadbeef") == (
        "https://git.almalinux.org/rpms/nginx/commit/deadbeef.diff"
    )


def test_parse_gitea_commit_reads_message_author_and_files() -> None:
    commit = parse_gitea_commit(_COMMIT_PAYLOAD)
    assert commit.subject == "Update to 1.20.1"
    assert commit.author == "AlmaLinux Packager"
    assert commit.short_sha == "911945c71710"
    assert [(f.path, f.status) for f in commit.files] == [
        ("SPECS/nginx.spec", "modified"),
        ("SOURCES/fix.patch", "added"),
    ]
    assert commit.has_content


def test_fetch_git_commit_uses_the_api_url_and_returns_files() -> None:
    seen: list[str] = []

    def fetcher(url: str) -> bytes:
        seen.append(url)
        return json.dumps(_COMMIT_PAYLOAD).encode()

    commit = fetch_git_commit(
        "https://git.almalinux.org/rpms/nginx.git",
        "911945c71710c83cf6f760447c32d8d6cae737dc",
        fetcher=fetcher,
    )
    assert seen == [
        "https://git.almalinux.org/api/v1/repos/rpms/nginx/git/commits/"
        "911945c71710c83cf6f760447c32d8d6cae737dc"
    ]
    assert commit.subject == "Update to 1.20.1"
    assert len(commit.files) == 2


def test_fetch_git_commit_degrades_when_remote_unusable() -> None:
    def fetcher(url: str) -> bytes:  # pragma: no cover - must not be called
        raise AssertionError("unusable remote should not be fetched")

    commit = fetch_git_commit("unknown-albs-source:nginx", "abc123", fetcher=fetcher)
    assert commit.sha == "abc123"
    assert not commit.has_content
    assert commit.html_url == ""


def test_fetch_git_commit_fills_web_url_on_fetch_error() -> None:
    def fetcher(url: str) -> bytes:
        raise OSError("offline")

    commit = fetch_git_commit("https://git.almalinux.org/rpms/nginx.git", "abc123", fetcher=fetcher)
    assert not commit.has_content
    assert commit.html_url == "https://git.almalinux.org/rpms/nginx/commit/abc123"


def test_split_unified_diff_keys_by_new_path() -> None:
    sections = split_unified_diff(_DIFF)
    assert list(sections) == ["SPECS/nginx.spec", "SOURCES/fix.patch"]
    assert "Version: 1.20.1" in sections["SPECS/nginx.spec"]
    assert sections["SOURCES/fix.patch"].startswith("diff --git a/SOURCES/fix.patch")


def test_file_diff_from_exact_then_basename_fallback() -> None:
    assert "Version: 1.20.1" in file_diff_from(_DIFF, "SPECS/nginx.spec")  # exact b/ path
    assert "Version: 1.20.1" in file_diff_from(_DIFF, "nginx.spec")  # basename fallback
    assert file_diff_from(_DIFF, "does/not/exist") == ""


def test_fetch_commit_diff_returns_text_or_empty_for_unusable_remote() -> None:
    diff = fetch_commit_diff(
        "https://git.almalinux.org/rpms/nginx.git", "abc123", fetcher=lambda url: _DIFF.encode()
    )
    assert diff == _DIFF
    assert fetch_commit_diff("unknown-albs-source:nginx", "abc123", fetcher=lambda url: b"x") == ""


def test_git_file_change_defaults_status_to_empty() -> None:
    assert GitFileChange(path="a/b.spec").status == ""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from albs_graph.adapters.albs import BuildNotFoundError, fetch_build_metadata


class FakeResponse:
    ok = True

    def __init__(
        self,
        data: dict[str, Any] | None = None,
        *,
        ok: bool = True,
        status_code: int = 200,
        content_type: str = "application/json",
        text: str = "",
    ) -> None:
        self._data = data
        self.ok = ok
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        self.text = text

    def json(self) -> dict[str, Any]:
        assert self._data is not None
        return self._data

    def raise_for_status(self) -> None:
        return None


class FakeRequests(ModuleType):
    def __init__(self, data: dict[str, Any]) -> None:
        super().__init__("requests")
        self.calls: list[str] = []
        self._data = data

    def get(self, url: str, timeout: int) -> FakeResponse:
        self.calls.append(url)
        return FakeResponse(self._data)


class FakeSequenceRequests(ModuleType):
    def __init__(self, responses: list[FakeResponse]) -> None:
        super().__init__("requests")
        self.calls: list[str] = []
        self._responses = responses

    def get(self, url: str, timeout: int) -> FakeResponse:
        self.calls.append(url)
        return self._responses.pop(0)


def test_fetch_build_metadata_reuses_fresh_local_cache(tmp_path: Path, monkeypatch: Any) -> None:
    payload = {
        "id": 17812,
        "package": "nginx",
        "tasks": [
            {
                "ref": {
                    "url": "https://git.almalinux.org/rpms/nginx.git",
                    "git_commit_hash": "abc123",
                },
                "alma_commit_cas_hash": "cas123",
                "artifacts": [],
            }
        ],
    }
    fake_requests = FakeRequests(payload)
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    cache = tmp_path / "build-17812.albs.json"

    first = fetch_build_metadata(17812, cache_path=cache)
    second = fetch_build_metadata(17812, cache_path=cache)

    assert first.package == "nginx"
    assert second.source_cas_hash == "cas123"
    assert cache.exists()
    assert len(fake_requests.calls) == 1


def test_fetch_build_metadata_reports_404_plainly(tmp_path: Path, monkeypatch: Any) -> None:
    # A non-existent build id returns a clean 404 from the API; surface it as a
    # plain "not found" rather than falling through to the HTML fallback (which
    # would fail later with a confusing "HTML fallback did not contain metadata").
    not_found = FakeResponse(
        {"detail": "Build with build_id=57809 is not found"}, ok=False, status_code=404
    )
    fake_requests = FakeSequenceRequests([not_found])
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)

    # BuildNotFoundError (a ValueError subclass) lets UIs distinguish "no such
    # build" from a genuine fetch/parse failure.
    with pytest.raises(BuildNotFoundError, match="57809 is not found"):
        fetch_build_metadata(57809, cache_path=tmp_path / "build-57809.albs.json")

    # The HTML fallback URL was never even fetched -- only the API was hit.
    assert len(fake_requests.calls) == 1
    assert "/api/v1/builds/57809/" in fake_requests.calls[0]


def test_fetch_build_metadata_caches_html_fallback(
    tmp_path: Path, monkeypatch: Any
) -> None:
    html = """
    <html>
      <head><title>ALBS build 57811</title></head>
      <body>
        <p>Package: almalinux-release</p>
        <p>Commit: abc123</p>
        <p>Repository: https://git.almalinux.org/rpms/almalinux-release.git</p>
        <a>almalinux-release-10.0-1.el10.x86_64.rpm</a>
      </body>
    </html>
    """
    fake_requests = FakeSequenceRequests(
        [
            FakeResponse(ok=False, content_type="text/html"),
            FakeResponse(content_type="text/html", text=html),
        ]
    )
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    cache = tmp_path / "build-57811.albs.json"

    first = fetch_build_metadata(57811, cache_path=cache)
    cached = json.loads(cache.read_text(encoding="utf-8"))
    second = fetch_build_metadata(57811, cache_path=cache)

    assert first.package == "almalinux-release"
    assert cached["build_id"] == "57811"
    assert cached["package"] == "almalinux-release"
    assert cached["binary_rpms"] == ["almalinux-release-10.0-1.el10.x86_64.rpm"]
    assert second.commit == "abc123"
    assert len(fake_requests.calls) == 2


def test_fetch_build_metadata_rejects_empty_spa_html_fallback(
    tmp_path: Path, monkeypatch: Any
) -> None:
    html = """
    <!DOCTYPE html>
    <html>
      <head><title>AlmaLinux Build System</title></head>
      <body><div id="q-app"></div></body>
    </html>
    """
    fake_requests = FakeSequenceRequests(
        [
            FakeResponse(ok=False, content_type="application/json", text='{"detail":"not found"}'),
            FakeResponse(content_type="text/html", text=html),
        ]
    )
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    cache = tmp_path / "build-57811.albs.json"

    with pytest.raises(ValueError, match="did not contain build metadata"):
        fetch_build_metadata(57811, cache_path=cache)

    assert not cache.exists()
    assert len(fake_requests.calls) == 2


def test_fetch_build_metadata_discards_cached_empty_spa_fallback(
    tmp_path: Path, monkeypatch: Any
) -> None:
    payload = {
        "id": 57811,
        "package": "real-package",
        "tasks": [
            {
                "ref": {
                    "url": "https://git.almalinux.org/rpms/real-package.git",
                    "git_commit_hash": "abc123",
                },
                "artifacts": [],
            }
        ],
    }
    fake_requests = FakeRequests(payload)
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    cache = tmp_path / "build-57811.albs.json"
    cache.write_text(
        json.dumps(
            {
                "build_id": "57811",
                "package": "AlmaLinux",
                "source_repository": "unknown-albs-source:AlmaLinux",
                "commit": "unknown",
                "source_rpm": None,
                "binary_rpms": [],
                "source_url": "https://build.almalinux.org/build/57811",
                "title": "AlmaLinux Build System",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    metadata = fetch_build_metadata(57811, cache_path=cache)

    assert metadata.package == "real-package"
    assert json.loads(cache.read_text(encoding="utf-8"))["package"] == "real-package"
    assert len(fake_requests.calls) == 1


def test_fetch_build_metadata_ignores_cache_for_a_different_build(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # A fresh cache whose build id does not match the request must be refetched,
    # not silently reused (regression: one cache path reused across builds
    # returned a graph for the wrong build).
    payload = {
        "id": 17812,
        "package": "nginx",
        "tasks": [
            {
                "ref": {
                    "url": "https://git.almalinux.org/rpms/nginx.git",
                    "git_commit_hash": "abc123",
                },
                "artifacts": [],
            }
        ],
    }
    fake_requests = FakeRequests(payload)
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    cache = tmp_path / "shared.albs.json"
    # Fresh mtime, but it holds a DIFFERENT build id.
    cache.write_text('{"id": 999, "package": "other-build", "tasks": []}\n', encoding="utf-8")

    metadata = fetch_build_metadata(17812, cache_path=cache)

    assert metadata.package == "nginx"  # refetched the requested build, not the cache
    assert len(fake_requests.calls) == 1  # did not reuse the id=999 cache


def test_fetch_build_metadata_rejects_cache_with_build_id_but_no_id(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # parse_build_metadata accepts "build_id" or "id"; the guard must too. A
    # fresh cache holding {"build_id": 999} with no "id" was previously treated
    # as "absent id" and reused for any requested build - it must refetch.
    payload = {"id": 17812, "package": "nginx", "tasks": []}
    fake_requests = FakeRequests(payload)
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    cache = tmp_path / "shared.albs.json"
    cache.write_text('{"build_id": 999, "package": "other-build", "tasks": []}\n', encoding="utf-8")

    metadata = fetch_build_metadata(17812, cache_path=cache)

    assert metadata.package == "nginx"  # refetched, did not reuse the build_id=999 cache
    assert len(fake_requests.calls) == 1


def test_fetch_build_metadata_accepts_idless_fixture_cache(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # A cache with neither "id" nor "build_id" is a synthetic / HTML-fallback
    # fixture and is still accepted without a build-id match (no refetch).
    fake_requests = FakeRequests({"id": 17812, "package": "nginx", "tasks": []})
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    cache = tmp_path / "fixture.albs.json"
    cache.write_text('{"package": "synthetic", "tasks": []}\n', encoding="utf-8")

    metadata = fetch_build_metadata(17812, cache_path=cache)

    assert metadata.package == "synthetic"  # reused the idless fixture
    assert len(fake_requests.calls) == 0  # no refetch


def test_fetch_build_metadata_refreshes_stale_local_cache(tmp_path: Path, monkeypatch: Any) -> None:
    payload = {
        "id": 17812,
        "package": "nginx",
        "tasks": [
            {
                "ref": {
                    "url": "https://git.almalinux.org/rpms/nginx.git",
                    "git_commit_hash": "abc123",
                },
                "alma_commit_cas_hash": "cas123",
                "artifacts": [],
            }
        ],
    }
    fake_requests = FakeRequests(payload)
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    cache = tmp_path / "build-17812.albs.json"
    cache.write_text(
        '{"id": 17812, "package": "stale", "tasks": []}\n',
        encoding="utf-8",
    )
    old_timestamp = 1_700_000_000
    os.utime(cache, (old_timestamp, old_timestamp))

    metadata = fetch_build_metadata(17812, cache_path=cache, cache_ttl_seconds=300)

    assert metadata.package == "nginx"
    assert len(fake_requests.calls) == 1

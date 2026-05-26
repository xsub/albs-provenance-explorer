from __future__ import annotations

import os
from pathlib import Path
from types import ModuleType
from typing import Any

from albs_graph.adapters.albs import fetch_build_metadata


class FakeResponse:
    ok = True
    headers = {"content-type": "application/json"}
    text = ""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def json(self) -> dict[str, Any]:
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

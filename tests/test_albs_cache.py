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

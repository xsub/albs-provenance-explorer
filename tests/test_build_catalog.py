"""Cached build-number catalog (D120).

No network: the ALBS ``/api/v1/builds/`` list is parsed from a literal payload
and ``fetch_build_list`` is exercised through an injected ``requests`` module.
The on-disk catalog round-trips through a temp file.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from albs_graph.adapters.albs import BuildSummary, fetch_build_list, parse_build_list
from albs_graph.services import BuildCatalog

_LIST = {
    "builds": [
        {
            "id": 100,
            "created_at": "2026-05-31T10:00:00",
            "owner": {"username": "alice"},
            "tasks": [
                {"ref": {"url": "https://git.almalinux.org/rpms/nginx.git"},
                 "platform": {"name": "AlmaLinux-9"}},
                {"ref": {"url": "https://git.almalinux.org/rpms/nginx.git"},  # dup -> one pkg
                 "platform": {"name": "AlmaLinux-9"}},
            ],
        },
        {
            "id": 99,
            "tasks": [
                {"ref": {"url": "kdepim-addons-25.12.3-1.el10_2.src.rpm"},  # SRPM upload ref
                 "platform": {"name": "AlmaLinux-10"}},
            ],
        },
    ],
    "total_builds": 2,
    "current_page": 1,
}


def test_parse_build_list_extracts_id_packages_platforms() -> None:
    builds = parse_build_list(_LIST)
    assert [b.build_id for b in builds] == [100, 99]
    assert builds[0].packages == ("nginx",)  # the two nginx tasks collapse to one
    assert builds[0].platforms == ("AlmaLinux-9",)
    assert builds[0].owner == "alice"
    # An SRPM-upload ref is cleaned to the package name, not the .src.rpm filename.
    assert builds[1].packages == ("kdepim-addons",)
    label = builds[0].label()
    assert "100" in label and "nginx" in label and "AlmaLinux-9" in label and "2026-05-31" in label


def test_fetch_build_list_via_injected_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeResponse:
        ok = True
        status_code = 200
        headers = {"content-type": "application/json"}

        def json(self) -> dict[str, Any]:
            return _LIST

    class _FakeRequests(ModuleType):
        def __init__(self) -> None:
            super().__init__("requests")
            self.calls: list[str] = []

        def get(self, url: str, timeout: int) -> _FakeResponse:
            self.calls.append(url)
            return _FakeResponse()

    fake = _FakeRequests()
    monkeypatch.setitem(sys.modules, "requests", fake)

    builds = fetch_build_list("https://build.almalinux.org", page=2)

    assert [b.build_id for b in builds] == [100, 99]
    assert "/api/v1/builds/?pageNumber=2" in fake.calls[0]


def _summary(build_id: int, package: str = "pkg") -> BuildSummary:
    return BuildSummary(build_id=build_id, packages=(package,), platforms=("AlmaLinux-9",))


def test_build_catalog_merge_upserts_and_sorts_desc(tmp_path: Path) -> None:
    catalog = BuildCatalog(tmp_path / "catalog.json")
    catalog.merge([_summary(99), _summary(100)])
    assert catalog.build_ids() == [100, 99]  # newest id first
    # A later merge upserts (newest wins) and keeps the sort order.
    catalog.merge([_summary(101), _summary(100, package="updated")])
    assert catalog.build_ids() == [101, 100, 99]
    hundred = next(b for b in catalog.load() if b.build_id == 100)
    assert hundred.packages == ("updated",)


def test_build_catalog_record_roundtrips(tmp_path: Path) -> None:
    catalog = BuildCatalog(tmp_path / "catalog.json")
    catalog.record(_summary(57810, package="buildah"))
    loaded = catalog.load()
    assert len(loaded) == 1 and loaded[0].build_id == 57810
    assert loaded[0].packages == ("buildah",)


def test_build_catalog_load_tolerates_missing_or_corrupt(tmp_path: Path) -> None:
    assert BuildCatalog(tmp_path / "absent.json").load() == []  # no file -> empty
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("not json{", encoding="utf-8")
    assert BuildCatalog(corrupt).load() == []  # never raises

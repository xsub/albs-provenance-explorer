"""Confirm the ALBS pipeline works across multiple build ids / packages / arches.

Uses synthetic ALBS-API-shaped metadata (no network) modelled on the real
build-17812 structure, so the parser/graph/coverage are exercised on builds
other than 17812.
"""

from __future__ import annotations

from typing import Any

import pytest

from albs_graph.adapters.albs import graph_from_build_metadata, parse_build_metadata
from albs_graph.model import NodeType
from albs_graph.provenance import coverage_report


def _albs_build(build_id: int, package: str, version: str, arches: list[str]) -> dict[str, Any]:
    tasks: list[dict[str, Any]] = []
    artifact_id = build_id * 100
    for index, arch in enumerate(arches):
        artifact_id += 2
        artifacts = [
            {
                "type": "rpm",
                "id": artifact_id - 1,
                "name": f"{package}-{version}.src.rpm",
                "href": f"/pulp/api/v3/content/rpm/packages/{artifact_id - 1}/",
                "cas_hash": f"src-{build_id}-{arch}",
            },
            {
                "type": "rpm",
                "id": artifact_id,
                "name": f"{package}-{version}.{arch}.rpm",
                "href": f"/pulp/api/v3/content/rpm/packages/{artifact_id}/",
                "cas_hash": f"bin-{build_id}-{arch}",
            },
        ]
        tasks.append(
            {
                "id": build_id * 10 + index,
                "arch": arch,
                "status": "completed",
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": "2026-01-01T00:10:00Z",
                "is_cas_authenticated": True,
                "alma_commit_cas_hash": f"commit-{build_id}",
                "platform": {"name": "AlmaLinux-9"},
                "ref": {
                    "url": f"https://git.almalinux.org/rpms/{package}.git",
                    "git_ref": f"imports/c9/{package}-{version}",
                    "git_commit_hash": f"commit-{build_id}",
                    "ref_type": 2,
                },
                "artifacts": artifacts,
                "test_tasks": [],
            }
        )
    return {
        "id": build_id,
        "build_id": build_id,
        "created_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:30:00Z",
        "owner": {"username": "builder", "email": "builder@almalinux.org"},
        "sign_tasks": [{"id": build_id + 1, "status": "completed"}],
        "release_id": build_id + 1000,
        "released": True,
        "tasks": tasks,
    }


_BUILDS = [
    _albs_build(20001, "zlib", "1.2.11-40.el9", ["x86_64", "aarch64"]),
    _albs_build(20002, "curl", "7.76.1-29.el9", ["x86_64", "ppc64le", "s390x"]),
]


@pytest.mark.parametrize("data", _BUILDS)
def test_parser_and_graph_are_not_17812_specific(data: dict[str, Any]) -> None:
    metadata = parse_build_metadata(data)
    graph = graph_from_build_metadata(metadata)

    expected_binaries = len(data["tasks"])  # one binary RPM per task in the fixture
    assert metadata.package in {"zlib", "curl"}
    assert len(graph.find_by_type(NodeType.BINARY_RPM)) == expected_binaries
    assert len(graph.find_by_type(NodeType.SRPM)) == expected_binaries


@pytest.mark.parametrize("data", _BUILDS)
def test_provenance_axis_complete_across_builds(data: dict[str, Any]) -> None:
    graph = graph_from_build_metadata(parse_build_metadata(data))
    report = coverage_report(graph)

    # Build linkage + signature + release + CAS evidence are all present, so
    # provenance is complete; security-context evidence is absent (honest 0).
    assert report.provenance.fraction == 1.0
    assert report.security_context.fraction == 0.0

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation


_ARCH_PREFERENCE = ("x86_64", "aarch64", "ppc64le", "s390x", "i686", "noarch", "src")


@dataclass(frozen=True)
class ArtifactInventoryItem:
    build_task_id: str
    build_arch: str
    artifact_node_id: str
    artifact_type: str
    artifact_id: str | None
    filename: str
    package_name: str | None
    artifact_arch: str
    kind: str
    purl: str | None
    cas_hash: str | None
    source_rpm: str | None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "build_task_id": self.build_task_id,
            "build_arch": self.build_arch,
            "artifact_node_id": self.artifact_node_id,
            "artifact_type": self.artifact_type,
            "filename": self.filename,
            "artifact_arch": self.artifact_arch,
            "kind": self.kind,
        }
        optional = {
            "artifact_id": self.artifact_id,
            "package_name": self.package_name,
            "purl": self.purl,
            "cas_hash": self.cas_hash,
            "source_rpm": self.source_rpm,
        }
        return data | {key: value for key, value in optional.items() if value}


@dataclass(frozen=True)
class ArtifactArchSummary:
    build_arch: str
    total_artifacts: int
    artifact_arches: dict[str, int]
    packages: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "build_arch": self.build_arch,
            "total_artifacts": self.total_artifacts,
            "artifact_arches": self.artifact_arches,
            "packages": list(self.packages),
        }


def rpm_artifact_inventory(graph: ProvenanceGraph) -> list[ArtifactInventoryItem]:
    items: list[ArtifactInventoryItem] = []
    for task in graph.find_by_type(NodeType.BUILD_TASK):
        for edge in graph.outgoing(task.id, Relation.PRODUCES):
            artifact = graph.nodes[edge.target]
            if artifact.type not in {NodeType.SRPM, NodeType.BINARY_RPM}:
                continue
            items.append(_inventory_item(task, artifact))
    return sorted(
        items,
        key=lambda item: (
            _arch_sort_key(item.build_arch),
            _arch_sort_key(item.artifact_arch),
            item.package_name or "",
            item.filename,
            item.artifact_node_id,
        ),
    )


def summarize_artifacts_by_build_arch(
    items: list[ArtifactInventoryItem],
) -> list[ArtifactArchSummary]:
    grouped: dict[str, list[ArtifactInventoryItem]] = defaultdict(list)
    for item in items:
        grouped[item.build_arch].append(item)

    summaries = [
        ArtifactArchSummary(
            build_arch=build_arch,
            total_artifacts=len(group),
            artifact_arches=dict(
                sorted(
                    Counter(item.artifact_arch for item in group).items(),
                    key=lambda pair: _arch_sort_key(pair[0]),
                )
            ),
            packages=tuple(
                sorted(
                    {item.package_name or item.filename.removesuffix(".rpm") for item in group}
                )
            ),
        )
        for build_arch, group in grouped.items()
    ]
    return sorted(summaries, key=lambda summary: _arch_sort_key(summary.build_arch))


def _inventory_item(task: Node, artifact: Node) -> ArtifactInventoryItem:
    metadata = artifact.metadata
    return ArtifactInventoryItem(
        build_task_id=task.id,
        build_arch=str(task.metadata.get("arch") or "build"),
        artifact_node_id=artifact.id,
        artifact_type=str(artifact.type),
        artifact_id=_text(metadata.get("artifact_id")),
        filename=artifact.label,
        package_name=_text(metadata.get("name")),
        artifact_arch=str(metadata.get("arch") or "unknown"),
        kind=_artifact_kind(artifact),
        purl=_text(metadata.get("purl")),
        cas_hash=_text(metadata.get("cas_hash")),
        source_rpm=_text(metadata.get("sourcerpm")),
    )


def _artifact_kind(artifact: Node) -> str:
    if artifact.type == NodeType.SRPM:
        return "srpm"
    name = str(artifact.metadata.get("name") or artifact.label)
    arch = str(artifact.metadata.get("arch") or "")
    if _is_debug_artifact(name):
        return "debug"
    if arch == "noarch":
        return "noarch"
    return "binary"


def _is_debug_artifact(name: str) -> bool:
    return (
        name.endswith("-debuginfo")
        or name.endswith("-debugsource")
        or "-debuginfo-" in name
        or "-debugsource-" in name
    )


def _arch_sort_key(value: str) -> tuple[int, str]:
    try:
        return (_ARCH_PREFERENCE.index(value), value)
    except ValueError:
        return (len(_ARCH_PREFERENCE), value)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

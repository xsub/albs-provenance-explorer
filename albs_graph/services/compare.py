from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from albs_graph.model import NodeType, ProvenanceGraph


@dataclass(frozen=True)
class ArtifactDelta:
    key: str
    change: str
    left: str | None = None
    right: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "change": self.change,
            "left": self.left,
            "right": self.right,
            "detail": self.detail,
        }


def compare_artifacts(left: ProvenanceGraph, right: ProvenanceGraph) -> list[ArtifactDelta]:
    left_items = {_artifact_key(node): node for node in left.find_by_type(NodeType.BINARY_RPM)}
    right_items = {_artifact_key(node): node for node in right.find_by_type(NodeType.BINARY_RPM)}
    deltas: list[ArtifactDelta] = []
    for key in sorted(left_items.keys() - right_items.keys()):
        node = left_items[key]
        deltas.append(ArtifactDelta(key, "removed", left=node.id, detail=node.label))
    for key in sorted(right_items.keys() - left_items.keys()):
        node = right_items[key]
        deltas.append(ArtifactDelta(key, "added", right=node.id, detail=node.label))
    for key in sorted(left_items.keys() & right_items.keys()):
        left_node = left_items[key]
        right_node = right_items[key]
        changed = _artifact_fingerprint(left_node.metadata) != _artifact_fingerprint(
            right_node.metadata
        )
        if changed:
            deltas.append(
                ArtifactDelta(
                    key,
                    "changed",
                    left=left_node.id,
                    right=right_node.id,
                    detail=f"{left_node.label} -> {right_node.label}",
                )
            )
    return deltas


def _artifact_key(node: Any) -> str:
    metadata = node.metadata
    name = metadata.get("name") or node.label
    arch = metadata.get("arch") or metadata.get("build_arch") or ""
    return f"{name}|{arch}"


def _artifact_fingerprint(metadata: dict[str, Any]) -> tuple[Any, ...]:
    return (
        metadata.get("version"),
        metadata.get("release"),
        metadata.get("purl"),
        metadata.get("cas_hash"),
        # ALBS metadata stores "source_rpm"; an RPM-header parse uses the
        # "sourcerpm" tag. Accept either so a real source change is detected.
        metadata.get("source_rpm") or metadata.get("sourcerpm"),
    )

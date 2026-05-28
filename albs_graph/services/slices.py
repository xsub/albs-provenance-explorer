"""Focused graph projections for task-oriented frontends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from albs_graph.model import NodeType, ProvenanceGraph, Relation
from albs_graph.provenance.trust import (
    find_binary_rpm,
    focused_trust_graph,
    select_default_binary_rpm,
    source_build_subgraph,
)
from albs_graph.provenance.universe import neighborhood_subgraph, path_subgraph, dependency_paths


@dataclass(frozen=True)
class GraphSlice:
    """A focused graph plus UI-friendly context about why it was selected."""

    name: str
    graph: ProvenanceGraph
    focus: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "focus": self.focus,
            "metadata": self.metadata,
            "nodes": len(self.graph.nodes),
            "edges": len(self.graph.edges),
        }


class GraphSlices:
    """Build focused subgraphs for investigation modes."""

    def __init__(self, graph: ProvenanceGraph) -> None:
        self.graph = graph

    def trust_path(
        self,
        package_or_node: str | None = None,
        *,
        arch: str | None = None,
        include_tests: bool = False,
    ) -> GraphSlice:
        rpm = (
            find_binary_rpm(self.graph, package_or_node, arch=arch)
            if package_or_node
            else select_default_binary_rpm(self.graph, arch=arch)
        )
        report = self.graph.trust_path_report(rpm.id).to_dict()
        return GraphSlice(
            name="trust_path",
            graph=focused_trust_graph(self.graph, rpm.id, include_tests=include_tests),
            focus=rpm.id,
            metadata={"trust": report},
        )

    def source_build(self, source_package: str, *, arch: str | None = None) -> GraphSlice:
        return GraphSlice(
            name="source_build",
            graph=source_build_subgraph(self.graph, source_package, arch=arch),
            focus=source_package,
            metadata={"arch": arch},
        )

    def dependency_evidence(self, subject_id: str) -> GraphSlice:
        self._require_node(subject_id)
        selected = {subject_id}
        claims = [
            node
            for node in self.graph.find_by_type(NodeType.DEPENDENCY_CLAIM)
            if node.metadata.get("subject") == subject_id
        ]
        selected.update(node.id for node in claims)
        selected.update(
            node.id
            for node in self.graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION)
            if node.metadata.get("subject") == subject_id
        )
        for claim in claims:
            selected.update(edge.source for edge in self.graph.incoming(claim.id, Relation.OBSERVED_AS))
        return GraphSlice(
            name="dependency_evidence",
            graph=self.graph.subgraph(selected),
            focus=subject_id,
            metadata={"claims": len(claims)},
        )

    def security_context(self, subject_id: str) -> GraphSlice:
        self._require_node(subject_id)
        selected = {subject_id}
        evidence_relations = {
            Relation.DESCRIBED_BY,
            Relation.FIXES,
            Relation.AFFECTED_BY,
            Relation.AUTHENTICATED_BY,
        }
        frontier = [
            edge.target
            for edge in self.graph.outgoing(subject_id)
            if edge.relation in evidence_relations
        ]
        selected.update(frontier)
        for node_id in frontier:
            if self.graph.nodes[node_id].type == NodeType.ERRATA:
                selected.update(edge.target for edge in self.graph.outgoing(node_id, Relation.FIXES))
        return GraphSlice(
            name="security_context",
            graph=self.graph.subgraph(selected),
            focus=subject_id,
            metadata={"security_identity": self.graph.nodes[subject_id].metadata.get("security_identity")},
        )

    def universe_neighborhood(self, selector: str, *, incoming: bool, depth: int = 1) -> GraphSlice:
        return GraphSlice(
            name="universe_neighborhood",
            graph=neighborhood_subgraph(self.graph, selector, incoming=incoming),
            focus=selector,
            metadata={"incoming": incoming, "depth": depth},
        )

    def universe_path(self, source_id: str, target_selector: str) -> GraphSlice:
        paths = dependency_paths(self.graph, source_id, target_selector)
        return GraphSlice(
            name="universe_path",
            graph=path_subgraph(self.graph, paths),
            focus=source_id,
            metadata={"target": target_selector, "paths": len(paths)},
        )

    def _require_node(self, node_id: str) -> None:
        if node_id not in self.graph.nodes:
            raise ValueError(f"Unknown node: {node_id}")

"""Read-only graph query helpers for UI and CLI callers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from albs_graph.model import Edge, Node, NodeType, ProvenanceGraph, Relation


@dataclass(frozen=True)
class NodeSummary:
    id: str
    type: str
    label: str
    metadata: dict[str, Any]
    incoming: int
    outgoing: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "metadata": self.metadata,
            "incoming": self.incoming,
            "outgoing": self.outgoing,
        }


@dataclass(frozen=True)
class EdgeSummary:
    index: int
    source: str
    target: str
    relation: str
    metadata: dict[str, Any]
    source_label: str
    target_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "metadata": self.metadata,
            "source_label": self.source_label,
            "target_label": self.target_label,
        }


class GraphQueries:
    """Small typed query surface over a :class:`ProvenanceGraph`."""

    def __init__(self, graph: ProvenanceGraph) -> None:
        self.graph = graph
        # Map each edge object to its list index once. The graph is fixed for
        # this instance, so incoming()/outgoing() resolve indexes in O(1)
        # instead of rebuilding an O(E) dict on every call -- it matters on a
        # large universe (tens of thousands of edges) inspected per click.
        self._edge_index: dict[int, int] = {
            id(edge): index for index, edge in enumerate(graph.edges)
        }

    def node_summary(self, node_id: str) -> NodeSummary:
        node = self._node(node_id)
        return NodeSummary(
            id=node.id,
            type=str(node.type),
            label=node.label,
            metadata=dict(node.metadata),
            incoming=len(self.graph.incoming(node.id)),
            outgoing=len(self.graph.outgoing(node.id)),
        )

    def edge_summary(self, index: int) -> EdgeSummary:
        try:
            edge = self.graph.edges[index]
        except IndexError as exc:
            raise ValueError(f"Unknown edge index: {index}") from exc
        return self._edge_summary(index, edge)

    def incoming(self, node_id: str, relation: Relation | str | None = None) -> list[EdgeSummary]:
        self._node(node_id)
        return [
            self._edge_summary(index, edge)
            for index, edge in self._indexed_edges(self.graph.incoming(node_id, relation))
        ]

    def outgoing(self, node_id: str, relation: Relation | str | None = None) -> list[EdgeSummary]:
        self._node(node_id)
        return [
            self._edge_summary(index, edge)
            for index, edge in self._indexed_edges(self.graph.outgoing(node_id, relation))
        ]

    def artifacts(
        self,
        *,
        package: str | None = None,
        arch: str | None = None,
        limit: int | None = None,
    ) -> list[NodeSummary]:
        nodes = self.graph.find_by_type(NodeType.BINARY_RPM)
        if package is not None:
            nodes = [
                node
                for node in nodes
                if node.metadata.get("name") == package or node.label.startswith(package)
            ]
        if arch is not None:
            nodes = [node for node in nodes if node.metadata.get("arch") == arch]
        nodes = sorted(nodes, key=lambda node: (str(node.metadata.get("name", "")), node.label))
        if limit is not None:
            nodes = nodes[:limit]
        return [self.node_summary(node.id) for node in nodes]

    def find_nodes(
        self,
        text: str,
        *,
        node_types: Iterable[NodeType | str] | None = None,
        limit: int = 50,
    ) -> list[NodeSummary]:
        needle = text.casefold()
        allowed = {str(node_type) for node_type in node_types} if node_types else None
        matches: list[Node] = []
        for node in self.graph.nodes.values():
            if allowed is not None and str(node.type) not in allowed:
                continue
            if _matches_node(node, needle):
                matches.append(node)
            if len(matches) >= limit:
                break
        return [self.node_summary(node.id) for node in matches]

    def _node(self, node_id: str) -> Node:
        try:
            return self.graph.nodes[node_id]
        except KeyError as exc:
            raise ValueError(f"Unknown node: {node_id}") from exc

    def _edge_summary(self, index: int, edge: Edge) -> EdgeSummary:
        return EdgeSummary(
            index=index,
            source=edge.source,
            target=edge.target,
            relation=str(edge.relation),
            metadata=dict(edge.metadata),
            source_label=self.graph.nodes[edge.source].label,
            target_label=self.graph.nodes[edge.target].label,
        )

    def _indexed_edges(self, edges: list[Edge]) -> list[tuple[int, Edge]]:
        return [(self._edge_index[id(edge)], edge) for edge in edges]


def _matches_node(node: Node, needle: str) -> bool:
    if (
        needle in node.id.casefold()
        or needle in node.label.casefold()
        or needle in str(node.type).casefold()
    ):
        return True
    for key, value in node.metadata.items():
        if needle in str(key).casefold() or needle in str(value).casefold():
            return True
    return False

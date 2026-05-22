from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Iterable

from .edges import Edge, Relation
from .nodes import Node, NodeType


@dataclass(frozen=True)
class TrustPathReport:
    subject: str
    complete: bool
    checks: dict[str, bool]
    path: list[str]
    missing: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "complete": self.complete,
            "checks": self.checks,
            "path": self.path,
            "missing": self.missing,
        }


class ProvenanceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def add_node(self, node: Node) -> None:
        if node.id in self.nodes and self.nodes[node.id] != node:
            raise ValueError(f"Conflicting node definition for {node.id}")
        self.nodes[node.id] = node

    def add_edge(
        self,
        source: str,
        target: str,
        relation: Relation | str,
        **metadata: Any,
    ) -> None:
        if source not in self.nodes:
            raise ValueError(f"Missing source node: {source}")
        if target not in self.nodes:
            raise ValueError(f"Missing target node: {target}")
        self.edges.append(
            Edge(
                source=source,
                target=target,
                relation=Relation.canonical(relation),
                metadata=metadata,
            )
        )

    def outgoing(self, node_id: str, relation: Relation | str | None = None) -> list[Edge]:
        return [
            edge
            for edge in self.edges
            if edge.source == node_id and (relation is None or edge.relation == relation)
        ]

    def incoming(self, node_id: str, relation: Relation | str | None = None) -> list[Edge]:
        return [
            edge
            for edge in self.edges
            if edge.target == node_id and (relation is None or edge.relation == relation)
        ]

    def find_by_type(self, node_type: NodeType | str) -> list[Node]:
        return [node for node in self.nodes.values() if str(node.type) == str(node_type)]

    def find_by_label(self, label: str) -> list[Node]:
        normalized = label.lower()
        return [node for node in self.nodes.values() if normalized in node.label.lower()]

    def first_binary_rpm(self, package: str) -> Node | None:
        for node in self.find_by_type(NodeType.BINARY_RPM):
            name = str(node.metadata.get("name", node.label)).lower()
            if package.lower() in {name, node.label.lower()} or node.label.lower().startswith(
                package.lower()
            ):
                return node
        return None

    def reachable(self, start_node_id: str) -> set[str]:
        if start_node_id not in self.nodes:
            raise ValueError(f"Unknown node: {start_node_id}")
        adjacency: dict[str, list[str]] = defaultdict(list)
        for edge in self.edges:
            adjacency[edge.source].append(edge.target)
        seen: set[str] = set()
        queue: deque[str] = deque([start_node_id])
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(adjacency[current])
        return seen

    def has_relation_path(self, source: str, target: str) -> bool:
        return target in self.reachable(source)

    def source_to_artifact_path(self, rpm_node_id: str) -> list[str]:
        producers = self.incoming(rpm_node_id, Relation.PRODUCES)
        if not producers:
            return [rpm_node_id]

        build_id = producers[0].source
        cas_edges = self.incoming(build_id, Relation.BUILT_BY)
        cas_id = cas_edges[0].source if cas_edges else None
        commit_edges = self.incoming(cas_id, Relation.AUTHENTICATED_BY) if cas_id else []
        commit_id = commit_edges[0].source if commit_edges else None
        repo_edges = self.incoming(commit_id, Relation.POINTS_TO) if commit_id else []
        repo_id = repo_edges[0].source if repo_edges else None
        source_edges = self.incoming(repo_id, Relation.STORED_IN) if repo_id else []
        source_id = source_edges[0].source if source_edges else None

        return [
            node_id
            for node_id in (source_id, repo_id, commit_id, cas_id, build_id, rpm_node_id)
            if node_id is not None
        ]

    def trust_report_for_rpm(self, rpm_node_id: str) -> dict[str, Any]:
        return self.trust_path_report(rpm_node_id).to_dict() | {"rpm": rpm_node_id}

    def trust_path_report(self, rpm_node_id: str) -> TrustPathReport:
        if rpm_node_id not in self.nodes:
            raise ValueError(f"Unknown RPM node: {rpm_node_id}")

        incoming_relations = {edge.relation for edge in self.incoming(rpm_node_id)}
        outgoing_relations = {edge.relation for edge in self.outgoing(rpm_node_id)}
        build_tasks = [edge.source for edge in self.incoming(rpm_node_id, Relation.PRODUCES)]
        has_source_cas_attestation = any(
            any(
                edge.relation == Relation.AUTHENTICATED_BY
                for edge in self.incoming(cas_edge.source)
            )
            and self.nodes[cas_edge.source].type == NodeType.CAS_ATTESTATION
            for build_task in build_tasks
            for cas_edge in self.incoming(build_task, Relation.BUILT_BY)
        )

        checks = {
            "has_build_task": Relation.PRODUCES in incoming_relations,
            "has_signature": Relation.SIGNED_AS in outgoing_relations,
            "has_release": Relation.RELEASED_TO in outgoing_relations,
            "has_sbom": Relation.DESCRIBED_BY in outgoing_relations,
            "has_errata_link": (
                Relation.FIXES in outgoing_relations or Relation.AFFECTED_BY in outgoing_relations
            ),
            "has_source_cas_attestation": has_source_cas_attestation,
            "has_artifact_cas_attestation": any(
                edge.relation == Relation.AUTHENTICATED_BY
                and self.nodes[edge.target].type == NodeType.CAS_ATTESTATION
                for edge in self.outgoing(rpm_node_id)
            ),
        }
        missing = [name for name, passed in checks.items() if not passed]
        return TrustPathReport(
            subject=rpm_node_id,
            complete=not missing,
            checks=checks,
            path=self.source_to_artifact_path(rpm_node_id),
            missing=missing,
        )

    def neighborhood(self, node_id: str, depth: int = 1) -> "ProvenanceGraph":
        if node_id not in self.nodes:
            raise ValueError(f"Unknown node: {node_id}")
        selected = {node_id}
        frontier = {node_id}
        for _ in range(depth):
            next_frontier: set[str] = set()
            for edge in self.edges:
                if edge.source in frontier:
                    next_frontier.add(edge.target)
                if edge.target in frontier:
                    next_frontier.add(edge.source)
            selected.update(next_frontier)
            frontier = next_frontier
        return self.subgraph(selected)

    def subgraph(self, node_ids: Iterable[str]) -> "ProvenanceGraph":
        selected = set(node_ids)
        graph = ProvenanceGraph()
        for node_id in selected:
            graph.add_node(self.nodes[node_id])
        for edge in self.edges:
            if edge.source in selected and edge.target in selected:
                graph.add_edge(edge.source, edge.target, edge.relation, **edge.metadata)
        return graph

    def to_networkx(self) -> Any:
        try:
            import networkx as nx  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError("networkx is required for to_networkx()") from exc
        graph = nx.MultiDiGraph()
        for node in self.nodes.values():
            graph.add_node(node.id, label=node.label, type=str(node.type), **node.metadata)
        for edge in self.edges:
            graph.add_edge(edge.source, edge.target, relation=str(edge.relation), **edge.metadata)
        return graph

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "albs-provenance-explorer/v1",
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges],
        }

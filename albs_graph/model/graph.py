from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .edges import Edge, Relation
from .nodes import Node, NodeType


@dataclass(frozen=True)
class TrustPathReport:
    subject: str
    complete: bool
    provenance_complete: bool
    security_context_complete: bool
    checks: dict[str, bool]
    provenance_checks: dict[str, bool]
    security_context_checks: dict[str, bool]
    path: list[str]
    missing: list[str]
    missing_provenance: list[str]
    missing_security_context: list[str]
    # Three-state errata view (D79): "advisory_present" (an advisory ships this
    # exact NEVRA), "confirmed_clean" (an errata source was consulted and found
    # none -- the normal, trustworthy state), or "not_checked" (no source was
    # consulted; the only genuinely-open case). ``has_errata_link`` in
    # ``security_context_checks`` is satisfied by the first two.
    errata_status: str = "not_checked"

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "complete": self.complete,
            "provenance_complete": self.provenance_complete,
            "security_context_complete": self.security_context_complete,
            "checks": self.checks,
            "provenance_checks": self.provenance_checks,
            "security_context_checks": self.security_context_checks,
            "path": self.path,
            "missing": self.missing,
            "missing_provenance": self.missing_provenance,
            "missing_security_context": self.missing_security_context,
            "errata_status": self.errata_status,
        }


class ProvenanceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        # Indexes maintained on insert so the hot read paths (outgoing / incoming
        # / find_by_type / reachable) do not rescan the full edge list or node
        # dict. Each preserves insertion order, so query results are identical to
        # the old linear scans. They are kept consistent because every mutation
        # goes through add_node / add_edge (verified: nothing pokes .nodes/.edges
        # directly), and in-place metadata.update keeps the same Node object.
        self._outgoing: dict[str, list[Edge]] = defaultdict(list)
        self._incoming: dict[str, list[Edge]] = defaultdict(list)
        self._nodes_by_type: dict[str, list[Node]] = defaultdict(list)

    def add_node(self, node: Node) -> None:
        existing = self.nodes.get(node.id)
        if existing is not None and existing != node:
            raise ValueError(f"Conflicting node definition for {node.id}")
        if existing is None:
            self._nodes_by_type[str(node.type)].append(node)
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
        edge = Edge(
            source=source,
            target=target,
            relation=Relation.canonical(relation),
            metadata=metadata,
        )
        self.edges.append(edge)
        self._outgoing[source].append(edge)
        self._incoming[target].append(edge)

    def update_metadata(self, node_id: str, updates: dict[str, Any]) -> None:
        """Merge ``updates`` into an existing node's metadata, in place.

        The one method for post-hoc metadata enrichment (adapters used to poke
        ``graph.nodes[id].metadata`` directly). Routing it through a method lets a
        ``RecordingGraph`` intercept the change into an ``EvidencePatch``. The
        node id / type are unchanged, so the type index stays valid.
        """

        node = self.nodes.get(node_id)
        if node is None:
            raise ValueError(f"Unknown node: {node_id}")
        node.metadata.update(updates)

    def remove_node(self, node_id: str) -> None:
        """Remove a node and every edge incident to it. No-op if missing.

        Used by re-runnable enrichers (the reconciler purges its prior
        DEPENDENCY_RESOLUTION nodes before rebuilding) so a saved graph can be
        re-enriched without `Conflicting node definition` errors.
        """

        node = self.nodes.pop(node_id, None)
        if node is None:
            return
        by_type = self._nodes_by_type.get(str(node.type))
        if by_type is not None:
            self._nodes_by_type[str(node.type)] = [n for n in by_type if n.id != node_id]
        # Drop incident edges from the adjacency indexes + the flat list.
        for edge in self._outgoing.pop(node_id, []):
            others = self._incoming.get(edge.target)
            if others is not None:
                self._incoming[edge.target] = [e for e in others if e is not edge]
        for edge in self._incoming.pop(node_id, []):
            others = self._outgoing.get(edge.source)
            if others is not None:
                self._outgoing[edge.source] = [e for e in others if e is not edge]
        self.edges = [e for e in self.edges if e.source != node_id and e.target != node_id]

    def remove_edges_where(self, predicate: Callable[[Edge], bool]) -> int:
        """Remove every edge for which ``predicate`` returns True. Returns count.

        Used by the reconciler to purge prior CORROBORATES / CONFLICTS_WITH
        edges between claim pairs before rebuilding the verdicts.
        """

        keep = [edge for edge in self.edges if not predicate(edge)]
        dropped = len(self.edges) - len(keep)
        if dropped == 0:
            return 0
        self.edges = keep
        self._outgoing = defaultdict(list)
        self._incoming = defaultdict(list)
        for edge in self.edges:
            self._outgoing[edge.source].append(edge)
            self._incoming[edge.target].append(edge)
        return dropped

    def outgoing(self, node_id: str, relation: Relation | str | None = None) -> list[Edge]:
        edges = self._outgoing.get(node_id, ())
        if relation is None:
            return list(edges)
        return [edge for edge in edges if edge.relation == relation]

    def incoming(self, node_id: str, relation: Relation | str | None = None) -> list[Edge]:
        edges = self._incoming.get(node_id, ())
        if relation is None:
            return list(edges)
        return [edge for edge in edges if edge.relation == relation]

    def find_by_type(self, node_type: NodeType | str) -> list[Node]:
        return list(self._nodes_by_type.get(str(node_type), ()))

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
        seen: set[str] = set()
        queue: deque[str] = deque([start_node_id])
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(edge.target for edge in self._outgoing.get(current, ()))
        return seen

    def has_relation_path(self, source: str, target: str) -> bool:
        return target in self.reachable(source)

    def source_to_artifact_path(self, rpm_node_id: str) -> list[str]:
        producers = _sorted_edges(self.incoming(rpm_node_id, Relation.PRODUCES))
        if not producers:
            return [rpm_node_id]

        build_id = producers[0].source
        cas_edges = _prefer_cas_evidence_edges(self.incoming(build_id, Relation.BUILT_BY), self)
        cas_id = cas_edges[0].source if cas_edges else None
        commit_edges = _sorted_edges(self.incoming(cas_id, Relation.AUTHENTICATED_BY)) if cas_id else []
        commit_id = commit_edges[0].source if commit_edges else None
        repo_edges = _sorted_edges(self.incoming(commit_id, Relation.POINTS_TO)) if commit_id else []
        repo_id = repo_edges[0].source if repo_edges else None
        source_edges = _sorted_edges(self.incoming(repo_id, Relation.STORED_IN)) if repo_id else []
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
            and _has_cas_evidence(self.nodes[cas_edge.source])
            for build_task in build_tasks
            for cas_edge in self.incoming(build_task, Relation.BUILT_BY)
        )

        provenance_checks = {
            "has_build_task": Relation.PRODUCES in incoming_relations,
            "has_signature": Relation.SIGNED_AS in outgoing_relations,
            "has_release": Relation.RELEASED_TO in outgoing_relations,
            "has_source_cas_attestation": has_source_cas_attestation,
            "has_artifact_cas_attestation": any(
                edge.relation == Relation.AUTHENTICATED_BY
                and self.nodes[edge.target].type == NodeType.CAS_ATTESTATION
                and _has_cas_evidence(self.nodes[edge.target])
                for edge in self.outgoing(rpm_node_id)
            ),
        }
        # Three-state errata (D79). An advisory edge means this exact build
        # ships in an advisory ("advisory_present"). Absent that, an errata
        # source may have recorded "confirmed_clean" on the node (it was
        # consulted and found no advisory -- the normal state for most
        # packages, which must NOT be penalised as missing). With neither, no
        # source was consulted: "not_checked", the only genuinely-open case.
        has_advisory_edge = (
            Relation.FIXES in outgoing_relations or Relation.AFFECTED_BY in outgoing_relations
        )
        recorded_status = self.nodes[rpm_node_id].metadata.get("errata_status")
        if has_advisory_edge:
            errata_status = "advisory_present"
        elif recorded_status == "confirmed_clean":
            errata_status = "confirmed_clean"
        else:
            errata_status = "not_checked"

        security_context_checks = {
            "has_sbom": Relation.DESCRIBED_BY in outgoing_relations,
            # Satisfied by a present advisory OR a confirmed-clean result; only
            # "not_checked" leaves it open.
            "has_errata_link": errata_status != "not_checked",
        }
        checks = provenance_checks | security_context_checks
        missing_provenance = [name for name, passed in provenance_checks.items() if not passed]
        missing_security_context = [
            name for name, passed in security_context_checks.items() if not passed
        ]
        missing = [name for name, passed in checks.items() if not passed]
        provenance_complete = not missing_provenance
        security_context_complete = not missing_security_context
        return TrustPathReport(
            subject=rpm_node_id,
            complete=provenance_complete and security_context_complete,
            provenance_complete=provenance_complete,
            security_context_complete=security_context_complete,
            checks=checks,
            provenance_checks=provenance_checks,
            security_context_checks=security_context_checks,
            path=self.source_to_artifact_path(rpm_node_id),
            missing=missing,
            missing_provenance=missing_provenance,
            missing_security_context=missing_security_context,
            errata_status=errata_status,
        )

    def neighborhood(self, node_id: str, depth: int = 1) -> "ProvenanceGraph":
        if node_id not in self.nodes:
            raise ValueError(f"Unknown node: {node_id}")
        selected = {node_id}
        frontier = {node_id}
        for _ in range(depth):
            next_frontier: set[str] = set()
            for current in frontier:
                next_frontier.update(edge.target for edge in self._outgoing.get(current, ()))
                next_frontier.update(edge.source for edge in self._incoming.get(current, ()))
            selected.update(next_frontier)
            frontier = next_frontier
        return self.subgraph(selected)

    def copy(self) -> "ProvenanceGraph":
        """Deep copy: fresh node/edge metadata *trees*, so an in-place mutation
        on a nested value of the copy (e.g. a dry-run enrichment modifying a
        ``security_identity`` sub-dict, or a candidate dict inside its
        ``cpe_candidates`` list) never leaks back into this graph.

        Regression: a previous shallow ``dict(node.metadata)`` left nested
        dict/list values shared between the original and the copy, so
        ``ProvenanceGraph.copy()`` did NOT actually isolate dry-run writes that
        went through nested mutation.
        """

        clone = ProvenanceGraph()
        for node in self.nodes.values():
            clone.add_node(Node(node.id, node.type, node.label, deepcopy(node.metadata)))
        for edge in self.edges:
            clone.add_edge(edge.source, edge.target, edge.relation, **deepcopy(edge.metadata))
        return clone

    def subgraph(self, node_ids: Iterable[str]) -> "ProvenanceGraph":
        selected = set(node_ids)
        graph = ProvenanceGraph()
        for node_id in sorted(selected):
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


def _sorted_edges(edges: Iterable[Edge]) -> list[Edge]:
    return sorted(edges, key=lambda edge: (edge.source, edge.target, str(edge.relation)))


def _prefer_cas_evidence_edges(edges: Iterable[Edge], graph: ProvenanceGraph) -> list[Edge]:
    return sorted(
        edges,
        key=lambda edge: (
            not _has_cas_evidence(graph.nodes[edge.source]),
            edge.source,
            edge.target,
            str(edge.relation),
        ),
    )


def _has_cas_evidence(node: Node) -> bool:
    return node.type == NodeType.CAS_ATTESTATION and bool(node.metadata.get("cas_hash"))

from __future__ import annotations

from typing import Any

from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation


def trust_path(graph: ProvenanceGraph, package_or_node: str) -> dict[str, Any]:
    return graph.trust_path_report(find_binary_rpm(graph, package_or_node).id).to_dict()


def trust_reports(graph: ProvenanceGraph) -> list[dict[str, Any]]:
    return [
        graph.trust_path_report(node.id).to_dict()
        for node in graph.find_by_type(NodeType.BINARY_RPM)
    ]


def find_binary_rpm(graph: ProvenanceGraph, name_or_node: str, arch: str | None = None) -> Node:
    if name_or_node in graph.nodes:
        node = graph.nodes[name_or_node]
        if node.type != NodeType.BINARY_RPM:
            raise ValueError(f"Node is not a binary RPM: {name_or_node}")
        if arch and node.metadata.get("arch") != arch:
            raise ValueError(f"RPM {name_or_node} does not match arch {arch}")
        return node

    candidates = graph.find_by_type(NodeType.BINARY_RPM)
    if arch:
        candidates = [node for node in candidates if node.metadata.get("arch") == arch]

    exact_matches = [node for node in candidates if node.metadata.get("name") == name_or_node]
    matches = exact_matches or [
        node
        for node in candidates
        if node.label == name_or_node or node.label.startswith(f"{name_or_node}-")
    ]

    if not matches:
        suffix = f" for arch {arch}" if arch else ""
        raise ValueError(f"No binary RPM found for {name_or_node}{suffix}")
    if len(matches) > 1:
        choices = ", ".join(sorted(node.label for node in matches[:10]))
        more = f" and {len(matches) - 10} more" if len(matches) > 10 else ""
        raise ValueError(
            f"Ambiguous RPM {name_or_node}; use --arch or a full node id. Matches: {choices}{more}"
        )
    return matches[0]


def focused_trust_graph(
    graph: ProvenanceGraph,
    rpm_node_id: str,
    include_tests: bool = False,
) -> ProvenanceGraph:
    path = graph.source_to_artifact_path(rpm_node_id)
    selected = set(path)

    build_task_id = path[-2] if len(path) >= 2 else None
    if build_task_id:
        selected.update(
            edge.source for edge in graph.incoming(build_task_id, Relation.DERIVED_FROM)
        )
        selected.update(edge.target for edge in graph.outgoing(build_task_id, Relation.BUILT_IN))
        srpm_nodes = [
            edge.target
            for edge in graph.outgoing(build_task_id, Relation.PRODUCES)
            if graph.nodes[edge.target].type == NodeType.SRPM
        ]
        selected.update(srpm_nodes)
        for srpm_node in srpm_nodes:
            selected.update(
                edge.target for edge in graph.outgoing(srpm_node, Relation.AUTHENTICATED_BY)
            )
        if include_tests:
            selected.update(
                edge.target for edge in graph.outgoing(build_task_id, Relation.TESTED_BY)
            )

    evidence_relations = {
        Relation.AUTHENTICATED_BY,
        Relation.SIGNED_AS,
        Relation.RELEASED_TO,
        Relation.DESCRIBED_BY,
        Relation.FIXES,
        Relation.AFFECTED_BY,
    }
    frontier = {
        edge.target for edge in graph.outgoing(rpm_node_id) if edge.relation in evidence_relations
    }
    selected.update(frontier)
    for node_id in list(frontier):
        if graph.nodes[node_id].type == NodeType.ERRATA:
            selected.update(edge.target for edge in graph.outgoing(node_id, Relation.FIXES))

    return graph.subgraph(selected)

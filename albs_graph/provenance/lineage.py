from __future__ import annotations

from albs_graph.model import NodeType, ProvenanceGraph, Relation


def artifacts_from_source(graph: ProvenanceGraph, source_package: str) -> list[str]:
    source_nodes = [
        node
        for node in graph.find_by_type(NodeType.SOURCE_PACKAGE)
        if node.label == source_package or node.id == source_package
    ]
    artifacts: list[str] = []
    for source in source_nodes:
        for node_id in graph.reachable(source.id):
            node = graph.nodes[node_id]
            if node.type in {NodeType.SRPM, NodeType.BINARY_RPM}:
                artifacts.append(node_id)
    return sorted(set(artifacts))


def cves_for_artifact(graph: ProvenanceGraph, rpm_node_id: str) -> list[str]:
    cves: set[str] = set()
    for edge in graph.outgoing(rpm_node_id):
        if edge.relation not in {Relation.FIXES, Relation.AFFECTED_BY}:
            continue
        for reachable in graph.reachable(edge.target):
            if graph.nodes[reachable].type == NodeType.CVE:
                cves.add(reachable)
    return sorted(cves)

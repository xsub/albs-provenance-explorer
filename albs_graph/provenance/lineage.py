from __future__ import annotations

from albs_graph.model import NodeType, ProvenanceGraph, Relation


def artifacts_from_source(graph: ProvenanceGraph, source_package: str) -> list[str]:
    """Binary RPMs / SRPMs produced from ``source_package``, scoped per task.

    Attribution walks each artifact's own source-to-artifact path (the per-task
    chain rpm <- task <- cas <- commit <- repo <- source) and keeps it only when
    *that* path roots at the requested source. Unrestricted graph reachability
    would over-attribute: in a multi-source batch the build-level aggregate node
    connects to every task, so the build's representative/first source could
    otherwise reach all of the build's artifacts.
    """

    source_ids = {
        node.id
        for node in graph.find_by_type(NodeType.SOURCE_PACKAGE)
        if node.label == source_package or node.id == source_package
    }
    if not source_ids:
        return []
    artifacts: list[str] = []
    for node in [*graph.find_by_type(NodeType.BINARY_RPM), *graph.find_by_type(NodeType.SRPM)]:
        path = graph.source_to_artifact_path(node.id)
        if len(path) >= 2 and path[0] in source_ids:
            artifacts.append(node.id)
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

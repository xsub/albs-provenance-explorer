from __future__ import annotations

from dataclasses import dataclass

from albs_graph.model import NodeType, ProvenanceGraph
from albs_graph.provenance.trust import trust_reports


@dataclass(frozen=True)
class GraphSummary:
    node_count: int
    edge_count: int
    rpm_count: int
    complete_trust_paths: int
    incomplete_trust_paths: int
    complete_provenance_paths: int
    incomplete_provenance_paths: int
    complete_security_contexts: int
    incomplete_security_contexts: int


def summarize(graph: ProvenanceGraph) -> GraphSummary:
    reports = trust_reports(graph)
    complete = sum(1 for report in reports if report["complete"])
    provenance_complete = sum(1 for report in reports if report["provenance_complete"])
    security_complete = sum(1 for report in reports if report["security_context_complete"])
    return GraphSummary(
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        rpm_count=len(graph.find_by_type(NodeType.BINARY_RPM)),
        complete_trust_paths=complete,
        incomplete_trust_paths=len(reports) - complete,
        complete_provenance_paths=provenance_complete,
        incomplete_provenance_paths=len(reports) - provenance_complete,
        complete_security_contexts=security_complete,
        incomplete_security_contexts=len(reports) - security_complete,
    )

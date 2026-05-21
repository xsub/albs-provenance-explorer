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


def summarize(graph: ProvenanceGraph) -> GraphSummary:
    reports = trust_reports(graph)
    complete = sum(1 for report in reports if report["complete"])
    return GraphSummary(
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        rpm_count=len(graph.find_by_type(NodeType.BINARY_RPM)),
        complete_trust_paths=complete,
        incomplete_trust_paths=len(reports) - complete,
    )

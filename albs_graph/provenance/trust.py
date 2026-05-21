from __future__ import annotations

from typing import Any

from albs_graph.model import NodeType, ProvenanceGraph


def trust_path(graph: ProvenanceGraph, package_or_node: str) -> dict[str, Any]:
    rpm_node_id = package_or_node
    if rpm_node_id not in graph.nodes:
        rpm = graph.first_binary_rpm(package_or_node)
        if rpm is None:
            raise ValueError(f"No binary RPM found for {package_or_node}")
        rpm_node_id = rpm.id
    return graph.trust_path_report(rpm_node_id).to_dict()


def trust_reports(graph: ProvenanceGraph) -> list[dict[str, Any]]:
    return [graph.trust_path_report(node.id).to_dict() for node in graph.find_by_type(NodeType.BINARY_RPM)]

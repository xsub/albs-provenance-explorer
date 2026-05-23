from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from albs_graph.model import ProvenanceGraph


@dataclass(frozen=True)
class DependencyCoverageSummary:
    dependency_nodes: int
    ecosystems: dict[str, int]
    scopes: dict[str, int]
    resolution_states: dict[str, int]
    context_aware_nodes: int


def summarize_dependency_coverage(graph: ProvenanceGraph) -> DependencyCoverageSummary:
    dependency_nodes = [
        node for node in graph.nodes.values() if isinstance(node.metadata.get("dependency"), dict)
    ]
    ecosystems = Counter(str(node.metadata.get("ecosystem", "unknown")) for node in dependency_nodes)
    scopes = Counter(str(node.metadata.get("scope", "unknown")) for node in dependency_nodes)
    states = Counter(
        str(node.metadata.get("resolution_state", "unknown")) for node in dependency_nodes
    )
    context_aware = sum(
        1 for node in dependency_nodes if node.metadata["dependency"].get("context")
    )
    return DependencyCoverageSummary(
        dependency_nodes=len(dependency_nodes),
        ecosystems=dict(ecosystems),
        scopes=dict(scopes),
        resolution_states=dict(states),
        context_aware_nodes=context_aware,
    )

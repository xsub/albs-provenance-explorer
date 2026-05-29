from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from albs_graph.model import ProvenanceGraph
from albs_graph.services import EdgeSummary, GraphQueries, NodeSummary


@dataclass(frozen=True)
class InspectorEdge:
    direction: str
    relation: str
    other_id: str
    other_label: str
    index: int


@dataclass(frozen=True)
class InspectorView:
    summary: list[tuple[str, str]]
    metadata: list[tuple[str, str]]
    incoming: list[InspectorEdge]
    outgoing: list[InspectorEdge]
    raw: dict[str, Any]


def inspector_view(graph: ProvenanceGraph, node_id: str) -> InspectorView:
    queries = GraphQueries(graph)
    node = queries.node_summary(node_id)
    incoming = queries.incoming(node_id)
    outgoing = queries.outgoing(node_id)
    return InspectorView(
        summary=_summary_rows(node),
        metadata=_metadata_rows(node.metadata),
        incoming=[_incoming_edge(edge) for edge in incoming],
        outgoing=[_outgoing_edge(edge) for edge in outgoing],
        raw={
            "node": node.to_dict(),
            "incoming": [edge.to_dict() for edge in incoming],
            "outgoing": [edge.to_dict() for edge in outgoing],
        },
    )


def edge_inspector_view(graph: ProvenanceGraph, edge_index: int) -> InspectorView:
    edge = GraphQueries(graph).edge_summary(edge_index)
    return InspectorView(
        summary=[
            ("Type", "edge"),
            ("Index", str(edge.index)),
            ("Relation", edge.relation),
            ("Source", edge.source),
            ("Source label", edge.source_label),
            ("Target", edge.target),
            ("Target label", edge.target_label),
        ],
        metadata=_metadata_rows(edge.metadata),
        incoming=[],
        outgoing=[],
        raw={"edge": edge.to_dict()},
    )


def raw_json(view: InspectorView) -> str:
    return json.dumps(view.raw, indent=2, sort_keys=True)


def _summary_rows(node: NodeSummary) -> list[tuple[str, str]]:
    rows = [
        ("Type", node.type),
        ("Label", node.label),
        ("Node id", node.id),
        ("Incoming edges", str(node.incoming)),
        ("Outgoing edges", str(node.outgoing)),
    ]
    for key in (
        "name",
        "version",
        "release",
        "arch",
        "build_arch",
        "artifact_id",
        "filename",
        "href",
        "purl",
        "cpe",
        "cas_hash",
    ):
        value = node.metadata.get(key)
        if value not in (None, "", [], {}):
            rows.append((key, _display(value)))
    return rows


def _metadata_rows(metadata: dict[str, Any]) -> list[tuple[str, str]]:
    return [(key, _display(value)) for key, value in sorted(metadata.items())]


def _incoming_edge(edge: EdgeSummary) -> InspectorEdge:
    return InspectorEdge(
        direction="incoming",
        relation=edge.relation,
        other_id=edge.source,
        other_label=edge.source_label,
        index=edge.index,
    )


def _outgoing_edge(edge: EdgeSummary) -> InspectorEdge:
    return InspectorEdge(
        direction="outgoing",
        relation=edge.relation,
        other_id=edge.target,
        other_label=edge.target_label,
        index=edge.index,
    )


def _display(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    return str(value)

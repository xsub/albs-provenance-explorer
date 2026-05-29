from __future__ import annotations

from albs_graph.fixtures import SYNTHETIC_RPM_ID, build_synthetic_fixture_graph
from albs_graph.gui.inspect import edge_inspector_view, inspector_view, raw_json


def test_inspector_view_splits_summary_metadata_edges_and_raw() -> None:
    graph = build_synthetic_fixture_graph()

    view = inspector_view(graph, SYNTHETIC_RPM_ID)

    assert ("Type", "binary_rpm") in view.summary
    assert ("arch", "x86_64") in view.metadata
    assert any(edge.relation == "produces" for edge in view.incoming)
    assert any(edge.relation == "signed_as" for edge in view.outgoing)
    assert view.raw["node"]["id"] == SYNTHETIC_RPM_ID


def test_inspector_raw_json_is_pretty_and_stable() -> None:
    graph = build_synthetic_fixture_graph()

    text = raw_json(inspector_view(graph, SYNTHETIC_RPM_ID))

    assert text.startswith("{\n")
    assert '"incoming"' in text
    assert SYNTHETIC_RPM_ID in text


def test_edge_inspector_view_treats_edge_as_first_class_selection() -> None:
    graph = build_synthetic_fixture_graph()

    view = edge_inspector_view(graph, 0)

    assert ("Type", "edge") in view.summary
    assert ("Index", "0") in view.summary
    assert view.raw["edge"]["index"] == 0

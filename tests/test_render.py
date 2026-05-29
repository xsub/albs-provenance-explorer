from albs_graph.fixtures import build_synthetic_fixture_graph
from albs_graph.render.dot import graph_to_dot
from albs_graph.render.json_export import graph_to_json


def test_dot_output_is_human_readable() -> None:
    dot = graph_to_dot(build_synthetic_fixture_graph())

    assert dot.startswith("digraph albs_provenance")
    assert "authenticated_by" in dot
    assert "released_to" in dot
    assert "synthetic-core-1.0.0-1.el9.x86_64.rpm" in dot


def test_json_export_contains_schema() -> None:
    exported = graph_to_json(build_synthetic_fixture_graph())

    assert '"schema": "albs-provenance-explorer/v1"' in exported

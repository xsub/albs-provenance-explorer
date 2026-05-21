from albs_graph.mock_data import build_mock_openssl_graph
from albs_graph.render.dot import graph_to_dot
from albs_graph.render.json_export import graph_to_json


def test_dot_output_is_human_readable() -> None:
    dot = graph_to_dot(build_mock_openssl_graph())

    assert dot.startswith("digraph albs_provenance")
    assert "notarized_as" in dot
    assert "released_to" in dot
    assert "openssl-libs-3.0.7-28.el9_4.x86_64.rpm" in dot


def test_json_export_contains_schema() -> None:
    exported = graph_to_json(build_mock_openssl_graph())

    assert '"schema": "albs-provenance-explorer/v1"' in exported

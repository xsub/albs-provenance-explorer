from albs_graph.graph import ProvenanceGraph
from albs_graph.model import Node, NodeType, Relation


def test_add_node_and_edge() -> None:
    graph = ProvenanceGraph()
    graph.add_node(Node("a", NodeType.SOURCE_PACKAGE, "a"))
    graph.add_node(Node("b", NodeType.GIT_REPOSITORY, "b"))
    graph.add_edge("a", "b", Relation.STORED_IN)

    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert graph.edges[0].relation == Relation.STORED_IN


def test_missing_edge_source_raises() -> None:
    graph = ProvenanceGraph()
    graph.add_node(Node("b", NodeType.GIT_REPOSITORY, "b"))

    try:
        graph.add_edge("a", "b", Relation.STORED_IN)
    except ValueError as exc:
        assert "Missing source node" in str(exc)
    else:
        raise AssertionError("Expected ValueError")

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


def test_find_by_type_is_insertion_ordered_and_idempotent() -> None:
    graph = ProvenanceGraph()
    graph.add_node(Node("r1", NodeType.BINARY_RPM, "r1"))
    graph.add_node(Node("s", NodeType.SOURCE_PACKAGE, "s"))
    graph.add_node(Node("r2", NodeType.BINARY_RPM, "r2"))
    # Re-adding an equal node must not duplicate it in the type index.
    graph.add_node(Node("r1", NodeType.BINARY_RPM, "r1"))

    rpms = graph.find_by_type(NodeType.BINARY_RPM)
    assert [node.id for node in rpms] == ["r1", "r2"]  # insertion order, no dup
    assert [node.id for node in graph.find_by_type(NodeType.SOURCE_PACKAGE)] == ["s"]
    assert graph.find_by_type(NodeType.SIGNATURE) == []  # unseen type -> empty


def test_find_by_type_returns_a_fresh_list() -> None:
    graph = ProvenanceGraph()
    graph.add_node(Node("r1", NodeType.BINARY_RPM, "r1"))
    result = graph.find_by_type(NodeType.BINARY_RPM)
    result.append(Node("bogus", NodeType.BINARY_RPM, "bogus"))
    # Mutating the returned list must not leak into the graph's index.
    assert [node.id for node in graph.find_by_type(NodeType.BINARY_RPM)] == ["r1"]


def test_outgoing_incoming_use_insertion_order_and_relation_filter() -> None:
    graph = ProvenanceGraph()
    for nid in ("a", "b", "c"):
        graph.add_node(Node(nid, NodeType.BINARY_RPM, nid))
    graph.add_edge("a", "b", Relation.REQUIRES_RUNTIME)
    graph.add_edge("a", "c", Relation.PROVIDES)
    graph.add_edge("b", "a", Relation.REQUIRES_RUNTIME)

    out = graph.outgoing("a")
    assert [(e.target, e.relation) for e in out] == [
        ("b", Relation.REQUIRES_RUNTIME),
        ("c", Relation.PROVIDES),
    ]
    assert [e.target for e in graph.outgoing("a", Relation.PROVIDES)] == ["c"]
    assert [e.source for e in graph.incoming("a")] == ["b"]
    # Fresh copies: mutating a result does not corrupt the index.
    graph.outgoing("a").clear()
    assert len(graph.outgoing("a")) == 2


def test_reachable_follows_outgoing_edges() -> None:
    graph = ProvenanceGraph()
    for nid in ("s", "c", "r", "x"):
        graph.add_node(Node(nid, NodeType.BINARY_RPM, nid))
    graph.add_edge("s", "c", Relation.PRODUCES)
    graph.add_edge("c", "r", Relation.PRODUCES)
    # x is only reachable backwards, so it must not appear from s.
    graph.add_edge("x", "s", Relation.PRODUCES)

    assert graph.reachable("s") == {"s", "c", "r"}

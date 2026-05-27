from albs_graph.adapters.dnf import enrich_graph_with_dnf
from albs_graph.model import (
    EdgeSpec,
    EvidencePatch,
    Node,
    NodeType,
    ProvenanceGraph,
    RecordingGraph,
    Relation,
    capture_patch,
)

SUBJECT = "rpm:app:x86_64"


def _graph_with_subject() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(Node(SUBJECT, NodeType.BINARY_RPM, "app", {"name": "app", "arch": "x86_64"}))
    return graph


def test_recording_graph_applies_writes_and_records_them() -> None:
    graph = _graph_with_subject()
    recorder = RecordingGraph(graph)
    recorder.add_node(Node("dep", NodeType.DEPENDENCY_CLAIM, "dep", {"name": "dep"}))
    recorder.add_edge(SUBJECT, "dep", Relation.DECLARES_DEPENDENCY, evidence="x")
    recorder.update_metadata(SUBJECT, {"rpm_license": "MIT"})
    recorder.warn("heads up")

    # Writes land on the underlying graph (shared state)...
    assert "dep" in graph.nodes
    assert graph.nodes[SUBJECT].metadata["rpm_license"] == "MIT"
    assert [e.target for e in graph.outgoing(SUBJECT)] == ["dep"]

    # ...and are recorded into the patch.
    patch = recorder.patch
    assert [n.id for n in patch.nodes] == ["dep"]
    assert patch.edges == [EdgeSpec(SUBJECT, "dep", Relation.DECLARES_DEPENDENCY, {"evidence": "x"})]
    assert patch.metadata_updates == [(SUBJECT, {"rpm_license": "MIT"})]
    assert patch.warnings == ["heads up"]
    assert patch.summary() == {"nodes": 1, "edges": 1, "metadata_updates": 1, "warnings": 1}


def test_capture_patch_dry_run_leaves_the_original_untouched() -> None:
    graph = _graph_with_subject()

    def mutate(target: ProvenanceGraph) -> None:
        target.add_node(Node("dep", NodeType.DEPENDENCY_CLAIM, "dep"))
        target.add_edge(SUBJECT, "dep", Relation.DECLARES_DEPENDENCY)
        target.update_metadata(SUBJECT, {"touched": True})

    patch = capture_patch(graph, mutate, apply=False)

    # The dry run touched only a throwaway copy.
    assert "dep" not in graph.nodes
    assert "touched" not in graph.nodes[SUBJECT].metadata
    # The patch is the record of what *would* change.
    assert [n.id for n in patch.nodes] == ["dep"]
    assert patch.metadata_updates == [(SUBJECT, {"touched": True})]

    # Replaying the patch reproduces the change on the real graph.
    patch.apply(graph)
    assert "dep" in graph.nodes
    assert graph.nodes[SUBJECT].metadata["touched"] is True


def test_capture_patch_apply_mutates_and_records() -> None:
    graph = _graph_with_subject()
    patch = capture_patch(
        graph, lambda target: target.add_node(Node("dep", NodeType.DEPENDENCY_CLAIM, "dep"))
    )
    assert "dep" in graph.nodes  # applied live
    assert [n.id for n in patch.nodes] == ["dep"]  # and recorded


def test_evidence_patch_merge_and_is_empty_do_not_mutate_operands() -> None:
    assert EvidencePatch().is_empty
    left = EvidencePatch(nodes=[Node("a", NodeType.BINARY_RPM, "a")])
    right = EvidencePatch(warnings=["w"])
    merged = left.merge(right)

    assert [n.id for n in merged.nodes] == ["a"]
    assert merged.warnings == ["w"]
    assert left.warnings == [] and right.nodes == []  # operands untouched
    assert not merged.is_empty


def test_update_metadata_rejects_unknown_node() -> None:
    graph = ProvenanceGraph()
    try:
        graph.update_metadata("missing", {"x": 1})
    except ValueError as exc:
        assert "Unknown node" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_recording_graph_captures_a_real_adapter_dry_run() -> None:
    # The point of the recorder: get an adapter's full patch without mutating the
    # graph. The dnf adapter adds a resolved claim (node + edge) and records its
    # relations as a metadata update -- all must show up in the patch.
    def runner(args: list[str]) -> tuple[int, str]:
        if "--requires" in args and "--resolve" in args:
            return 0, "glibc-2.34-100.el10_2.x86_64\n"
        if "--conflicts" in args:
            return 0, "nginx < 1:1.20\n"
        return 0, ""

    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:nginx-core:x86_64",
            NodeType.BINARY_RPM,
            "nginx-core-1.26.3-6.el10_2.x86_64.rpm",
            {"name": "nginx-core", "arch": "x86_64"},
        )
    )
    before = set(graph.nodes)

    patch = capture_patch(
        graph, lambda target: enrich_graph_with_dnf(target, runner=runner), apply=False
    )

    assert set(graph.nodes) == before  # dry run: original untouched
    assert any(node.metadata.get("name") == "glibc" for node in patch.nodes)
    assert any(
        node_id == "rpm:nginx-core:x86_64" and "dnf_relations" in updates
        for node_id, updates in patch.metadata_updates
    )
    # Replaying it reproduces the glibc claim on the real graph.
    patch.apply(graph)
    assert any(
        node.metadata.get("name") == "glibc"
        for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM)
    )

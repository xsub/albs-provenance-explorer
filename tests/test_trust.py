import json
from typing import Any
from pathlib import Path

from albs_graph.fixtures import build_synthetic_fixture_graph
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.provenance.lineage import artifacts_from_source, cves_for_artifact
from albs_graph.provenance.trust import (
    find_binary_rpm,
    focused_trust_graph,
    select_default_binary_rpm,
    source_build_subgraph,
    trust_path,
)


def test_trust_path_resolves_package_name() -> None:
    graph = build_synthetic_fixture_graph()

    report = trust_path(graph, "synthetic-core")

    assert report["complete"] is True
    assert report["provenance_complete"] is True
    assert report["security_context_complete"] is True
    assert report["path"][0] == "src:synthetic"
    assert report["path"][-1] == "rpm:synthetic-core:1.0.0-1.el9:x86_64"


def test_lineage_queries_include_artifacts_and_cves() -> None:
    graph = build_synthetic_fixture_graph()

    assert "rpm:synthetic-core:1.0.0-1.el9:x86_64" in artifacts_from_source(graph, "synthetic")
    assert cves_for_artifact(graph, "rpm:synthetic-core:1.0.0-1.el9:x86_64") == [
        "cve:CVE-2026-0001"
    ]


def test_focused_trust_graph_for_live_build_artifact_is_small() -> None:
    data = json.loads(
        Path("examples/live-build-17812/build-17812.json").read_text(encoding="utf-8")
    )
    graph = _graph_from_export(data)
    rpm = find_binary_rpm(graph, "nginx-core", arch="x86_64")

    focused = focused_trust_graph(graph, rpm.id)
    focused_ids = set(focused.nodes)

    assert rpm.id in focused_ids
    assert "src:nginx" in focused_ids
    assert "git:https://git.almalinux.org/rpms/nginx.git" in focused_ids
    assert "repo-release:ALBS release 7396" in focused_ids
    assert "sig:albs:11754" in focused_ids
    assert "cas:source:nginx:911945c71710c83cf6f760447c32d8d6cae737dc" in focused_ids
    assert any(
        node.type == "cas_attestation" and node.metadata.get("subject_type") == "rpm_artifact"
        for node in focused.nodes.values()
    )
    assert len(focused.nodes) < 20


def _two_source_batch_graph() -> ProvenanceGraph:
    # Reproduces a multi-source batch: a build-level aggregate for the
    # representative source A reaches *every* task (A -> ... -> build:B -> all
    # tasks), alongside correct per-task source chains for A and Z.
    graph = ProvenanceGraph()

    def add(
        node_id: str, node_type: NodeType, meta: dict[str, object] | None = None, label: str = ""
    ) -> None:
        graph.add_node(Node(node_id, node_type, label or node_id, meta or {}))

    add("src:A", NodeType.SOURCE_PACKAGE, label="A")
    add("repo:A", NodeType.GIT_REPOSITORY)
    add("commit:A", NodeType.GIT_COMMIT)
    add("cas:A:src", NodeType.CAS_ATTESTATION, {"cas_hash": "a-src"})
    add("build:B", NodeType.BUILD_TASK)
    graph.add_edge("src:A", "repo:A", Relation.STORED_IN)
    graph.add_edge("repo:A", "commit:A", Relation.POINTS_TO)
    graph.add_edge("commit:A", "cas:A:src", Relation.AUTHENTICATED_BY)
    graph.add_edge("cas:A:src", "build:B", Relation.BUILT_BY)  # aggregate over-reach edge

    add("src:Z", NodeType.SOURCE_PACKAGE, label="Z")
    add("repo:Z", NodeType.GIT_REPOSITORY)
    add("commit:Z", NodeType.GIT_COMMIT)
    graph.add_edge("src:Z", "repo:Z", Relation.STORED_IN)
    graph.add_edge("repo:Z", "commit:Z", Relation.POINTS_TO)

    for src in ("A", "Z"):
        add(f"cas:{src}:task", NodeType.CAS_ATTESTATION, {"cas_hash": f"{src.lower()}-task"})
        add(f"task:{src}", NodeType.BUILD_TASK)
        add(f"rpm:{src}1", NodeType.BINARY_RPM, {"name": f"{src.lower()}-core", "arch": "x86_64"})
        graph.add_edge(f"commit:{src}", f"cas:{src}:task", Relation.AUTHENTICATED_BY)
        graph.add_edge(f"cas:{src}:task", f"task:{src}", Relation.BUILT_BY)
        graph.add_edge("build:B", f"task:{src}", Relation.DERIVED_FROM)  # build -> every task
        graph.add_edge(f"task:{src}", f"rpm:{src}1", Relation.PRODUCES)
    return graph


def test_artifacts_from_source_scopes_to_per_task_in_a_batch() -> None:
    # The old reachability-based attribution returned both rpm:A1 and rpm:Z1 for
    # source A (it is the batch's representative, reaching every task via the
    # aggregate build). Per-task attribution scopes each artifact to its source.
    graph = _two_source_batch_graph()

    assert artifacts_from_source(graph, "A") == ["rpm:A1"]
    assert artifacts_from_source(graph, "Z") == ["rpm:Z1"]


def test_source_build_subgraph_unions_a_sources_rpms() -> None:
    # A middle zoom: the nginx source fans out to all its x86_64 RPMs over one
    # shared backbone - lighter than the full build, heavier than one RPM's path.
    data = json.loads(
        Path("examples/live-build-17812/build-17812.json").read_text(encoding="utf-8")
    )
    graph = _graph_from_export(data)

    whole = source_build_subgraph(graph, "nginx", arch="x86_64")
    rpm_names = {
        node.metadata.get("name")
        for node in whole.nodes.values()
        if str(node.type) == "binary_rpm"
    }

    assert "src:nginx" in set(whole.nodes)  # shared backbone present once
    assert {"nginx-core", "nginx"} <= rpm_names  # multiple subpackages, not just one
    assert len(rpm_names) >= 3
    one = focused_trust_graph(graph, find_binary_rpm(graph, "nginx-core", arch="x86_64").id)
    assert len(one.nodes) < len(whole.nodes) < len(graph.nodes)


def test_default_binary_rpm_selection_comes_from_graph_metadata() -> None:
    data = json.loads(
        Path("examples/live-build-17812/build-17812.json").read_text(encoding="utf-8")
    )
    graph = _graph_from_export(data)

    rpm = select_default_binary_rpm(graph)

    assert rpm.metadata["name"] == "nginx"
    assert rpm.metadata["arch"] == "x86_64"
    assert rpm.id == "rpm:3237133:nginx-1.20.1-16.el9_4.1.x86_64.rpm"


def test_default_binary_rpm_selection_respects_requested_arch() -> None:
    data = json.loads(
        Path("examples/live-build-17812/build-17812.json").read_text(encoding="utf-8")
    )
    graph = _graph_from_export(data)

    rpm = select_default_binary_rpm(graph, arch="s390x")

    assert rpm.metadata["name"] == "nginx"
    assert rpm.metadata["arch"] == "s390x"
    assert rpm.id == "rpm:3237057:nginx-1.20.1-16.el9_4.1.s390x.rpm"


def _graph_from_export(data: dict[str, Any]) -> ProvenanceGraph:
    graph = ProvenanceGraph()
    for node in data["nodes"]:
        graph.add_node(Node(node["id"], node["type"], node["label"], node["metadata"]))
    for edge in data["edges"]:
        graph.add_edge(edge["source"], edge["target"], edge["relation"], **edge["metadata"])
    return graph

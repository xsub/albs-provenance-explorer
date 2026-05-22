import json
from typing import Any
from pathlib import Path

from albs_graph.mock_data import build_mock_openssl_graph
from albs_graph.model import Node, ProvenanceGraph
from albs_graph.provenance.lineage import artifacts_from_source, cves_for_artifact
from albs_graph.provenance.trust import find_binary_rpm, focused_trust_graph, trust_path


def test_trust_path_resolves_package_name() -> None:
    graph = build_mock_openssl_graph()

    report = trust_path(graph, "openssl-libs")

    assert report["complete"] is True
    assert report["path"][0] == "src:openssl"
    assert report["path"][-1] == "rpm:openssl-libs:3.0.7-28.el9_4:x86_64"


def test_lineage_queries_include_artifacts_and_cves() -> None:
    graph = build_mock_openssl_graph()

    assert "rpm:openssl-libs:3.0.7-28.el9_4:x86_64" in artifacts_from_source(graph, "openssl")
    assert cves_for_artifact(graph, "rpm:openssl-libs:3.0.7-28.el9_4:x86_64") == [
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


def _graph_from_export(data: dict[str, Any]) -> ProvenanceGraph:
    graph = ProvenanceGraph()
    for node in data["nodes"]:
        graph.add_node(Node(node["id"], node["type"], node["label"], node["metadata"]))
    for edge in data["edges"]:
        graph.add_edge(edge["source"], edge["target"], edge["relation"], **edge["metadata"])
    return graph

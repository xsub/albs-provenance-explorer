from albs_graph.fixtures import build_synthetic_fixture_graph


def test_synthetic_fixture_graph_has_complete_trust_path() -> None:
    graph = build_synthetic_fixture_graph()
    report = graph.trust_report_for_rpm("rpm:synthetic-core:1.0.0-1.el9:x86_64")

    assert report["complete"] is True
    assert report["provenance_complete"] is True
    assert report["security_context_complete"] is True
    assert report["checks"]["has_build_task"] is True
    assert report["checks"]["has_signature"] is True
    assert report["checks"]["has_release"] is True
    assert report["checks"]["has_sbom"] is True
    assert report["checks"]["has_errata_link"] is True
    assert report["checks"]["has_source_cas_attestation"] is True
    assert report["checks"]["has_artifact_cas_attestation"] is True


def test_synthetic_fixture_graph_contains_expected_nodes() -> None:
    graph = build_synthetic_fixture_graph()

    assert "src:synthetic" in graph.nodes
    assert "repo:git.almalinux.org/rpms/synthetic" in graph.nodes
    assert "cas:source:synthetic:xyz789" in graph.nodes
    assert "build:albs:123456" in graph.nodes


def test_synthetic_cas_fixture_is_evidence_not_external_verification() -> None:
    graph = build_synthetic_fixture_graph()
    cas_node = graph.nodes["cas:source:synthetic:xyz789"]

    assert cas_node.metadata["evidence_present"] is True
    assert cas_node.metadata["externally_verified"] is False
    assert "trusted" not in cas_node.metadata

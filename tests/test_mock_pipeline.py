from albs_graph.mock_data import build_mock_openssl_graph


def test_mock_openssl_graph_has_complete_trust_path() -> None:
    graph = build_mock_openssl_graph()
    report = graph.trust_report_for_rpm("rpm:openssl-libs:3.0.7-28.el9_4:x86_64")

    assert report["complete"] is True
    assert report["checks"]["has_build_task"] is True
    assert report["checks"]["has_signature"] is True
    assert report["checks"]["has_release"] is True
    assert report["checks"]["has_sbom"] is True
    assert report["checks"]["has_errata_link"] is True
    assert report["checks"]["has_notarized_source_ref"] is True


def test_mock_openssl_graph_contains_expected_nodes() -> None:
    graph = build_mock_openssl_graph()

    assert "src:openssl" in graph.nodes
    assert "repo:git.almalinux.org/rpms/openssl" in graph.nodes
    assert "notary:immudb:openssl:xyz789" in graph.nodes
    assert "build:albs:123456" in graph.nodes

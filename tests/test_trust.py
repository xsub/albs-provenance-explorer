from albs_graph.mock_data import build_mock_openssl_graph
from albs_graph.provenance.lineage import artifacts_from_source, cves_for_artifact
from albs_graph.provenance.trust import trust_path


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

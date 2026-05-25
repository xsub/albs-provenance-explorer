from albs_graph.fixtures import SYNTHETIC_RPM_ID, build_synthetic_fixture_graph
from albs_graph.provenance import slsa_provenance


def test_slsa_statement_shape_and_content() -> None:
    graph = build_synthetic_fixture_graph()
    statement = slsa_provenance(graph, SYNTHETIC_RPM_ID)

    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"

    subject = statement["subject"][0]
    assert subject["name"] == "synthetic-core-1.0.0-1.el9.x86_64.rpm"
    assert subject["digest"]["sha256"] == "synthetic-core-x86_64-cas"

    predicate = statement["predicate"]
    resolved = predicate["buildDefinition"]["resolvedDependencies"][0]
    assert resolved["uri"].startswith("git+git.almalinux.org/rpms/synthetic")
    assert resolved["digest"]["gitCommit"] == "abc123"
    assert predicate["buildDefinition"]["externalParameters"]["package"] == "synthetic-core"
    assert predicate["runDetails"]["builder"]["id"] == "https://build.almalinux.org"


def test_slsa_surfaces_signature_verification() -> None:
    graph = build_synthetic_fixture_graph()
    graph.nodes[SYNTHETIC_RPM_ID].metadata["signature_verified"] = True

    statement = slsa_provenance(graph, SYNTHETIC_RPM_ID)
    assert statement["predicate"]["runDetails"]["metadata"]["signatureVerified"] is True

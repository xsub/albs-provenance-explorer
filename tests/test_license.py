from albs_graph.adapters.sbom import cyclonedx_dependency_claims
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance import RpmLicenseRollup, add_dependency_claim, license_report

SUBJECT = "rpm:app:x86_64"

_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [
        {
            "type": "library",
            "name": "zlib",
            "version": "1.2.11",
            "purl": "pkg:rpm/almalinux/zlib@1.2.11-40.el9?arch=x86_64",
            "licenses": [{"license": {"id": "Zlib"}}],
        },
        {
            "type": "library",
            "name": "openssl-libs",
            "version": "3.0.7",
            "purl": "pkg:rpm/almalinux/openssl-libs@3.0.7-27.el9?arch=x86_64",
            "licenses": [{"expression": "Apache-2.0"}],
        },
        {
            "type": "library",
            "name": "mystery",
            "version": "1.0",
            "purl": "pkg:rpm/almalinux/mystery@1.0?arch=x86_64",
        },
    ],
}


def _graph_with_sbom() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(Node(SUBJECT, NodeType.BINARY_RPM, "app", {"name": "app"}))
    for claim in cyclonedx_dependency_claims(SUBJECT, _CYCLONEDX):
        add_dependency_claim(graph, claim)
    return graph


def test_license_rollup_counts_and_unlicensed() -> None:
    report = license_report(_graph_with_sbom())

    assert report.components == 3
    assert report.licenses == {"Apache-2.0": 1, "Zlib": 1}
    assert report.distinct_licenses == 2
    assert report.unlicensed == ["mystery"]


def test_license_report_to_dict() -> None:
    data = license_report(_graph_with_sbom()).to_dict()
    assert data["components"] == 3
    assert data["licenses"]["Zlib"] == 1
    assert data["unlicensed"] == ["mystery"]


def test_rpm_license_rollup_counts_and_unknowns() -> None:
    # Real licenses from RPM headers + dnf, with one package whose license could
    # not be determined (kept honest as "unknown", never guessed).
    rollup = RpmLicenseRollup(
        packages={
            "nginx-core": "BSD-2-Clause",
            "openssl-libs": "Apache-2.0",
            "glibc": "LGPL-2.1-or-later",
            "libxcrypt": "LGPL-2.1-or-later",
            "mystery": "",
        }
    )
    assert rollup.components == 5
    assert rollup.licenses == {
        "Apache-2.0": 1,
        "BSD-2-Clause": 1,
        "LGPL-2.1-or-later": 2,
    }
    assert rollup.distinct_licenses == 3
    assert rollup.unlicensed == ["mystery"]
    data = rollup.to_dict()
    assert data["components"] == 5
    assert data["licenses"]["LGPL-2.1-or-later"] == 2
    assert data["unlicensed"] == ["mystery"]
    assert data["packages"]["nginx-core"] == "BSD-2-Clause"

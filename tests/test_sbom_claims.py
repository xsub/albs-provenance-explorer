import json
from pathlib import Path
from typing import Any

from albs_graph.adapters.sbom import attach_cyclonedx_sbom_claims, cyclonedx_dependency_claims
from albs_graph.dependency import (
    DependencySpec,
    Ecosystem,
    Linkage,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.provenance import (
    Agreement,
    ConflictKind,
    DependencyClaim,
    add_dependency_claim,
    coverage_report,
    reconcile_dependency_claims,
)

SUBJECT = "rpm:nginx-core:1.20.1-16.el9_4.1:x86_64"

_CYCLONEDX: dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "serialNumber": "urn:uuid:test-sbom-1",
    "metadata": {
        "component": {
            "name": "nginx-core",
            "version": "1.20.1-16.el9_4.1",
            "purl": "pkg:rpm/almalinux/nginx-core@1.20.1-16.el9_4.1?arch=x86_64",
        }
    },
    "components": [
        {
            "type": "library",
            "name": "zlib",
            "version": "1.2.11",
            "purl": "pkg:rpm/almalinux/zlib@1.2.11-40.el9?arch=x86_64",
            "scope": "required",
        },
        {
            "type": "library",
            "name": "openssl-libs",
            "version": "3.0.7",
            "purl": "pkg:rpm/almalinux/openssl-libs@3.0.7-28.el9?arch=x86_64",
        },
    ],
}


def _subject_graph() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(Node(SUBJECT, NodeType.BINARY_RPM, "nginx-core", {"name": "nginx-core"}))
    return graph


def _write_sbom(tmp_path: Path) -> Path:
    path = tmp_path / "nginx-core.cdx.json"
    path.write_text(json.dumps(_CYCLONEDX), encoding="utf-8")
    return path


def test_cyclonedx_components_become_versioned_claims() -> None:
    claims = cyclonedx_dependency_claims(SUBJECT, _CYCLONEDX)

    assert {claim.spec.identity.name for claim in claims} == {"zlib", "openssl-libs"}
    assert all(claim.evidence == "sbom" for claim in claims)
    # The PURL version (release included) wins over the bare component version.
    versions = {claim.spec.identity.name: claim.asserted_version for claim in claims}
    assert versions["zlib"] == "1.2.11-40.el9"
    assert versions["openssl-libs"] == "3.0.7-28.el9"


def test_attach_sbom_adds_evidence_node_and_claims(tmp_path: Path) -> None:
    graph = _subject_graph()
    result = attach_cyclonedx_sbom_claims(graph, SUBJECT, _write_sbom(tmp_path))

    assert result.components == 2
    assert result.claims_added == 2
    sbom_nodes = graph.find_by_type(NodeType.SBOM)
    assert len(sbom_nodes) == 1
    assert any(
        edge.relation == Relation.DESCRIBED_BY and edge.target == sbom_nodes[0].id
        for edge in graph.outgoing(SUBJECT)
    )
    assert len(graph.find_by_type(NodeType.DEPENDENCY_CLAIM)) == 2


def test_sbom_claims_raise_resolution_coverage(tmp_path: Path) -> None:
    graph = _subject_graph()
    attach_cyclonedx_sbom_claims(graph, SUBJECT, _write_sbom(tmp_path))
    reconcile_dependency_claims(graph)

    report = coverage_report(graph)
    # Two concrete component versions, each single-source -> COMPATIBLE -> resolved.
    assert report.resolution.covered == 2
    assert report.resolution.total == 2


def test_sbom_version_drifts_against_lockfile() -> None:
    graph = _subject_graph()
    for claim in cyclonedx_dependency_claims(SUBJECT, _CYCLONEDX):
        add_dependency_claim(graph, claim)
    # A lockfile pins zlib differently than the SBOM observed in the build.
    add_dependency_claim(
        graph,
        DependencyClaim(
            subject_id=SUBJECT,
            spec=DependencySpec(
                identity=PackageIdentity(Ecosystem.RPM, "zlib", namespace="almalinux", version="1.2.13"),
                resolution_state=ResolutionState.LOCKED,
            ),
            evidence="lockfile",
        ),
    )

    report = reconcile_dependency_claims(graph)

    zlib_conflicts = [c for c in report.conflicts if "zlib" in c.coordinate]
    assert len(zlib_conflicts) == 1
    assert zlib_conflicts[0].kind == ConflictKind.VERSION_DRIFT
    assert set(zlib_conflicts[0].versions) == {"1.2.11-40.el9", "1.2.13"}


def test_header_soname_not_flagged_undeclared_when_sbom_present() -> None:
    graph = _subject_graph()
    for claim in cyclonedx_dependency_claims(SUBJECT, _CYCLONEDX):
        add_dependency_claim(graph, claim)
    # A dynamic soname from the RPM header lives in a different coordinate space
    # than the SBOM's packages; it must not be reported as a presence conflict.
    add_dependency_claim(
        graph,
        DependencyClaim(
            subject_id=SUBJECT,
            spec=DependencySpec(
                identity=PackageIdentity(Ecosystem.RPM, "libz.so.1"),
                linkage=Linkage.DYNAMIC,
                resolution_state=ResolutionState.OBSERVED,
            ),
            evidence="rpm_header_soname",
        ),
    )

    report = reconcile_dependency_claims(graph)

    assert not any(c.kind == ConflictKind.PRESENCE_UNDECLARED for c in report.conflicts)
    soname_resolution = next(
        node
        for node in graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION)
        if "libz.so.1" in str(node.metadata.get("coordinate", ""))
    )
    assert soname_resolution.metadata["agreement"] == str(Agreement.INSUFFICIENT_EVIDENCE)

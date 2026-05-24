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
    reconcile_dependency_claims,
)

SUBJECT = "rpm:app:1.0:x86_64"


def _graph_with_subject() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(Node(SUBJECT, NodeType.BINARY_RPM, "app", {"name": "app", "arch": "x86_64"}))
    return graph


def _claim(
    name: str,
    version: str | None,
    evidence: str,
    *,
    state: ResolutionState = ResolutionState.DECLARED,
    linkage: Linkage = Linkage.UNKNOWN,
) -> DependencyClaim:
    spec = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, name, version=version),
        resolution_state=state,
        linkage=linkage,
    )
    return DependencyClaim(subject_id=SUBJECT, spec=spec, evidence=evidence)


def _resolution_for(graph: ProvenanceGraph, name: str) -> Node:
    matches = [
        node
        for node in graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION)
        if name in str(node.metadata.get("coordinate", ""))
    ]
    assert len(matches) == 1
    return matches[0]


def test_two_sources_agreeing_yield_consensus() -> None:
    graph = _graph_with_subject()
    add_dependency_claim(graph, _claim("openssl", "3.0.7", "lockfile", state=ResolutionState.LOCKED))
    add_dependency_claim(
        graph, _claim("openssl", "3.0.7", "resolver:uv", state=ResolutionState.RESOLVED)
    )

    report = reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "openssl")

    assert resolution.metadata["agreement"] == str(Agreement.CONSENSUS)
    assert resolution.metadata["chosen_version"] == "3.0.7"
    assert report.conflict_count == 0
    # The agreeing claims are linked as corroboration, not collapsed.
    assert any(edge.relation == Relation.CORROBORATES for edge in graph.edges)


def test_version_drift_is_a_first_class_conflict() -> None:
    graph = _graph_with_subject()
    add_dependency_claim(graph, _claim("zlib", "1.2.13", "lockfile", state=ResolutionState.LOCKED))
    add_dependency_claim(
        graph, _claim("zlib", "1.3.1", "elf_dt_needed", state=ResolutionState.OBSERVED)
    )

    report = reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "zlib")

    assert resolution.metadata["agreement"] == str(Agreement.CONFLICT)
    assert str(ConflictKind.VERSION_DRIFT) in resolution.metadata["conflict_kinds"]
    assert report.conflict_count == 1
    assert report.conflicts[0].kind == ConflictKind.VERSION_DRIFT
    assert set(report.conflicts[0].versions) == {"1.2.13", "1.3.1"}
    assert any(
        edge.relation == Relation.CONFLICTS_WITH
        and edge.metadata.get("kind") == str(ConflictKind.VERSION_DRIFT)
        for edge in graph.edges
    )


def test_artifact_only_dependency_is_flagged_undeclared() -> None:
    graph = _graph_with_subject()
    # The subject has declaration evidence (a manifest dep), so a thing present
    # only in the built artifact (vendored/static) is a genuine presence gap.
    add_dependency_claim(graph, _claim("declared-dep", "1.0", "manifest"))
    add_dependency_claim(
        graph, _claim("vendored-lib", "9.9", "static_bom", state=ResolutionState.OBSERVED)
    )

    report = reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "vendored-lib")

    assert resolution.metadata["agreement"] == str(Agreement.CONFLICT)
    assert str(ConflictKind.PRESENCE_UNDECLARED) in resolution.metadata["conflict_kinds"]
    assert any(c.kind == ConflictKind.PRESENCE_UNDECLARED for c in report.conflicts)


def test_artifact_only_without_declarations_is_not_a_conflict() -> None:
    graph = _graph_with_subject()
    # Header-only ingest: a soname observed from the RPM header with no manifest
    # or resolver evidence anywhere is unreconciled, not a presence conflict.
    add_dependency_claim(
        graph, _claim("libssl.so.3", None, "rpm_header_soname", state=ResolutionState.OBSERVED)
    )

    report = reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "libssl.so.3")

    assert resolution.metadata["agreement"] == str(Agreement.INSUFFICIENT_EVIDENCE)
    assert report.conflict_count == 0


def test_linkage_mismatch_detected_even_when_versions_agree() -> None:
    graph = _graph_with_subject()
    add_dependency_claim(
        graph,
        _claim("crypto", "1.0", "manifest", state=ResolutionState.DECLARED, linkage=Linkage.DYNAMIC),
    )
    add_dependency_claim(
        graph,
        _claim("crypto", "1.0", "static_bom", state=ResolutionState.OBSERVED, linkage=Linkage.STATIC),
    )

    reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "crypto")

    assert resolution.metadata["agreement"] == str(Agreement.CONFLICT)
    assert str(ConflictKind.LINKAGE_MISMATCH) in resolution.metadata["conflict_kinds"]


def test_range_only_claim_is_insufficient_evidence() -> None:
    graph = _graph_with_subject()
    add_dependency_claim(graph, _claim("requests", None, "manifest"))

    reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "requests")

    assert resolution.metadata["agreement"] == str(Agreement.INSUFFICIENT_EVIDENCE)
    assert resolution.metadata["chosen_version"] is None


def test_resolver_asserted_range_violation_surfaces_as_conflict() -> None:
    graph = _graph_with_subject()
    # AlmaLinux backport case: shipped version sits outside the upstream range,
    # but is patched. The resolver asserts the violation; the reconciler records it.
    spec = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, "openssl", version="3.0.7"),
        resolution_state=ResolutionState.RESOLVED,
    )
    add_dependency_claim(
        graph,
        DependencyClaim(
            subject_id=SUBJECT, spec=spec, evidence="resolver:libsolv", range_satisfied=False
        ),
    )

    reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "openssl")

    assert resolution.metadata["agreement"] == str(Agreement.CONFLICT)
    assert str(ConflictKind.RANGE_VIOLATION) in resolution.metadata["conflict_kinds"]

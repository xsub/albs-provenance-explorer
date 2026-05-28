from albs_graph.dependency import (
    DependencyContext,
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
    ContextIssue,
    DependencyClaim,
    add_dependency_claim,
    coverage_report,
    reconcile_dependency_claims,
    resolution_details,
)

SUBJECT = "rpm:app:1.0:x86_64"


def _graph_with_subject() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(Node(SUBJECT, NodeType.BINARY_RPM, "app", {"name": "app", "arch": "x86_64"}))
    return graph


def _graph_with_subject_release(release: str) -> ProvenanceGraph:
    """A subject whose release carries a dist tag, e.g. ``16.el9_4.1`` (el9) or el10."""

    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            SUBJECT,
            NodeType.BINARY_RPM,
            "app",
            {"name": "app", "arch": "x86_64", "version": "1.0", "release": release},
        )
    )
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


def test_semantically_equal_versions_do_not_drift() -> None:
    graph = _graph_with_subject()
    # "1.01" and "1.1" are the same version under rpmvercmp -> not drift.
    add_dependency_claim(graph, _claim("zlib", "1.01", "lockfile", state=ResolutionState.LOCKED))
    add_dependency_claim(graph, _claim("zlib", "1.1", "resolver:dnf", state=ResolutionState.RESOLVED))

    report = reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "zlib")

    assert report.conflict_count == 0
    assert resolution.metadata["agreement"] == str(Agreement.CONSENSUS)
    # The claim-pair edge must agree with the verdict: corroborate, not conflict.
    assert any(edge.relation == Relation.CORROBORATES for edge in graph.edges)
    assert not any(edge.relation == Relation.CONFLICTS_WITH for edge in graph.edges)


def test_semantic_drift_still_detected() -> None:
    graph = _graph_with_subject()
    add_dependency_claim(graph, _claim("zlib", "1.2.11", "lockfile", state=ResolutionState.LOCKED))
    add_dependency_claim(
        graph, _claim("zlib", "1.2.3", "elf_dt_needed", state=ResolutionState.OBSERVED)
    )

    report = reconcile_dependency_claims(graph)

    assert any(conflict.kind == ConflictKind.VERSION_DRIFT for conflict in report.conflicts)


def test_declared_range_violation_fires_on_concrete_version() -> None:
    graph = _graph_with_subject()
    # A manifest requires >= 3.2, but the resolved version is 3.0.7 (backport case).
    declared = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, "openssl-libs"),
        requested="openssl-libs >= 3.2",
        resolution_state=ResolutionState.DECLARED,
    )
    add_dependency_claim(graph, DependencyClaim(SUBJECT, declared, evidence="manifest"))
    add_dependency_claim(
        graph, _claim("openssl-libs", "3.0.7-1.el9", "resolver:dnf", state=ResolutionState.RESOLVED)
    )

    reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "openssl-libs")
    assert resolution.metadata["agreement"] == str(Agreement.CONFLICT)
    assert str(ConflictKind.RANGE_VIOLATION) in resolution.metadata["conflict_kinds"]


def test_satisfied_declared_range_is_no_conflict() -> None:
    graph = _graph_with_subject()
    declared = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, "openssl-libs"),
        requested="openssl-libs >= 3.0",
        resolution_state=ResolutionState.DECLARED,
    )
    add_dependency_claim(graph, DependencyClaim(SUBJECT, declared, evidence="manifest"))
    add_dependency_claim(
        graph, _claim("openssl-libs", "3.0.7-1.el9", "resolver:dnf", state=ResolutionState.RESOLVED)
    )

    report = reconcile_dependency_claims(graph)
    assert not any(conflict.kind == ConflictKind.RANGE_VIOLATION for conflict in report.conflicts)


def test_resolution_details_list_each_group_for_verbose_output() -> None:
    graph = _graph_with_subject()
    add_dependency_claim(graph, _claim("openssl", "3.0.7", "lockfile", state=ResolutionState.LOCKED))
    add_dependency_claim(
        graph, _claim("openssl", "3.0.7", "resolver:uv", state=ResolutionState.RESOLVED)
    )
    add_dependency_claim(
        graph, _claim("libssl.so.3", None, "rpm_header_soname", state=ResolutionState.OBSERVED)
    )
    reconcile_dependency_claims(graph)

    details = resolution_details(graph)

    # One detail row per reconciled group, carrying verdict + evidence sources.
    assert len(details) == 2
    assert any("libssl.so.3" in d.coordinate for d in details)
    openssl = next(d for d in details if "openssl" in d.coordinate)
    assert openssl.agreement == str(Agreement.CONSENSUS)
    assert openssl.versions == ("3.0.7",)
    assert set(openssl.evidence) == {"lockfile", "resolver:uv"}
    # Sorted deterministically (by subject, then coordinate) for stable output.
    assert details == sorted(details, key=lambda d: (d.subject_id, d.coordinate))


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


def test_cross_distro_is_a_context_issue_not_a_weaker_agreement() -> None:
    # An el9 build whose deps resolved against el10 host repos: both sources
    # agree on the el10 glibc, so the agreement is honest CONSENSUS. But that is
    # the host's package, not the el9 build's dep -- an orthogonal CROSS_DISTRO
    # context issue, not a downgraded verdict.
    graph = _graph_with_subject_release("16.el9_4.1")
    add_dependency_claim(
        graph, _claim("glibc", "2.39-121.el10_2", "resolver:dnf", state=ResolutionState.RESOLVED)
    )
    add_dependency_claim(
        graph,
        _claim("glibc", "2.39-121.el10_2", "soname_provider", state=ResolutionState.PROVIDED),
    )

    report = reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "glibc")

    # Agreement is unchanged -- the sources do agree on a version.
    assert resolution.metadata["agreement"] == str(Agreement.CONSENSUS)
    # The build-context problem is recorded on a separate axis.
    assert resolution.metadata["context_issue"] == str(ContextIssue.CROSS_DISTRO)
    assert resolution.metadata["distro_mismatch"] is True
    assert resolution.metadata["subject_distro"] == "el9"
    assert resolution.metadata["dependency_distros"] == ["el10"]
    # It is neither a cross-source conflict nor an agreement verdict of its own.
    assert report.conflict_count == 0
    assert report.agreements.get(str(Agreement.CONSENSUS)) == 1
    assert report.cross_distro_count == 1


def test_cross_distro_resolution_excluded_from_coverage() -> None:
    # Coverage policy: a CONSENSUS carrying a context issue is not "resolved for
    # this build", so an el9-build-on-el10-host honestly reports deps unresolved.
    graph = _graph_with_subject_release("16.el9_4.1")
    add_dependency_claim(
        graph, _claim("glibc", "2.39-121.el10_2", "resolver:dnf", state=ResolutionState.RESOLVED)
    )
    add_dependency_claim(
        graph,
        _claim("glibc", "2.39-121.el10_2", "soname_provider", state=ResolutionState.PROVIDED),
    )
    reconcile_dependency_claims(graph)

    report = coverage_report(graph)

    assert report.resolution.total == 1
    assert report.resolution.covered == 0  # context issue excludes the consensus
    assert report.resolution.fraction == 0.0


def test_same_distro_consensus_has_no_context_issue() -> None:
    # el10 build, el10 deps: the host matches the build, so consensus counts.
    graph = _graph_with_subject_release("16.el10_2.1")
    add_dependency_claim(
        graph, _claim("glibc", "2.39-121.el10_2", "resolver:dnf", state=ResolutionState.RESOLVED)
    )
    add_dependency_claim(
        graph,
        _claim("glibc", "2.39-121.el10_2", "soname_provider", state=ResolutionState.PROVIDED),
    )

    report = reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "glibc")

    assert resolution.metadata["agreement"] == str(Agreement.CONSENSUS)
    assert resolution.metadata["context_issue"] is None
    assert resolution.metadata["distro_mismatch"] is False
    assert report.cross_distro_count == 0
    assert coverage_report(graph).resolution.covered == 1


def test_distro_minor_difference_is_not_a_context_issue() -> None:
    # el9_2 build, el9_4 dep: same generation (el9), only the minor differs.
    # That is normal within a release, so it must not be flagged cross-distro.
    graph = _graph_with_subject_release("16.el9_2.1")
    add_dependency_claim(
        graph, _claim("glibc", "2.34-100.el9_4.2", "resolver:dnf", state=ResolutionState.RESOLVED)
    )
    add_dependency_claim(
        graph,
        _claim("glibc", "2.34-100.el9_4.2", "soname_provider", state=ResolutionState.PROVIDED),
    )

    report = reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "glibc")

    assert resolution.metadata["agreement"] == str(Agreement.CONSENSUS)
    assert resolution.metadata["context_issue"] is None
    assert report.cross_distro_count == 0


def test_identity_mismatch_when_sources_agree_on_version_but_not_purl() -> None:
    # Two resolved claims agree zlib is 1.2.11 (so not version drift) but assert
    # different PURL coordinates -- a genuine identity disagreement, not consensus.
    graph = _graph_with_subject()
    for arch, evidence in (("x86_64", "sbom"), ("aarch64", "resolver:dnf")):
        spec = DependencySpec(
            identity=PackageIdentity(
                Ecosystem.RPM, "zlib", version="1.2.11",
                purl=f"pkg:rpm/almalinux/zlib@1.2.11?arch={arch}",
            ),
            resolution_state=ResolutionState.RESOLVED,
        )
        add_dependency_claim(graph, DependencyClaim(SUBJECT, spec, evidence=evidence))

    report = reconcile_dependency_claims(graph)
    resolution = _resolution_for(graph, "zlib")

    assert resolution.metadata["agreement"] == str(Agreement.CONFLICT)
    assert str(ConflictKind.IDENTITY_MISMATCH) in resolution.metadata["conflict_kinds"]
    assert any(c.kind == ConflictKind.IDENTITY_MISMATCH for c in report.conflicts)


def test_reconcile_is_idempotent_no_duplicate_edges_or_resolution_nodes() -> None:
    # Regression: running reconcile_dependency_claims() twice used to duplicate
    # OBSERVED_AS / CORROBORATES edges and raise "Conflicting node definition
    # for dep-res:..." on a second run. The idempotent purge-and-rebuild keeps
    # edge + resolution-node counts stable across repeated runs.
    graph = _graph_with_subject()
    add_dependency_claim(graph, _claim("openssl", "3.0.7", "lockfile", state=ResolutionState.LOCKED))
    add_dependency_claim(
        graph, _claim("openssl", "3.0.7", "resolver:uv", state=ResolutionState.RESOLVED)
    )

    reconcile_dependency_claims(graph)
    edges_after_first = len(graph.edges)
    resolutions_after_first = len(graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION))

    # Second run on the same graph -- no exception, no growth.
    reconcile_dependency_claims(graph)

    assert len(graph.edges) == edges_after_first
    assert len(graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION)) == resolutions_after_first


def test_reconcile_after_new_evidence_reflects_the_updated_verdict() -> None:
    # The realistic re-enrich case: reconcile -> persist -> reload -> attach
    # new evidence -> reconcile again. The new verdict must replace the old,
    # not collide with it. Here a CONSENSUS flips to VERSION_DRIFT after a
    # conflicting claim is added.
    graph = _graph_with_subject()
    add_dependency_claim(graph, _claim("zlib", "1.2.11", "lockfile", state=ResolutionState.LOCKED))
    add_dependency_claim(
        graph, _claim("zlib", "1.2.11", "resolver:dnf", state=ResolutionState.RESOLVED)
    )

    first = reconcile_dependency_claims(graph)
    assert _resolution_for(graph, "zlib").metadata["agreement"] == str(Agreement.CONSENSUS)
    assert first.conflict_count == 0

    # New evidence arrives -- different version observed in the wild.
    add_dependency_claim(
        graph, _claim("zlib", "1.2.13", "elf_dt_needed", state=ResolutionState.OBSERVED)
    )

    second = reconcile_dependency_claims(graph)  # must not raise

    resolution = _resolution_for(graph, "zlib")
    assert resolution.metadata["agreement"] == str(Agreement.CONFLICT)
    assert str(ConflictKind.VERSION_DRIFT) in resolution.metadata["conflict_kinds"]
    assert second.conflict_count == 1


def test_claim_node_id_distinguishes_by_resolver_context_and_purl() -> None:
    # Regression: two claims for the same subject/name/version/evidence but
    # different arch/profile/distro context (or different PURL qualifiers) used
    # to collide on add (the same claim_node_id), even though group_key already
    # treated them as separate groups. Now the id keys on context + PURL too.
    graph = _graph_with_subject()

    spec_x = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, "glibc", version="2.39"),
        context=DependencyContext(arch="x86_64"),
        resolution_state=ResolutionState.RESOLVED,
    )
    spec_a = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, "glibc", version="2.39"),
        context=DependencyContext(arch="aarch64"),
        resolution_state=ResolutionState.RESOLVED,
    )

    # Both adds must succeed -- no "Conflicting node definition for claim:...".
    id_x = add_dependency_claim(graph, DependencyClaim(SUBJECT, spec_x, evidence="resolver:dnf"))
    id_a = add_dependency_claim(graph, DependencyClaim(SUBJECT, spec_a, evidence="resolver:dnf"))

    assert id_x != id_a
    # And the reconciler keeps them as two independent groups (context-keyed).
    reconcile_dependency_claims(graph)
    glibc_groups = [
        node
        for node in graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION)
        if "glibc" in str(node.metadata.get("coordinate", ""))
    ]
    assert len(glibc_groups) == 2  # one per arch context

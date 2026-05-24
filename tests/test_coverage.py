from albs_graph.dependency import (
    DependencySpec,
    Ecosystem,
    Linkage,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.fixtures import SYNTHETIC_RPM_ID, build_synthetic_fixture_graph
from albs_graph.provenance import (
    DependencyClaim,
    add_dependency_claim,
    coverage_report,
    reconcile_dependency_claims,
)


def test_synthetic_fixture_reports_honest_residue() -> None:
    report = coverage_report(build_synthetic_fixture_graph())
    axes = report.to_dict()

    # Provenance + security context are fully wired in the fixture.
    assert axes["provenance"]["fraction"] == 1.0
    assert axes["security_context"]["fraction"] == 1.0
    # The axes nothing has fed yet honestly report zero, not a false pass.
    assert axes["identity"]["fraction"] == 0.0  # no verified CPE
    assert axes["linkage"]["covered"] == 0  # no linkage facts on the runtime edge
    assert report.resolution.total == 0  # nothing resolved or even claimed


def test_feeding_resolved_claims_raises_resolution_and_linkage() -> None:
    graph = build_synthetic_fixture_graph()

    def _resolved_claim(evidence: str) -> DependencyClaim:
        spec = DependencySpec(
            identity=PackageIdentity(Ecosystem.RPM, "openssl", version="3.0.7"),
            resolution_state=ResolutionState.RESOLVED,
            linkage=Linkage.DYNAMIC,
        )
        return DependencyClaim(subject_id=SYNTHETIC_RPM_ID, spec=spec, evidence=evidence)

    add_dependency_claim(graph, _resolved_claim("resolver:libsolv"))
    add_dependency_claim(graph, _resolved_claim("rpm_header_soname"))
    reconcile_dependency_claims(graph)

    report = coverage_report(graph)

    assert report.resolution.total == 1
    assert report.resolution.fraction == 1.0  # consensus verdict counts as resolved
    assert report.linkage.covered == 1  # dynamic linkage now recorded on the subject
    # Provenance/security context are unchanged by dependency evidence.
    assert report.provenance.fraction == 1.0

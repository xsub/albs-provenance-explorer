from __future__ import annotations

from dataclasses import dataclass

from albs_graph.adapters.rpmgraph import RpmgraphUnavailable
from albs_graph.dependency import DependencySpec, Ecosystem, PackageIdentity
from albs_graph.fixtures import SYNTHETIC_RPM_ID, build_synthetic_fixture_graph
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.pipeline import AnalysisPipeline, EnrichmentContext, RunSpec
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim
from albs_graph.services import (
    AnalysisService,
    GraphQueries,
    GraphSlices,
    findings_for_analysis,
)


@dataclass(frozen=True)
class _FakeStep:
    name: str = "fake"

    def applies(self, spec: RunSpec) -> bool:
        return spec.use_dnf

    def run(self, ctx: EnrichmentContext) -> object:
        ctx.graph.add_node(Node("dep:fake", NodeType.DEPENDENCY_CLAIM, "fake"))
        return {"ok": True}


def _tiny_graph() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(
        Node("rpm:app:x86_64", NodeType.BINARY_RPM, "app", {"name": "app", "arch": "x86_64"})
    )
    return graph


def test_analysis_service_wraps_pipeline_and_reports_coverage() -> None:
    service = AnalysisService(pipeline=AnalysisPipeline(steps=(_FakeStep(),)))

    result = service.analyze_graph(_tiny_graph(), RunSpec(use_dnf=True))

    assert result.result("fake") == {"ok": True}
    assert "dep:fake" in result.graph.nodes
    assert result.reconciliation.conflict_count == 0
    assert result.coverage.provenance.total == 1


def test_analysis_service_reports_repograph_warning_without_failing() -> None:
    def unavailable(_repo: str | None) -> str:
        raise RpmgraphUnavailable("dnf is missing")

    service = AnalysisService(
        pipeline=AnalysisPipeline(steps=()),
        repograph_runner=unavailable,
    )

    result = service.analyze_graph(_tiny_graph(), RunSpec(), repograph="baseos")

    assert [warning.kind for warning in result.warnings] == ["repograph_unavailable"]
    assert "dnf is missing" in result.warnings[0].message


def test_graph_queries_summarize_and_search_nodes() -> None:
    graph = build_synthetic_fixture_graph()
    queries = GraphQueries(graph)

    summary = queries.node_summary(SYNTHETIC_RPM_ID)
    matches = queries.find_nodes("synthetic-core")
    outgoing = queries.outgoing(SYNTHETIC_RPM_ID, Relation.SIGNED_AS)

    assert summary.type == "binary_rpm"
    assert summary.outgoing > 0
    assert any(match.id == SYNTHETIC_RPM_ID for match in matches)
    assert outgoing[0].target == "sig:gpg:alma9"


def test_graph_slices_return_focused_trust_and_security_views() -> None:
    graph = build_synthetic_fixture_graph()
    slices = GraphSlices(graph)

    trust = slices.trust_path("synthetic-core", arch="x86_64")
    security = slices.security_context(SYNTHETIC_RPM_ID)

    assert trust.name == "trust_path"
    assert trust.focus == SYNTHETIC_RPM_ID
    assert "build:albs:123456" in trust.graph.nodes
    assert "cve:CVE-2026-0001" in security.graph.nodes


def test_dependency_evidence_slice_includes_claims_and_resolutions() -> None:
    graph = _tiny_graph()
    claim = DependencyClaim(
        "rpm:app:x86_64",
        DependencySpec(PackageIdentity(Ecosystem.RPM, "zlib", version="1")),
        "sbom",
    )
    add_dependency_claim(graph, claim)
    result = AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze_graph(graph, RunSpec())

    evidence = GraphSlices(result.graph).dependency_evidence("rpm:app:x86_64")

    assert evidence.metadata["claims"] == 1
    assert any(node_id.startswith("claim:") for node_id in evidence.graph.nodes)
    assert any(node_id.startswith("dep-res:") for node_id in evidence.graph.nodes)


def test_findings_cover_incomplete_axes_and_conflicts() -> None:
    result = AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze_graph(_tiny_graph(), RunSpec())

    findings = findings_for_analysis(result.graph, result.coverage, result.reconciliation)

    assert any(finding.code == "coverage.provenance" for finding in findings)
    assert any(finding.code == "trust.has_build_task" for finding in findings)

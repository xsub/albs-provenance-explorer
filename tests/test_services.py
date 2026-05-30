from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from albs_graph.adapters.rpmgraph import RpmgraphUnavailable
from albs_graph.dependency import DependencySpec, Ecosystem, PackageIdentity
from albs_graph.fixtures import SYNTHETIC_RPM_ID, build_synthetic_fixture_graph
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.pipeline import AnalysisPipeline, EnrichmentContext, RunSpec
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim
from albs_graph.services import (
    AnalysisService,
    GraphLoadSpec,
    WorkbenchSession,
    compare_builds,
    compare_artifacts,
    coverage_rows,
    evidence_matrix_rows,
    evidence_bundle,
    evidence_report_html,
    filter_graph_layers,
    finding_drilldown_rows,
    GraphQueries,
    GraphSlices,
    findings_for_analysis,
    run_graph_query,
    source_evidence_rows,
    investigation_recipes,
    timeline_gantt_rows,
    timeline_rows,
    timeline_tree,
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


def test_analysis_service_attaches_build_analysis_from_source_metadata() -> None:
    service = AnalysisService(pipeline=AnalysisPipeline(steps=()))

    result = service.analyze(
        GraphLoadSpec(source=Path("examples/live-build-17812/build-17812.albs.json")),
        RunSpec(),
    )

    assert result.build_analysis is not None
    assert result.build_analysis.build_id == "17812"
    assert result.build_analysis.task_timings[0].wall_seconds is not None


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


def test_graph_slices_can_focus_selected_node_neighborhood() -> None:
    graph = build_synthetic_fixture_graph()

    neighborhood = GraphSlices(graph).node_neighborhood(SYNTHETIC_RPM_ID)

    assert neighborhood.name == "node_neighborhood"
    assert neighborhood.focus == SYNTHETIC_RPM_ID
    assert SYNTHETIC_RPM_ID in neighborhood.graph.nodes
    assert len(neighborhood.graph.nodes) < len(graph.nodes)


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


def test_workbench_views_summarize_coverage_timeline_and_recipes() -> None:
    result = AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze_graph(
        build_synthetic_fixture_graph(), RunSpec()
    )
    findings = findings_for_analysis(result.graph, result.coverage, result.reconciliation)

    coverage = coverage_rows(result.coverage)
    timeline = timeline_rows(result.graph)
    recipes = investigation_recipes(result.graph, result.coverage, findings)

    assert any(row.axis == "provenance" for row in coverage)
    assert any(row.kind == "build_task" for row in timeline)
    assert any(recipe.mode == "Node Neighborhood" for recipe in recipes)


def test_workbench_timeline_tree_uses_build_analysis_steps() -> None:
    result = AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze(
        GraphLoadSpec(source=Path("examples/live-build-17812/build-17812.albs.json")),
        RunSpec(),
    )

    tree = timeline_tree(result.graph, result.build_analysis)
    x86_task = next(item for item in tree if item.label == "ALBS task 188077 x86_64")

    assert x86_task.duration_seconds == 398.212342
    assert any(child.label == "build_node_stats.build_binaries" for child in x86_task.children)
    assert any(child.kind == "artifacts" for child in x86_task.children)


def test_workbench_gantt_rows_preserve_timing_offsets() -> None:
    result = AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze(
        GraphLoadSpec(source=Path("examples/live-build-17812/build-17812.albs.json")),
        RunSpec(),
    )

    rows = timeline_gantt_rows(result.graph, result.build_analysis)
    x86_task = next(row for row in rows if row.label == "ALBS task 188077 x86_64")

    assert x86_task.offset_seconds >= 0
    assert x86_task.duration_seconds == 398.212342
    assert any(row.depth == 1 and row.kind == "build_step" for row in rows)


def test_workbench_evidence_matrix_reports_per_artifact_completeness() -> None:
    rows = evidence_matrix_rows(build_synthetic_fixture_graph())
    row = next(item for item in rows if item.node_id == SYNTHETIC_RPM_ID)

    assert row.provenance == "complete"
    assert row.security_context == "complete"
    assert row.signature == "ok"
    assert row.sbom == "ok"
    assert "has_sbom" not in row.missing
    assert row.completeness > 0.75


def test_workbench_layer_filter_hides_disabled_security_context() -> None:
    graph = build_synthetic_fixture_graph()

    filtered = filter_graph_layers(graph, {"build"}, always_nodes={SYNTHETIC_RPM_ID})

    assert SYNTHETIC_RPM_ID in filtered.nodes
    assert not filtered.find_by_type(NodeType.SBOM)
    assert not filtered.find_by_type(NodeType.CVE)
    assert list(filter_graph_layers(graph, set(), always_nodes={SYNTHETIC_RPM_ID}).nodes) == [
        SYNTHETIC_RPM_ID
    ]


def test_compare_builds_reports_artifact_and_evidence_changes() -> None:
    left = build_synthetic_fixture_graph()
    right = build_synthetic_fixture_graph()
    right.remove_edges_where(
        lambda edge: edge.source == SYNTHETIC_RPM_ID and edge.relation == Relation.DESCRIBED_BY
    )
    right.update_metadata(SYNTHETIC_RPM_ID, {"release": "2"})

    rows = compare_builds(left, right)

    assert any(row.area == "artifact" and row.change == "changed" for row in rows)
    assert any(row.area == "evidence" and "sbom" in row.detail for row in rows)


def test_workbench_source_evidence_summarizes_backbone_and_scanned_files() -> None:
    graph = build_synthetic_fixture_graph()
    graph.add_node(
        Node(
            "source-tree:synthetic",
            NodeType.SOURCE_TREE,
            "synthetic source tree",
            {"files": 2, "manifests": 1, "spec_files": 1, "dependency_specs": 1},
        )
    )
    graph.add_edge("src:synthetic", "source-tree:synthetic", Relation.DESCRIBED_BY)
    graph.add_node(
        Node("source-file:synthetic.spec", NodeType.SOURCE_FILE, "synthetic.spec", {"kind": "spec"})
    )
    graph.add_edge("source-tree:synthetic", "source-file:synthetic.spec", Relation.CONTAINS)
    graph.add_node(
        Node(
            "source-file:Cargo.toml",
            NodeType.SOURCE_MANIFEST,
            "Cargo.toml",
            {"kind": "manifest", "ecosystem": "cargo"},
        )
    )
    graph.add_edge("source-tree:synthetic", "source-file:Cargo.toml", Relation.CONTAINS)
    graph.add_node(
        Node(
            "dep:make",
            NodeType.DEPENDENCY_SPEC,
            "make",
            {"requested": "make", "scope": "buildtime", "resolution_state": "declared"},
        )
    )
    graph.add_edge("source-file:synthetic.spec", "dep:make", Relation.DECLARES_DEPENDENCY)

    rows = source_evidence_rows(graph, SYNTHETIC_RPM_ID)

    assert any(row.category == "git repository" for row in rows)
    assert any(row.category == "source tree" for row in rows)
    assert any(row.category == "manifest" and row.label == "Cargo.toml" for row in rows)
    assert any(row.category == "declared dependency" and row.label == "make" for row in rows)


def test_workbench_graph_query_presets_find_paths_and_gaps() -> None:
    graph = _tiny_graph()

    gaps = run_graph_query(graph, "missing_sbom")
    path = run_graph_query(build_synthetic_fixture_graph(), "source_to_artifact_path", subject_id=SYNTHETIC_RPM_ID)

    assert gaps[0].node_id == "rpm:app:x86_64"
    assert path[0].node_id == "src:synthetic"
    assert path[-1].node_id == SYNTHETIC_RPM_ID


def test_finding_drilldown_expands_artifact_checks() -> None:
    result = AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze_graph(_tiny_graph(), RunSpec())
    finding = next(
        item
        for item in findings_for_analysis(result.graph, result.coverage, result.reconciliation)
        if item.code.startswith("trust.")
    )

    rows = finding_drilldown_rows(result.graph, finding)

    assert rows[0].kind == "finding"
    assert any(row.kind == "check" and row.detail == "missing" for row in rows)


def test_workbench_session_round_trips_dict() -> None:
    session = WorkbenchSession(
        source="build.json",
        build_sbom="build.cyclonedx.json",
        mode="Node Neighborhood",
        selected_artifact_id=SYNTHETIC_RPM_ID,
        selected_node_id="build:albs:123456",
        selected_edge_index=2,
    )

    restored = WorkbenchSession.from_dict(session.to_dict())

    assert restored == session


def test_evidence_bundle_exports_current_slice_context() -> None:
    result = AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze_graph(
        build_synthetic_fixture_graph(), RunSpec()
    )
    graph_slice = GraphSlices(result.graph).trust_path(SYNTHETIC_RPM_ID)
    findings = findings_for_analysis(result.graph, result.coverage, result.reconciliation)

    bundle = evidence_bundle(
        graph=result.graph,
        graph_slice=graph_slice,
        coverage=result.coverage,
        findings=findings,
        selected_node_id=SYNTHETIC_RPM_ID,
        selected_edge_index=0,
        selected_edge_graph=graph_slice.graph,
        svg="<svg/>",
        session=WorkbenchSession(selected_node_id=SYNTHETIC_RPM_ID),
    )

    assert bundle["schema"].endswith("/v1")
    assert bundle["selected_node"]["node"]["id"] == SYNTHETIC_RPM_ID
    assert bundle["selected_edge"]["index"] == 0
    assert bundle["slice"]["name"] == "trust_path"
    assert bundle["svg"] == "<svg/>"


def test_evidence_report_html_renders_bundle_sections() -> None:
    bundle = {
        "session": {"source": "build.json"},
        "slice": {"name": "trust_path"},
        "coverage": [{"axis": "provenance", "covered": 1, "total": 1, "ratio": 1, "status": "complete"}],
        "findings": [{"severity": "info", "code": "trust.has_sbom", "subject": "rpm:1", "detail": ""}],
        "timeline": [],
        "selected_node": {"node": {"id": "rpm:1"}},
        "selected_edge": {"index": 0},
        "svg": "<svg></svg>",
    }

    html = evidence_report_html(bundle)

    assert "ALBS Provenance Investigation Report" in html
    assert "trust.has_sbom" in html
    assert "<svg></svg>" in html


def test_compare_artifacts_reports_added_removed_and_changed_artifacts() -> None:
    left = _tiny_graph()
    right = _tiny_graph()
    right.update_metadata("rpm:app:x86_64", {"version": "2"})
    left.add_node(Node("rpm:old:x86_64", NodeType.BINARY_RPM, "old", {"name": "old", "arch": "x86_64"}))
    right.add_node(Node("rpm:new:x86_64", NodeType.BINARY_RPM, "new", {"name": "new", "arch": "x86_64"}))

    deltas = compare_artifacts(left, right)

    assert {delta.change for delta in deltas} == {"added", "removed", "changed"}

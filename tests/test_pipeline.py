from dataclasses import dataclass
from pathlib import Path

from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.pipeline import (
    DEFAULT_STEPS,
    AnalysisPipeline,
    EnrichmentContext,
    RunSpec,
)


@dataclass(frozen=True)
class _FakeStep:
    name: str = "fake"

    def applies(self, spec: RunSpec) -> bool:
        return spec.use_dnf  # reuse an existing flag to gate the fake step

    def run(self, ctx: EnrichmentContext) -> object:
        ctx.log("fake step")
        ctx.graph.add_node(Node("dep:fake", NodeType.DEPENDENCY_CLAIM, "fake", {"name": "fake"}))
        return {"added": "dep:fake"}


def _graph() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(
        Node("rpm:app:x86_64", NodeType.BINARY_RPM, "app", {"name": "app", "arch": "x86_64"})
    )
    return graph


def test_pipeline_runs_applicable_steps_records_and_reconciles() -> None:
    logs: list[str] = []
    result = AnalysisPipeline(steps=(_FakeStep(),)).run(
        RunSpec(use_dnf=True), _graph(), on_progress=logs.append
    )

    assert result.result("fake") == {"added": "dep:fake"}
    assert "dep:fake" in result.graph.nodes  # applied to the graph
    assert result.patch is not None and any(n.id == "dep:fake" for n in result.patch.nodes)
    assert result.reconciliation.conflict_count == 0  # reconcile ran
    # The step logged its intent and the pipeline logged the reconcile.
    assert "fake step" in logs and "Reconciling dependency claims" in logs


def test_pipeline_skips_non_applicable_steps() -> None:
    result = AnalysisPipeline(steps=(_FakeStep(),)).run(RunSpec(use_dnf=False), _graph())
    assert result.result("fake") is None
    assert "dep:fake" not in result.graph.nodes


def test_pipeline_dry_run_leaves_the_source_graph_untouched() -> None:
    graph = _graph()
    result = AnalysisPipeline(steps=(_FakeStep(),)).run(RunSpec(use_dnf=True), graph, dry_run=True)

    assert "dep:fake" not in graph.nodes  # the original is untouched
    assert "dep:fake" in result.graph.nodes  # the throwaway copy got it
    assert result.patch is not None and any(n.id == "dep:fake" for n in result.patch.nodes)


def test_default_steps_are_the_enrichment_flow_in_order() -> None:
    assert [step.name for step in DEFAULT_STEPS] == [
        "build_sbom",
        "repograph",
        "dnf",
        "sbom",
        "python",
        "python_imports",
        "errata",
        "errata_source",
        "verify_cpe",
        "rpm_headers",
        "rpm_payloads",
        "soname",
        "cas",
        "signatures",
    ]


def test_default_steps_gate_on_their_spec_fields() -> None:
    by_name = {step.name: step for step in DEFAULT_STEPS}
    assert not any(step.applies(RunSpec()) for step in DEFAULT_STEPS)  # empty spec: nothing runs
    assert by_name["dnf"].applies(RunSpec(use_dnf=True))
    assert by_name["rpm_headers"].applies(RunSpec(with_rpm_headers=True))
    assert by_name["soname"].applies(RunSpec(resolve_sonames=True))
    assert by_name["build_sbom"].applies(RunSpec(build_sbom=Path("sbom.json")))
    assert by_name["errata_source"].applies(RunSpec(errata_source="dnf"))
    assert by_name["errata_source"].applies(RunSpec(errata_feed=Path("errata.json")))

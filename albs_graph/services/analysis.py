"""Shared analysis service for command-line and desktop callers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from albs_graph.adapters.albs import (
    AlbsBuildMetadata,
    graph_from_build_metadata,
    fetch_build_metadata,
    parse_build_metadata,
)
from albs_graph.adapters.rpmgraph import RpmgraphUnavailable, run_repograph
from albs_graph.model import ProvenanceGraph
from albs_graph.pipeline import AnalysisPipeline, PipelineResult, Progress, RunSpec
from albs_graph.provenance.build_analysis import BuildAnalysis, analyze_albs_build
from albs_graph.provenance.coverage import CoverageReport, coverage_report, identity_strength
from albs_graph.provenance.reconcile import ReconciliationReport

RepographRunner = Callable[[str | None], str]


@dataclass(frozen=True)
class GraphLoadSpec:
    """Where a graph comes from before analysis enrichment runs."""

    build_id: int | None = None
    source: Path | None = None
    base_url: str = "https://build.almalinux.org"
    cache: Path | None = None
    cache_ttl_seconds: int = 300
    refresh_cache: bool = False

    def validate(self) -> None:
        chosen = sum(value is not None for value in (self.build_id, self.source))
        if chosen != 1:
            raise ValueError("exactly one of build_id or source is required")


@dataclass(frozen=True)
class ServiceWarning:
    """Non-fatal service warning suitable for a CLI log or UI findings pane."""

    kind: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "message": self.message}


@dataclass
class AnalysisResult:
    """A completed enrichment run with the derived reports most callers need."""

    graph: ProvenanceGraph
    pipeline: PipelineResult
    coverage: CoverageReport
    identity_breakdown: dict[str, int] = field(default_factory=dict)
    warnings: list[ServiceWarning] = field(default_factory=list)
    build_analysis: BuildAnalysis | None = None

    @property
    def reconciliation(self) -> ReconciliationReport:
        return self.pipeline.reconciliation

    def result(self, name: str) -> Any | None:
        return self.pipeline.result(name)


class AnalysisService:
    """Backend facade used by CLI today and by the PyQt workbench later."""

    def __init__(
        self,
        *,
        pipeline: AnalysisPipeline | None = None,
        repograph_runner: RepographRunner | None = None,
    ) -> None:
        self.pipeline = pipeline or AnalysisPipeline()
        self.repograph_runner = repograph_runner or run_repograph

    def load_graph(self, spec: GraphLoadSpec, *, on_progress: Progress = None) -> ProvenanceGraph:
        """Load the base graph from ALBS metadata or a local fixture."""

        metadata = self._load_build_metadata(spec, on_progress=on_progress)
        return graph_from_build_metadata(metadata)

    def _load_build_metadata(
        self, spec: GraphLoadSpec, *, on_progress: Progress = None
    ) -> AlbsBuildMetadata:
        spec.validate()
        if spec.build_id is not None:
            return fetch_build_metadata(
                spec.build_id,
                base_url=spec.base_url,
                progress=on_progress,
                cache_path=spec.cache,
                refresh_cache=spec.refresh_cache,
                cache_ttl_seconds=spec.cache_ttl_seconds,
            )

        assert spec.source is not None
        if on_progress:
            on_progress(f"Loading ALBS build metadata from {spec.source}")
        return parse_build_metadata(json.loads(spec.source.read_text(encoding="utf-8")))

    def analyze(
        self,
        load_spec: GraphLoadSpec,
        run_spec: RunSpec,
        *,
        repograph_dot: Path | None = None,
        repograph: str | None = None,
        on_progress: Progress = None,
        dry_run: bool = False,
    ) -> AnalysisResult:
        """Load a graph, run enrichment, reconcile, and compute coverage."""

        metadata = self._load_build_metadata(load_spec, on_progress=on_progress)
        graph = graph_from_build_metadata(metadata)
        return self.analyze_graph(
            graph,
            run_spec,
            repograph_dot=repograph_dot,
            repograph=repograph,
            on_progress=on_progress,
            dry_run=dry_run,
            build_analysis=analyze_albs_build(metadata.raw),
        )

    def analyze_graph(
        self,
        graph: ProvenanceGraph,
        run_spec: RunSpec,
        *,
        repograph_dot: Path | None = None,
        repograph: str | None = None,
        on_progress: Progress = None,
        dry_run: bool = False,
        build_analysis: BuildAnalysis | None = None,
    ) -> AnalysisResult:
        """Run enrichment against an already loaded graph."""

        dot_text, warnings = self._resolve_repograph(
            repograph_dot=repograph_dot, repograph=repograph, on_progress=on_progress
        )
        if dot_text is not None:
            run_spec = replace(run_spec, repograph_dot_text=dot_text)

        pipeline_result = self.pipeline.run(
            run_spec, graph, on_progress=on_progress, dry_run=dry_run
        )
        enriched = pipeline_result.graph
        return AnalysisResult(
            graph=enriched,
            pipeline=pipeline_result,
            coverage=coverage_report(enriched),
            identity_breakdown=identity_strength(enriched),
            warnings=warnings,
            build_analysis=build_analysis,
        )

    def _resolve_repograph(
        self,
        *,
        repograph_dot: Path | None,
        repograph: str | None,
        on_progress: Progress,
    ) -> tuple[str | None, list[ServiceWarning]]:
        if repograph_dot is not None:
            if on_progress:
                on_progress(f"Ingesting dnf repograph/rpmgraph dot from {repograph_dot}")
            return repograph_dot.read_text(encoding="utf-8"), []
        if repograph is None:
            return None, []

        if on_progress:
            on_progress(f"Running dnf repograph {repograph}")
        try:
            return self.repograph_runner(repograph), []
        except RpmgraphUnavailable as exc:
            return None, [
                ServiceWarning(
                    kind="repograph_unavailable",
                    message=f"repograph unavailable: {exc}",
                )
            ]

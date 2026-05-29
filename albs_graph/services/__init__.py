"""App-facing service layer for CLI and future desktop frontends."""

from .analysis import AnalysisResult, AnalysisService, GraphLoadSpec, ServiceWarning
from .compare import ArtifactDelta, compare_artifacts
from .findings import Finding, findings_for_analysis
from .queries import EdgeSummary, GraphQueries, NodeSummary
from .slices import GraphSlice, GraphSlices
from .workbench import (
    CoverageRow,
    InvestigationRecipe,
    TimelineRow,
    WorkbenchSession,
    coverage_rows,
    evidence_report_html,
    evidence_bundle,
    investigation_recipes,
    timeline_rows,
)

__all__ = [
    "AnalysisResult",
    "AnalysisService",
    "ArtifactDelta",
    "CoverageRow",
    "EdgeSummary",
    "Finding",
    "GraphLoadSpec",
    "GraphQueries",
    "GraphSlice",
    "GraphSlices",
    "InvestigationRecipe",
    "NodeSummary",
    "ServiceWarning",
    "TimelineRow",
    "WorkbenchSession",
    "compare_artifacts",
    "coverage_rows",
    "evidence_bundle",
    "evidence_report_html",
    "findings_for_analysis",
    "investigation_recipes",
    "timeline_rows",
]

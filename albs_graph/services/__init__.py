"""App-facing service layer for CLI and future desktop frontends."""

from .analysis import AnalysisResult, AnalysisService, GraphLoadSpec, ServiceWarning
from .findings import Finding, findings_for_analysis
from .queries import EdgeSummary, GraphQueries, NodeSummary
from .slices import GraphSlice, GraphSlices

__all__ = [
    "AnalysisResult",
    "AnalysisService",
    "EdgeSummary",
    "Finding",
    "GraphLoadSpec",
    "GraphQueries",
    "GraphSlice",
    "GraphSlices",
    "NodeSummary",
    "ServiceWarning",
    "findings_for_analysis",
]

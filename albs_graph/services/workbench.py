from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from albs_graph.model import NodeType, ProvenanceGraph
from albs_graph.provenance.coverage import CoverageReport
from albs_graph.services.findings import Finding
from albs_graph.services.slices import GraphSlice


@dataclass(frozen=True)
class CoverageRow:
    axis: str
    covered: int
    total: int
    ratio: float
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "axis": self.axis,
            "covered": self.covered,
            "total": self.total,
            "ratio": self.ratio,
            "status": self.status,
        }


@dataclass(frozen=True)
class TimelineRow:
    kind: str
    label: str
    status: str
    node_id: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "node_id": self.node_id,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class InvestigationRecipe:
    code: str
    title: str
    mode: str
    detail: str
    subject: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "mode": self.mode,
            "detail": self.detail,
            "subject": self.subject,
        }


@dataclass(frozen=True)
class WorkbenchSession:
    source: str = ""
    build_id: str = ""
    mode: str = "Trust Path"
    include_tests: bool = False
    artifact_filter: str = ""
    selected_artifact_id: str | None = None
    selected_node_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "build_id": self.build_id,
            "mode": self.mode,
            "include_tests": self.include_tests,
            "artifact_filter": self.artifact_filter,
            "selected_artifact_id": self.selected_artifact_id,
            "selected_node_id": self.selected_node_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WorkbenchSession":
        return cls(
            source=str(data.get("source") or ""),
            build_id=str(data.get("build_id") or ""),
            mode=str(data.get("mode") or "Trust Path"),
            include_tests=bool(data.get("include_tests")),
            artifact_filter=str(data.get("artifact_filter") or ""),
            selected_artifact_id=_optional_text(data.get("selected_artifact_id")),
            selected_node_id=_optional_text(data.get("selected_node_id")),
        )

    @classmethod
    def load(cls, path: Path) -> "WorkbenchSession":
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def coverage_rows(report: CoverageReport) -> list[CoverageRow]:
    rows: list[CoverageRow] = []
    for axis in report.axes():
        ratio = axis.covered / axis.total if axis.total else 1.0
        rows.append(
            CoverageRow(
                axis=axis.name,
                covered=axis.covered,
                total=axis.total,
                ratio=ratio,
                status="complete" if ratio >= 1.0 else "incomplete",
            )
        )
    return rows


def timeline_rows(graph: ProvenanceGraph) -> list[TimelineRow]:
    rows: list[TimelineRow] = []
    for node in graph.find_by_type(NodeType.BUILD_TASK):
        produced = len(graph.outgoing(node.id))
        arch = node.metadata.get("arch") or node.metadata.get("build_arch") or "unknown"
        status = node.metadata.get("status")
        rows.append(
            TimelineRow(
                kind="build_task",
                label=node.label,
                status=str(status) if status is not None else "",
                node_id=node.id,
                detail=f"{arch}; {produced} outgoing edges",
            )
        )
    for node in graph.find_by_type(NodeType.SIGNATURE):
        status = node.metadata.get("status")
        task_id = node.metadata.get("task_id") or node.metadata.get("sign_task_id")
        rows.append(
            TimelineRow(
                kind="signature",
                label=node.label,
                status=str(status) if status is not None else "",
                node_id=node.id,
                detail=f"sign task {task_id}" if task_id else "signature evidence",
            )
        )
    return sorted(rows, key=lambda row: (row.kind, row.label, row.node_id))


def investigation_recipes(
    graph: ProvenanceGraph,
    coverage: CoverageReport,
    findings: list[Finding],
) -> list[InvestigationRecipe]:
    recipes = [
        InvestigationRecipe(
            "trust_path",
            "Why is this RPM trusted?",
            "Trust Path",
            "Follow source, build, signature, release, CAS and security evidence.",
        ),
        InvestigationRecipe(
            "node_neighborhood",
            "What surrounds the selected node?",
            "Node Neighborhood",
            "Show one-hop incoming and outgoing evidence around the selected object.",
        ),
        InvestigationRecipe(
            "security_context",
            "What security context is attached?",
            "Security Context",
            "Inspect SBOM, errata, CVE and identity evidence for the selected artifact.",
        ),
        InvestigationRecipe(
            "dependency_evidence",
            "Which dependency evidence exists?",
            "Dependency Evidence",
            "Inspect declared, resolved and observed dependency claims for the selected artifact.",
        ),
    ]
    first_subject = next((finding.subject for finding in findings if finding.subject), None)
    if first_subject is not None:
        recipes.append(
            InvestigationRecipe(
                "first_finding",
                "Jump to first concrete finding",
                "Trust Path",
                "Open the artifact or node attached to the highest listed finding.",
                first_subject,
            )
        )
    if any(row.total and row.covered < row.total for row in coverage.axes()):
        recipes.append(
            InvestigationRecipe(
                "coverage_gaps",
                "Show coverage gaps",
                "Trust Path",
                "Use the coverage dashboard and findings table to prioritize incomplete axes.",
            )
        )
    if graph.find_by_type(NodeType.BUILD_TASK):
        recipes.append(
            InvestigationRecipe(
                "build_timeline",
                "Review build timeline",
                "Trust Path",
                "Use the timeline tab to move across build tasks and signing evidence.",
            )
        )
    return recipes


def evidence_bundle(
    *,
    graph: ProvenanceGraph,
    graph_slice: GraphSlice | None,
    coverage: CoverageReport,
    findings: list[Finding],
    selected_node_id: str | None,
    svg: str,
    session: WorkbenchSession,
) -> dict[str, Any]:
    selected = _selected_node_raw(graph, selected_node_id)
    return {
        "schema": "albs-provenance-workbench/evidence-bundle/v1",
        "session": session.to_dict(),
        "selected_node": selected,
        "coverage": [row.to_dict() for row in coverage_rows(coverage)],
        "findings": [finding.to_dict() for finding in findings],
        "timeline": [row.to_dict() for row in timeline_rows(graph)],
        "slice": graph_slice.to_dict() if graph_slice is not None else None,
        "slice_graph": graph_slice.graph.to_dict() if graph_slice is not None else None,
        "svg": svg,
    }


def _optional_text(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _selected_node_raw(graph: ProvenanceGraph, node_id: str | None) -> dict[str, Any] | None:
    if node_id is None or node_id not in graph.nodes:
        return None
    return {
        "node": graph.nodes[node_id].to_dict(),
        "incoming": [edge.to_dict() for edge in graph.incoming(node_id)],
        "outgoing": [edge.to_dict() for edge in graph.outgoing(node_id)],
    }

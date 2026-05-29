from __future__ import annotations

import json
from html import escape
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from albs_graph.model import NodeType, ProvenanceGraph
from albs_graph.provenance.build_analysis import BuildAnalysis, SignTaskTiming, TaskTiming
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
    duration_seconds: float | None = None
    started_at: str | None = None
    finished_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "node_id": self.node_id,
            "detail": self.detail,
        }
        if self.duration_seconds is not None:
            data["duration_seconds"] = self.duration_seconds
        if self.started_at:
            data["started_at"] = self.started_at
        if self.finished_at:
            data["finished_at"] = self.finished_at
        return data


@dataclass(frozen=True)
class TimelineTreeItem:
    kind: str
    label: str
    status: str = ""
    node_id: str = ""
    detail: str = ""
    duration_seconds: float | None = None
    started_at: str | None = None
    finished_at: str | None = None
    children: tuple["TimelineTreeItem", ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = TimelineRow(
            kind=self.kind,
            label=self.label,
            status=self.status,
            node_id=self.node_id,
            detail=self.detail,
            duration_seconds=self.duration_seconds,
            started_at=self.started_at,
            finished_at=self.finished_at,
        ).to_dict()
        data["children"] = [child.to_dict() for child in self.children]
        return data


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
    selected_edge_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "build_id": self.build_id,
            "mode": self.mode,
            "include_tests": self.include_tests,
            "artifact_filter": self.artifact_filter,
            "selected_artifact_id": self.selected_artifact_id,
            "selected_node_id": self.selected_node_id,
            "selected_edge_index": self.selected_edge_index,
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
            selected_edge_index=_optional_int(data.get("selected_edge_index")),
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


def timeline_rows(
    graph: ProvenanceGraph, build_analysis: BuildAnalysis | None = None
) -> list[TimelineRow]:
    rows: list[TimelineRow] = []
    for item in timeline_tree(graph, build_analysis):
        _flatten_timeline(item, rows)
    return rows


def timeline_tree(
    graph: ProvenanceGraph, build_analysis: BuildAnalysis | None = None
) -> list[TimelineTreeItem]:
    if build_analysis is not None and (
        build_analysis.task_timings or build_analysis.sign_timings
    ):
        return _analysis_timeline_tree(graph, build_analysis)
    return _graph_timeline_tree(graph)


def _graph_timeline_tree(graph: ProvenanceGraph) -> list[TimelineTreeItem]:
    rows: list[TimelineTreeItem] = []
    for node in graph.find_by_type(NodeType.BUILD_TASK):
        produced = len(graph.outgoing(node.id))
        arch = node.metadata.get("arch") or node.metadata.get("build_arch") or "unknown"
        status = node.metadata.get("status")
        rows.append(
            TimelineTreeItem(
                kind="build_task",
                label=node.label,
                status=str(status) if status is not None else "",
                node_id=node.id,
                detail=f"{arch}; {produced} outgoing edges",
                started_at=_optional_text(node.metadata.get("started_at")),
                finished_at=_optional_text(node.metadata.get("finished_at")),
            )
        )
    for node in graph.find_by_type(NodeType.SIGNATURE):
        status = node.metadata.get("status")
        task_id = node.metadata.get("task_id") or node.metadata.get("sign_task_id")
        rows.append(
            TimelineTreeItem(
                kind="signature",
                label=node.label,
                status=str(status) if status is not None else "",
                node_id=node.id,
                detail=f"sign task {task_id}" if task_id else "signature evidence",
            )
        )
    return sorted(rows, key=lambda row: (row.kind, row.label, row.node_id))


def _analysis_timeline_tree(
    graph: ProvenanceGraph, build_analysis: BuildAnalysis
) -> list[TimelineTreeItem]:
    items = [_task_timeline_item(graph, task) for task in build_analysis.task_timings]
    items.extend(_sign_timeline_item(sign) for sign in build_analysis.sign_timings)
    return items


def _task_timeline_item(graph: ProvenanceGraph, task: TaskTiming) -> TimelineTreeItem:
    node_id = _task_node_id(graph, task.task_id)
    step_children = tuple(
        TimelineTreeItem(
            kind="build_step",
            label=step.name,
            status="",
            node_id=node_id,
            detail="build performance step",
            duration_seconds=step.seconds,
            started_at=step.started_at,
            finished_at=step.finished_at,
        )
        for step in task.steps
    )
    test_children = tuple(
        TimelineTreeItem(
            kind="test_step",
            label=name,
            node_id=node_id,
            detail=f"{task.test_tasks} test task(s)",
            duration_seconds=seconds,
        )
        for name, seconds in task.test_step_totals.items()
    )
    artifact_children = tuple(
        TimelineTreeItem(
            kind="artifact_group",
            label=artifact_type,
            node_id=node_id,
            detail=f"{count} artifact(s)",
        )
        for artifact_type, count in sorted(task.artifact_counts.items())
    )
    children: list[TimelineTreeItem] = []
    children.extend(step_children)
    if test_children:
        children.append(
            TimelineTreeItem(
                kind="test_tasks",
                label=f"test tasks ({task.test_tasks})",
                node_id=node_id,
                detail="aggregate test performance",
                children=test_children,
            )
        )
    if artifact_children:
        children.append(
            TimelineTreeItem(
                kind="artifacts",
                label="artifacts",
                node_id=node_id,
                detail=_artifact_counts_text(task.artifact_counts),
                children=artifact_children,
            )
        )
    return TimelineTreeItem(
        kind="build_task",
        label=f"ALBS task {task.task_id} {task.arch}",
        status=str(task.status) if task.status is not None else "",
        node_id=node_id,
        detail=f"{task.arch}; {_artifact_counts_text(task.artifact_counts)}",
        duration_seconds=task.wall_seconds,
        started_at=task.started_at,
        finished_at=task.finished_at,
        children=tuple(children),
    )


def _sign_timeline_item(sign: SignTaskTiming) -> TimelineTreeItem:
    children = tuple(
        TimelineTreeItem(
            kind="sign_step",
            label=name,
            detail="signing performance step",
            duration_seconds=seconds,
        )
        for name, seconds in sorted(sign.stats_seconds.items())
    )
    return TimelineTreeItem(
        kind="sign_task",
        label=f"ALBS sign task {sign.sign_task_id}",
        status=str(sign.status) if sign.status is not None else "",
        node_id=f"sig:albs:{sign.sign_task_id}",
        detail="signature task",
        duration_seconds=sign.wall_seconds,
        started_at=sign.started_at,
        finished_at=sign.finished_at,
        children=children,
    )


def _flatten_timeline(item: TimelineTreeItem, rows: list[TimelineRow]) -> None:
    rows.append(
        TimelineRow(
            kind=item.kind,
            label=item.label,
            status=item.status,
            node_id=item.node_id,
            detail=item.detail,
            duration_seconds=item.duration_seconds,
            started_at=item.started_at,
            finished_at=item.finished_at,
        )
    )
    for child in item.children:
        _flatten_timeline(child, rows)


def _task_node_id(graph: ProvenanceGraph, task_id: str) -> str:
    node_id = f"build:albs-task:{task_id}"
    if node_id in graph.nodes:
        return node_id
    return ""


def _artifact_counts_text(counts: dict[str, int]) -> str:
    if not counts:
        return "no artifacts"
    return ", ".join(f"{kind}={count}" for kind, count in sorted(counts.items()))


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
    selected_edge_index: int | None = None,
    selected_edge_graph: ProvenanceGraph | None = None,
    build_analysis: BuildAnalysis | None = None,
) -> dict[str, Any]:
    selected = _selected_node_raw(graph, selected_node_id)
    edge_graph = selected_edge_graph or graph
    return {
        "schema": "albs-provenance-workbench/evidence-bundle/v1",
        "session": session.to_dict(),
        "selected_node": selected,
        "selected_edge": _selected_edge_raw(edge_graph, selected_edge_index),
        "coverage": [row.to_dict() for row in coverage_rows(coverage)],
        "findings": [finding.to_dict() for finding in findings],
        "timeline": [row.to_dict() for row in timeline_rows(graph, build_analysis)],
        "slice": graph_slice.to_dict() if graph_slice is not None else None,
        "slice_graph": graph_slice.graph.to_dict() if graph_slice is not None else None,
        "svg": svg,
    }


def evidence_report_html(bundle: dict[str, Any]) -> str:
    session = bundle.get("session") or {}
    selected_node = bundle.get("selected_node") or {}
    selected_edge = bundle.get("selected_edge") or {}
    slice_info = bundle.get("slice") or {}
    coverage = bundle.get("coverage") or []
    findings = bundle.get("findings") or []
    timeline = bundle.get("timeline") or []
    svg = str(bundle.get("svg") or "")
    title = "ALBS Provenance Investigation Report"
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            f"<title>{title}</title>",
            "<style>",
            "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
            "margin:0;background:#f5f7fa;color:#17212b}",
            "header{padding:24px 32px;background:#20242a;color:#eef2f6}",
            "main{padding:24px 32px;display:grid;gap:24px}",
            "section{background:white;border:1px solid #d8dde6;padding:16px}",
            "h1,h2{margin:0 0 12px}",
            "table{border-collapse:collapse;width:100%;font-size:13px}",
            "th,td{border:1px solid #d8dde6;padding:6px 8px;text-align:left;vertical-align:top}",
            "th{background:#eef2f6}",
            "pre{white-space:pre-wrap;background:#17212b;color:#eef2f6;padding:12px;overflow:auto}",
            ".graph{overflow:auto;background:#171a1f;padding:12px}",
            "</style>",
            "</head>",
            "<body>",
            f"<header><h1>{title}</h1><div>{escape(str(session.get('source') or session.get('build_id') or 'current investigation'))}</div></header>",
            "<main>",
            _section("Current Slice", _dict_table(slice_info)),
            _section("Coverage", _rows_table(coverage, ["axis", "covered", "total", "ratio", "status"])),
            _section("Findings", _rows_table(findings, ["severity", "code", "subject", "detail"])),
            _section(
                "Timeline",
                _rows_table(
                    timeline,
                    [
                        "kind",
                        "label",
                        "status",
                        "duration_seconds",
                        "started_at",
                        "finished_at",
                        "node_id",
                        "detail",
                    ],
                ),
            ),
            _section("Selected Node", _raw_block(selected_node)),
            _section("Selected Edge", _raw_block(selected_edge)),
            _section("Graph", f'<div class="graph">{svg}</div>'),
            "</main>",
            "</body>",
            "</html>",
            "",
        ]
    )


def _optional_text(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _selected_node_raw(graph: ProvenanceGraph, node_id: str | None) -> dict[str, Any] | None:
    if node_id is None or node_id not in graph.nodes:
        return None
    return {
        "node": graph.nodes[node_id].to_dict(),
        "incoming": [edge.to_dict() for edge in graph.incoming(node_id)],
        "outgoing": [edge.to_dict() for edge in graph.outgoing(node_id)],
    }


def _selected_edge_raw(graph: ProvenanceGraph, edge_index: int | None) -> dict[str, Any] | None:
    if edge_index is None:
        return None
    try:
        edge = graph.edges[edge_index]
    except IndexError:
        return None
    return {
        "index": edge_index,
        "edge": edge.to_dict(),
        "source": graph.nodes[edge.source].to_dict(),
        "target": graph.nodes[edge.target].to_dict(),
    }


def _section(title: str, body: str) -> str:
    return f"<section><h2>{escape(title)}</h2>{body}</section>"


def _dict_table(data: dict[str, Any]) -> str:
    if not data:
        return "<p>No data.</p>"
    rows = "".join(
        f"<tr><th>{escape(str(key))}</th><td>{escape(json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value))}</td></tr>"
        for key, value in data.items()
    )
    return f"<table>{rows}</table>"


def _rows_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "<p>No rows.</p>"
    header = "".join(f"<th>{escape(column)}</th>" for column in columns)
    body = "".join(
        "<tr>"
        + "".join(f"<td>{escape(str(row.get(column) or ''))}</td>" for column in columns)
        + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>"


def _raw_block(data: Any) -> str:
    if not data:
        return "<p>No selection.</p>"
    return f"<pre>{escape(json.dumps(data, indent=2, sort_keys=True))}</pre>"

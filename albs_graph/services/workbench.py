from __future__ import annotations

import json
from html import escape
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from albs_graph.model import Edge, Node, NodeType, ProvenanceGraph, Relation
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
class TimelineGanttRow:
    depth: int
    kind: str
    label: str
    status: str
    node_id: str
    detail: str
    offset_seconds: float
    duration_seconds: float
    started_at: str | None = None
    finished_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "depth": self.depth,
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "node_id": self.node_id,
            "detail": self.detail,
            "offset_seconds": self.offset_seconds,
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


@dataclass(frozen=True)
class EvidenceMatrixRow:
    node_id: str
    package: str
    arch: str
    version: str
    release: str
    provenance: str
    security_context: str
    build_task: str
    source_cas: str
    artifact_cas: str
    signature: str
    release_context: str
    sbom: str
    errata: str
    tests: str
    completeness: float
    missing: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "package": self.package,
            "arch": self.arch,
            "version": self.version,
            "release": self.release,
            "provenance": self.provenance,
            "security_context": self.security_context,
            "build_task": self.build_task,
            "source_cas": self.source_cas,
            "artifact_cas": self.artifact_cas,
            "signature": self.signature,
            "release_context": self.release_context,
            "sbom": self.sbom,
            "errata": self.errata,
            "tests": self.tests,
            "completeness": self.completeness,
            "missing": self.missing,
        }


@dataclass(frozen=True)
class BuildDiffRow:
    area: str
    change: str
    key: str
    left: str
    right: str
    detail: str
    left_node_id: str | None = None
    right_node_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "area": self.area,
            "change": self.change,
            "key": self.key,
            "left": self.left,
            "right": self.right,
            "detail": self.detail,
            "left_node_id": self.left_node_id,
            "right_node_id": self.right_node_id,
        }


@dataclass(frozen=True)
class GraphLayer:
    code: str
    label: str
    node_types: frozenset[str]
    relations: frozenset[str]


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


def timeline_gantt_rows(
    graph: ProvenanceGraph, build_analysis: BuildAnalysis | None = None
) -> list[TimelineGanttRow]:
    events = timeline_tree(graph, build_analysis)
    base = _timeline_base(events)
    rows: list[TimelineGanttRow] = []
    for event in events:
        _append_gantt_rows(event, rows, base=base, depth=0, parent_offset=0.0)
    return rows


def evidence_matrix_rows(graph: ProvenanceGraph) -> list[EvidenceMatrixRow]:
    rows: list[EvidenceMatrixRow] = []
    for node in sorted(
        graph.find_by_type(NodeType.BINARY_RPM),
        key=lambda item: (
            str(item.metadata.get("name") or item.label),
            str(item.metadata.get("arch") or ""),
            item.id,
        ),
    ):
        report = graph.trust_path_report(node.id)
        checks = report.checks
        has_tests = _artifact_has_tests(graph, node.id)
        status_values = {
            "build_task": checks.get("has_build_task", False),
            "source_cas": checks.get("has_source_cas_attestation", False),
            "artifact_cas": checks.get("has_artifact_cas_attestation", False),
            "signature": checks.get("has_signature", False),
            "release_context": checks.get("has_release", False),
            "sbom": checks.get("has_sbom", False),
            "errata": checks.get("has_errata_link", False),
            "tests": has_tests,
        }
        missing = list(report.missing)
        if not has_tests:
            missing.append("has_tests")
        covered = sum(1 for value in status_values.values() if value)
        rows.append(
            EvidenceMatrixRow(
                node_id=node.id,
                package=str(node.metadata.get("name") or node.label),
                arch=str(node.metadata.get("arch") or node.metadata.get("build_arch") or ""),
                version=str(node.metadata.get("version") or ""),
                release=str(node.metadata.get("release") or ""),
                provenance="complete" if report.provenance_complete else "incomplete",
                security_context="complete" if report.security_context_complete else "incomplete",
                build_task=_status(status_values["build_task"]),
                source_cas=_status(status_values["source_cas"]),
                artifact_cas=_status(status_values["artifact_cas"]),
                signature=_status(status_values["signature"]),
                release_context=_status(status_values["release_context"]),
                sbom=_status(status_values["sbom"]),
                errata=_status(status_values["errata"]),
                tests=_status(status_values["tests"]),
                completeness=covered / len(status_values),
                missing=", ".join(missing),
            )
        )
    return rows


def compare_builds(
    left: ProvenanceGraph,
    right: ProvenanceGraph,
    *,
    left_build_analysis: BuildAnalysis | None = None,
    right_build_analysis: BuildAnalysis | None = None,
) -> list[BuildDiffRow]:
    from albs_graph.services.compare import compare_artifacts

    rows = [
        BuildDiffRow(
            area="artifact",
            change=delta.change,
            key=delta.key,
            left=delta.left or "",
            right=delta.right or "",
            detail=delta.detail,
            left_node_id=delta.left,
            right_node_id=delta.right,
        )
        for delta in compare_artifacts(left, right)
    ]
    rows.extend(_compare_evidence_matrices(left, right))
    rows.extend(_compare_build_timings(left_build_analysis, right_build_analysis))
    return sorted(rows, key=lambda row: (row.area, row.change, row.key))


def graph_layers() -> tuple[GraphLayer, ...]:
    return GRAPH_LAYERS


def filter_graph_layers(
    graph: ProvenanceGraph,
    enabled_layers: set[str],
    *,
    always_nodes: set[str] | None = None,
) -> ProvenanceGraph:
    if enabled_layers == {layer.code for layer in GRAPH_LAYERS}:
        return graph
    always = {node_id for node_id in (always_nodes or set()) if node_id in graph.nodes}
    allowed_node_types = {
        node_type
        for layer in GRAPH_LAYERS
        if layer.code in enabled_layers
        for node_type in layer.node_types
    }
    allowed_relations = {
        relation
        for layer in GRAPH_LAYERS
        if layer.code in enabled_layers
        for relation in layer.relations
    }
    kept_edges = [
        edge
        for edge in graph.edges
        if str(edge.relation) in allowed_relations
        and _node_layer_allowed(graph.nodes[edge.source], allowed_node_types, always)
        and _node_layer_allowed(graph.nodes[edge.target], allowed_node_types, always)
    ]
    selected = set(always)
    selected.update(
        node.id for node in graph.nodes.values() if str(node.type) in allowed_node_types
    )
    selected.update(edge.source for edge in kept_edges)
    selected.update(edge.target for edge in kept_edges)
    return _subgraph_from_edges(graph, selected, kept_edges)


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


GRAPH_LAYERS = (
    GraphLayer(
        "build",
        "Build",
        frozenset(
            {
                str(NodeType.SOURCE_PACKAGE),
                str(NodeType.GIT_REPOSITORY),
                str(NodeType.GIT_COMMIT),
                str(NodeType.BUILD_TASK),
                str(NodeType.BUILD_ENVIRONMENT),
                str(NodeType.SRPM),
                str(NodeType.BINARY_RPM),
                str(NodeType.SOURCE_TREE),
                str(NodeType.SOURCE_FILE),
                str(NodeType.SOURCE_MANIFEST),
            }
        ),
        frozenset(
            {
                str(Relation.STORED_IN),
                str(Relation.POINTS_TO),
                str(Relation.BUILT_BY),
                str(Relation.BUILT_IN),
                str(Relation.PRODUCES),
                str(Relation.DERIVED_FROM),
                str(Relation.CONTAINS),
                str(Relation.REFERENCES),
            }
        ),
    ),
    GraphLayer(
        "cas",
        "CAS",
        frozenset({str(NodeType.CAS_ATTESTATION)}),
        frozenset({str(Relation.AUTHENTICATED_BY)}),
    ),
    GraphLayer(
        "sign_release",
        "Sign/Release",
        frozenset({str(NodeType.SIGNATURE), str(NodeType.REPOSITORY_RELEASE)}),
        frozenset({str(Relation.SIGNED_AS), str(Relation.RELEASED_TO)}),
    ),
    GraphLayer(
        "tests",
        "Tests",
        frozenset({str(NodeType.TEST_RESULT)}),
        frozenset({str(Relation.TESTED_BY)}),
    ),
    GraphLayer(
        "security",
        "Security",
        frozenset({str(NodeType.SBOM), str(NodeType.ERRATA), str(NodeType.CVE)}),
        frozenset({str(Relation.DESCRIBED_BY), str(Relation.FIXES), str(Relation.AFFECTED_BY)}),
    ),
    GraphLayer(
        "dependencies",
        "Dependencies",
        frozenset(
            {
                str(NodeType.EXTERNAL_PACKAGE),
                str(NodeType.DEPENDENCY_SPEC),
                str(NodeType.DEPENDENCY_CLAIM),
                str(NodeType.DEPENDENCY_RESOLUTION),
            }
        ),
        frozenset(
            {
                str(Relation.REQUIRES_RUNTIME),
                str(Relation.REQUIRES_BUILDTIME),
                str(Relation.DECLARES_DEPENDENCY),
                str(Relation.PROVIDES),
                str(Relation.OBSERVED_AS),
                str(Relation.CORROBORATES),
                str(Relation.CONFLICTS_WITH),
                str(Relation.SUPERSEDES),
            }
        ),
    ),
)


def _append_gantt_rows(
    event: TimelineTreeItem,
    rows: list[TimelineGanttRow],
    *,
    base: datetime | None,
    depth: int,
    parent_offset: float,
) -> None:
    start = _parse_datetime(event.started_at)
    finish = _parse_datetime(event.finished_at)
    offset = _offset_seconds(base, start) if base and start else parent_offset
    duration = event.duration_seconds
    if duration is None and start and finish:
        duration = max(0.0, (finish - start).total_seconds())
    rows.append(
        TimelineGanttRow(
            depth=depth,
            kind=event.kind,
            label=event.label,
            status=event.status,
            node_id=event.node_id,
            detail=event.detail,
            offset_seconds=round(max(0.0, offset), 6),
            duration_seconds=round(max(0.0, duration or 0.0), 6),
            started_at=event.started_at,
            finished_at=event.finished_at,
        )
    )
    child_offset = max(0.0, offset)
    for child in event.children:
        _append_gantt_rows(child, rows, base=base, depth=depth + 1, parent_offset=child_offset)


def _timeline_base(events: list[TimelineTreeItem]) -> datetime | None:
    starts = [
        start
        for event in events
        for start in _timeline_starts(event)
        if start is not None
    ]
    return min(starts) if starts else None


def _timeline_starts(event: TimelineTreeItem) -> list[datetime | None]:
    return [_parse_datetime(event.started_at)] + [
        start for child in event.children for start in _timeline_starts(child)
    ]


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.fromisoformat(text.replace(" ", "T"))
        except ValueError:
            return None


def _offset_seconds(base: datetime, value: datetime) -> float:
    if base.tzinfo is None and value.tzinfo is not None:
        value = value.replace(tzinfo=None)
    elif base.tzinfo is not None and value.tzinfo is None:
        base = base.replace(tzinfo=None)
    return (value - base).total_seconds()


def _artifact_has_tests(graph: ProvenanceGraph, node_id: str) -> bool:
    if any(edge.relation == Relation.TESTED_BY for edge in graph.outgoing(node_id)):
        return True
    return any(
        graph.outgoing(edge.source, Relation.TESTED_BY)
        for edge in graph.incoming(node_id, Relation.PRODUCES)
    )


def _status(value: bool) -> str:
    return "ok" if value else "missing"


def _compare_evidence_matrices(
    left: ProvenanceGraph, right: ProvenanceGraph
) -> list[BuildDiffRow]:
    left_rows = {_evidence_key(row): row for row in evidence_matrix_rows(left)}
    right_rows = {_evidence_key(row): row for row in evidence_matrix_rows(right)}
    rows: list[BuildDiffRow] = []
    for key in sorted(left_rows.keys() & right_rows.keys()):
        left_row = left_rows[key]
        right_row = right_rows[key]
        left_state = _evidence_state(left_row)
        right_state = _evidence_state(right_row)
        if left_state != right_state:
            rows.append(
                BuildDiffRow(
                    area="evidence",
                    change="changed",
                    key=key,
                    left=left_state,
                    right=right_state,
                    detail=_changed_fields(left_state, right_state),
                    left_node_id=left_row.node_id,
                    right_node_id=right_row.node_id,
                )
            )
    return rows


def _compare_build_timings(
    left: BuildAnalysis | None, right: BuildAnalysis | None
) -> list[BuildDiffRow]:
    if left is None or right is None:
        return []
    rows: list[BuildDiffRow] = []
    if left.wall_seconds != right.wall_seconds:
        rows.append(
            BuildDiffRow(
                area="build",
                change="changed",
                key="overall wall time",
                left=_seconds_value(left.wall_seconds),
                right=_seconds_value(right.wall_seconds),
                detail=f"build {left.build_id} -> {right.build_id}",
            )
        )
    left_tasks = {_task_compare_key(task): task for task in left.task_timings}
    right_tasks = {_task_compare_key(task): task for task in right.task_timings}
    for key in sorted(left_tasks.keys() - right_tasks.keys()):
        task = left_tasks[key]
        rows.append(
            BuildDiffRow(
                area="task",
                change="removed",
                key=key,
                left=_task_timing_state(task),
                right="",
                detail=f"ALBS task {task.task_id}",
                left_node_id=f"build:albs-task:{task.task_id}",
            )
        )
    for key in sorted(right_tasks.keys() - left_tasks.keys()):
        task = right_tasks[key]
        rows.append(
            BuildDiffRow(
                area="task",
                change="added",
                key=key,
                left="",
                right=_task_timing_state(task),
                detail=f"ALBS task {task.task_id}",
                right_node_id=f"build:albs-task:{task.task_id}",
            )
        )
    for key in sorted(left_tasks.keys() & right_tasks.keys()):
        left_task = left_tasks[key]
        right_task = right_tasks[key]
        left_state = _task_timing_state(left_task)
        right_state = _task_timing_state(right_task)
        if left_state != right_state:
            rows.append(
                BuildDiffRow(
                    area="task",
                    change="changed",
                    key=key,
                    left=left_state,
                    right=right_state,
                    detail=f"ALBS task {left_task.task_id} -> {right_task.task_id}",
                    left_node_id=f"build:albs-task:{left_task.task_id}",
                    right_node_id=f"build:albs-task:{right_task.task_id}",
                )
            )
    return rows


def _evidence_key(row: EvidenceMatrixRow) -> str:
    return f"{row.package}|{row.arch}"


def _evidence_state(row: EvidenceMatrixRow) -> str:
    fields = [
        ("prov", row.provenance),
        ("sec", row.security_context),
        ("build", row.build_task),
        ("src_cas", row.source_cas),
        ("art_cas", row.artifact_cas),
        ("sig", row.signature),
        ("release", row.release_context),
        ("sbom", row.sbom),
        ("errata", row.errata),
        ("tests", row.tests),
    ]
    return "; ".join(f"{name}={value}" for name, value in fields)


def _changed_fields(left: str, right: str) -> str:
    left_parts = dict(part.split("=", 1) for part in left.split("; ") if "=" in part)
    right_parts = dict(part.split("=", 1) for part in right.split("; ") if "=" in part)
    changed = [
        key
        for key in sorted(left_parts.keys() | right_parts.keys())
        if left_parts.get(key) != right_parts.get(key)
    ]
    return ", ".join(changed)


def _task_compare_key(task: TaskTiming) -> str:
    return task.arch


def _task_timing_state(task: TaskTiming) -> str:
    return (
        f"status={task.status}; wall={_seconds_value(task.wall_seconds)}; "
        f"tests={task.test_tasks}; artifacts={_artifact_counts_text(task.artifact_counts)}"
    )


def _seconds_value(value: float | None) -> str:
    return "" if value is None else f"{value:.3f}s"


def _node_layer_allowed(node: Node, allowed_node_types: set[str], always: set[str]) -> bool:
    return node.id in always or str(node.type) in allowed_node_types


def _subgraph_from_edges(
    graph: ProvenanceGraph, selected: set[str], edges: list[Edge]
) -> ProvenanceGraph:
    filtered = ProvenanceGraph()
    for node in graph.nodes.values():
        if node.id in selected:
            filtered.add_node(node)
    for edge in edges:
        if edge.source in filtered.nodes and edge.target in filtered.nodes:
            filtered.add_edge(edge.source, edge.target, edge.relation, **edge.metadata)
    return filtered


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
        "evidence_matrix": [row.to_dict() for row in evidence_matrix_rows(graph)],
        "findings": [finding.to_dict() for finding in findings],
        "timeline": [row.to_dict() for row in timeline_rows(graph, build_analysis)],
        "timeline_gantt": [row.to_dict() for row in timeline_gantt_rows(graph, build_analysis)],
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
    evidence_matrix = bundle.get("evidence_matrix") or []
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
            _section(
                "Evidence Matrix",
                _rows_table(
                    evidence_matrix,
                    [
                        "package",
                        "arch",
                        "provenance",
                        "security_context",
                        "build_task",
                        "source_cas",
                        "artifact_cas",
                        "signature",
                        "release_context",
                        "sbom",
                        "errata",
                        "tests",
                        "completeness",
                        "missing",
                    ],
                ),
            ),
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

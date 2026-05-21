from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import NodeType, ProvenanceGraph
from .render.dot import graph_to_dot
from .render.json_export import graph_to_json

__all__ = ["as_interview_summary", "graph_to_dot", "graph_to_json", "write_text"]


def write_text(path: str | Path, content: str) -> None:
    Path(path).write_text(content, encoding="utf-8")


def as_interview_summary(graph: ProvenanceGraph) -> str:
    rpm_nodes = graph.find_by_type(NodeType.BINARY_RPM)
    lines: list[str] = []
    for rpm in rpm_nodes:
        report: dict[str, Any] = graph.trust_report_for_rpm(rpm.id)
        lines.append(f"Package artifact: {rpm.label}")
        lines.append(f"Trust path complete: {report['complete']}")
        for name, value in report["checks"].items():
            lines.append(f"  - {name}: {value}")
    return "\n".join(lines) + "\n"

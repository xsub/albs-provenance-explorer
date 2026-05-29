from __future__ import annotations

import subprocess
from pathlib import Path
from xml.sax.saxutils import escape

from .dot import graph_to_dot
from albs_graph.model import ProvenanceGraph


SVG_FONT_STACK = "Arial,Helvetica,sans-serif"

class SvgRenderError(RuntimeError):
    pass


def graph_to_svg(graph: ProvenanceGraph) -> str:
    try:
        result = subprocess.run(
            ["dot", "-Tsvg"],
            input=graph_to_dot(graph),
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        return _fallback_svg(graph, f"Graphviz unavailable: {exc}")

    if result.returncode != 0:
        return _fallback_svg(graph, result.stderr.strip() or "Graphviz failed to render SVG")
    return result.stdout


def write_svg(graph: ProvenanceGraph, path: str | Path) -> None:
    Path(path).write_text(graph_to_svg(graph), encoding="utf-8")


def _fallback_svg(graph: ProvenanceGraph, note: str) -> str:
    width = 1200
    row_height = 78
    node_width = 260
    node_height = 48
    source_x = 40
    target_x = 560
    label_x = 360
    height = max(220, 120 + row_height * max(1, len(graph.edges)))
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f"<style>text{{font-family:{SVG_FONT_STACK};font-size:13px}}.meta{{fill:#607D8B;font-size:11px}}.node{{fill:#F8FAFC;stroke:#90A4AE;rx:6}}.edge{{stroke:#546E7A;stroke-width:1.4;marker-end:url(#arrow)}}</style>",
        '<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#546E7A"/></marker></defs>',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="40" y="34" font-size="18" font-weight="700">ALBS provenance graph</text>',
        f'<text class="meta" x="40" y="56">{escape(note)}</text>',
    ]
    for index, edge in enumerate(graph.edges):
        y = 92 + index * row_height
        source = graph.nodes[edge.source]
        target = graph.nodes[edge.target]
        lines.extend(
            [
                f'<rect class="node" x="{source_x}" y="{y}" width="{node_width}" height="{node_height}"/>',
                f'<text x="{source_x + 12}" y="{y + 20}">{escape(source.label[:34])}</text>',
                f'<text class="meta" x="{source_x + 12}" y="{y + 38}">{escape(str(source.type))}</text>',
                f'<line class="edge" x1="{source_x + node_width + 18}" y1="{y + 24}" x2="{target_x - 22}" y2="{y + 24}"/>',
                f'<text class="meta" text-anchor="middle" x="{label_x + 70}" y="{y + 18}">{escape(str(edge.relation))}</text>',
                f'<rect class="node" x="{target_x}" y="{y}" width="{node_width}" height="{node_height}"/>',
                f'<text x="{target_x + 12}" y="{y + 20}">{escape(target.label[:34])}</text>',
                f'<text class="meta" x="{target_x + 12}" y="{y + 38}">{escape(str(target.type))}</text>',
            ]
        )
    lines.append("</svg>")
    return "\n".join(lines) + "\n"

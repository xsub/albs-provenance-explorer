from __future__ import annotations

from dataclasses import dataclass
import subprocess
import textwrap
from xml.sax.saxutils import escape
from urllib.parse import quote

from albs_graph.gui.hitmap import EdgeRegion, GraphRegions, NodeRegion, graph_regions_from_cmap
from albs_graph.model import Node, NodeType, ProvenanceGraph


GRAPH_FONT = "Arial"
SVG_FONT_STACK = "Arial"

LIGHT_NODE_COLORS = {
    "source_package": "#E8F5E9",
    "git_repository": "#E3F2FD",
    "git_commit": "#E3F2FD",
    "cas_attestation": "#FFF8E1",
    "build_task": "#F3E5F5",
    "build_environment": "#F5F5F5",
    "srpm": "#E0F7FA",
    "binary_rpm": "#DDF4F8",
    "signature": "#FFF3E0",
    "repository_release": "#E8EAF6",
    "errata": "#FFEBEE",
    "cve": "#FFCDD2",
    "sbom": "#F1F8E9",
    "external_package": "#F5F5F5",
    "dependency_claim": "#ECEFF1",
    "dependency_resolution": "#E0F2F1",
    "source_tree": "#E8F5E9",
    "source_file": "#F1F8E9",
    "source_manifest": "#F9FBE7",
    "test_result": "#E1F5FE",
}

DARK_NODE_COLORS = {
    "source_package": "#173927",
    "git_repository": "#17334A",
    "git_commit": "#17334A",
    "cas_attestation": "#493A18",
    "build_task": "#3B2743",
    "build_environment": "#30343A",
    "srpm": "#183B40",
    "binary_rpm": "#173E46",
    "signature": "#463420",
    "repository_release": "#252D46",
    "errata": "#4A2428",
    "cve": "#5A252C",
    "sbom": "#253A1E",
    "external_package": "#30343A",
    "dependency_claim": "#29323A",
    "dependency_resolution": "#1D3D3A",
    "source_tree": "#173927",
    "source_file": "#1C3A22",
    "source_manifest": "#2E3315",
    "test_result": "#16323E",
}


@dataclass(frozen=True)
class WorkbenchGraphRendering:
    svg: str
    node_regions: tuple[NodeRegion, ...]
    edge_regions: tuple[EdgeRegion, ...]


def workbench_graph_to_svg(
    graph: ProvenanceGraph,
    *,
    dark: bool = False,
    selected_node_id: str | None = None,
    selected_edge_index: int | None = None,
) -> str:
    return workbench_graph_rendering(
        graph,
        dark=dark,
        selected_node_id=selected_node_id,
        selected_edge_index=selected_edge_index,
    ).svg


def workbench_graph_rendering(
    graph: ProvenanceGraph,
    *,
    dark: bool = False,
    selected_node_id: str | None = None,
    selected_edge_index: int | None = None,
) -> WorkbenchGraphRendering:
    dot = workbench_graph_to_dot(
        graph,
        dark=dark,
        selected_node_id=selected_node_id,
        selected_edge_index=selected_edge_index,
    )
    try:
        svg_result = _run_dot(dot, "svg")
    except FileNotFoundError as exc:
        return _fallback_rendering(graph, dark=dark, note=f"Graphviz unavailable: {exc}")

    if svg_result.returncode != 0:
        note = svg_result.stderr.strip() or "Graphviz failed to render SVG"
        return _fallback_rendering(graph, dark=dark, note=note)

    cmap_result = _run_dot(dot, "cmapx")
    regions = (
        graph_regions_from_cmap(cmap_result.stdout)
        if cmap_result.returncode == 0
        else GraphRegions((), ())
    )
    return WorkbenchGraphRendering(
        svg=svg_result.stdout,
        node_regions=regions.nodes,
        edge_regions=regions.edges,
    )


def workbench_graph_to_dot(
    graph: ProvenanceGraph,
    *,
    dark: bool = False,
    selected_node_id: str | None = None,
    selected_edge_index: int | None = None,
) -> str:
    theme = _theme(dark)
    colors = DARK_NODE_COLORS if dark else LIGHT_NODE_COLORS
    lines = [
        "digraph albs_workbench {",
        (
            f'  graph [rankdir=LR, bgcolor="{theme["background"]}", '
            f'fontname="{GRAPH_FONT}", pad="0.35", nodesep="0.65", ranksep="1.05"];'
        ),
        (
            f'  node [shape=box, style="rounded,filled", fontname="{GRAPH_FONT}", '
            f'fontsize=12, penwidth=1.4, margin="0.14,0.08", color="{theme["node_border"]}", '
            f'fontcolor="{theme["text"]}"];'
        ),
        (
            f'  edge [fontname="{GRAPH_FONT}", fontsize=9, color="{theme["edge"]}", '
            f'fontcolor="{theme["muted"]}", arrowsize=0.75, penwidth=1.5];'
        ),
    ]
    for node in graph.nodes.values():
        node_type = str(node.type)
        fill = colors.get(node_type, theme["node_fill"])
        border = theme["selected"] if node.id == selected_node_id else theme["node_border"]
        penwidth = "3.0" if node.id == selected_node_id else "1.4"
        label = _escape_label(_node_label(node))
        tooltip = _escape(f"{node_type}: {node.id}")
        url = _escape_url(f"node:{quote(node.id, safe='')}")
        lines.append(
            f'  "{_escape(node.id)}" [label="{label}", fillcolor="{fill}", '
            f'color="{border}", penwidth={penwidth}, tooltip="{tooltip}", URL="{url}"];'
        )
    for index, edge in enumerate(graph.edges):
        relation = _edge_label(str(edge.relation))
        color = theme["selected"] if index == selected_edge_index else theme["edge"]
        penwidth = "3.2" if index == selected_edge_index else "1.5"
        tooltip = _escape(f"{index}: {edge.source} {relation} {edge.target}")
        lines.append(
            f'  "{_escape(edge.source)}" -> "{_escape(edge.target)}" '
            f'[label="{_escape(relation)}", color="{color}", penwidth={penwidth}, '
            f'tooltip="{tooltip}", URL="edge:{index}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _run_dot(dot: str, output_format: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["dot", f"-T{output_format}"],
        input=dot,
        text=True,
        capture_output=True,
        check=False,
    )


def _node_label(node: Node) -> str:
    node_type = str(node.type)
    md = node.metadata
    if node.type == NodeType.BINARY_RPM:
        name = str(md.get("name") or node.label).removesuffix(".rpm")
        version = _version_release(md)
        arch = str(md.get("arch") or md.get("build_arch") or "")
        lines = [name]
        if version:
            lines.append(version)
        if arch:
            lines.append(f"[{arch}]")
        return _label(node_type, lines)
    if node.type == NodeType.SRPM:
        return _label(node_type, [str(md.get("name") or node.label).removesuffix(".rpm")])
    if node.type == NodeType.BUILD_TASK:
        arch_value = md.get("arch") or md.get("build_arch") or md.get("platform")
        task = md.get("task_id") or md.get("id") or _tail(node.label)
        return _label(node_type, [f"ALBS task {task}", str(arch_value) if arch_value else ""])
    if node.type == NodeType.GIT_COMMIT:
        commit = str(md.get("commit") or node.label)
        return _label(node_type, [commit[:12]])
    if node.type == NodeType.CAS_ATTESTATION:
        digest = str(md.get("cas_hash") or md.get("hash") or node.label)
        return _label(node_type, ["CAS", digest[:18]])
    if node.type == NodeType.SIGNATURE:
        return _label(node_type, [str(md.get("task_id") or node.label)])
    if node.type == NodeType.REPOSITORY_RELEASE:
        return _label(node_type, [str(md.get("repository") or node.label)])
    if node.type == NodeType.DEPENDENCY_RESOLUTION:
        return _label(
            node_type,
            [
                str(md.get("coordinate") or node.label),
                str(md.get("agreement") or ""),
            ],
        )
    if node.type == NodeType.DEPENDENCY_CLAIM:
        return _label(
            node_type,
            [
                str(md.get("name") or node.label),
                str(md.get("evidence") or ""),
            ],
        )
    return _label(node_type, [node.label])


def _label(node_type: str, lines: list[str]) -> str:
    compact_type = node_type.replace("_", " ")
    wrapped = [compact_type]
    for line in lines:
        clean = str(line).strip()
        if not clean:
            continue
        wrapped.extend(_wrap(clean, width=26, max_lines=2))
    return "\\n".join(wrapped[:5])


def _wrap(value: str, *, width: int, max_lines: int) -> list[str]:
    if len(value) <= width:
        return [value]
    chunks = textwrap.wrap(value, width=width, break_long_words=False, break_on_hyphens=True)
    if not chunks:
        return [value[: width - 1] + "…"]
    if len(chunks) <= max_lines:
        return chunks
    return chunks[: max_lines - 1] + [chunks[max_lines - 1][: width - 1] + "…"]


def _version_release(metadata: dict[str, object]) -> str:
    version = metadata.get("version")
    release = metadata.get("release")
    if version and release:
        return f"{version}-{release}"
    if version:
        return str(version)
    return ""


def _tail(value: str) -> str:
    return value.rsplit(" ", 1)[-1].rsplit(":", 1)[-1]


def _edge_label(relation: str) -> str:
    return relation.replace("_", " ")


def _theme(dark: bool) -> dict[str, str]:
    if dark:
        return {
            "background": "#171A1F",
            "text": "#F0F3F7",
            "muted": "#A9B5C2",
            "edge": "#7E94A3",
            "node_border": "#8EA0AD",
            "node_fill": "#2A3038",
            "selected": "#66A3FF",
        }
    return {
        "background": "#FFFFFF",
        "text": "#18212B",
        "muted": "#52616F",
        "edge": "#607D8B",
        "node_border": "#2F3B45",
        "node_fill": "#FFFFFF",
        "selected": "#2F6FED",
    }


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', "'")


def _escape_url(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', "%22")


def _escape_label(value: str) -> str:
    return value.replace('"', "'")


def _fallback_rendering(graph: ProvenanceGraph, *, dark: bool, note: str) -> WorkbenchGraphRendering:
    return WorkbenchGraphRendering(
        svg=_fallback_svg(graph, dark=dark, note=note),
        node_regions=_fallback_node_regions(graph),
        edge_regions=_fallback_edge_regions(graph),
    )


def _fallback_svg(graph: ProvenanceGraph, *, dark: bool, note: str) -> str:
    theme = _theme(dark)
    width = 1100
    row_height = 92
    height = max(260, 110 + row_height * max(1, len(graph.edges)))
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        (
            "<style>"
            f"text{{font-family:{SVG_FONT_STACK};font-size:13px;fill:{theme['text']}}}"
            f".meta{{fill:{theme['muted']};font-size:11px}}"
            f".node{{fill:{theme['node_fill']};stroke:{theme['node_border']};stroke-width:1.2;rx:7}}"
            f".edge{{stroke:{theme['edge']};stroke-width:1.5;marker-end:url(#arrow)}}"
            "</style>"
        ),
        f'<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="{theme["edge"]}"/></marker></defs>',
        f'<rect width="100%" height="100%" fill="{theme["background"]}"/>',
        '<text x="36" y="34" font-size="18" font-weight="700">ALBS provenance graph</text>',
        f'<text class="meta" x="36" y="58">{escape(note)}</text>',
    ]
    for index, edge in enumerate(graph.edges):
        y = 92 + index * row_height
        source = graph.nodes[edge.source]
        target = graph.nodes[edge.target]
        lines.extend(
            [
                f'<rect class="node" x="36" y="{y}" width="285" height="56"/>',
                f'<text x="50" y="{y + 23}">{escape(source.label[:34])}</text>',
                f'<text class="meta" x="50" y="{y + 43}">{escape(str(source.type))}</text>',
                f'<line class="edge" x1="345" y1="{y + 28}" x2="500" y2="{y + 28}"/>',
                f'<text class="meta" text-anchor="middle" x="425" y="{y + 20}">{escape(_edge_label(str(edge.relation)))}</text>',
                f'<rect class="node" x="524" y="{y}" width="285" height="56"/>',
                f'<text x="538" y="{y + 23}">{escape(target.label[:34])}</text>',
                f'<text class="meta" x="538" y="{y + 43}">{escape(str(target.type))}</text>',
            ]
        )
    lines.append("</svg>")
    return "\n".join(lines) + "\n"


def _fallback_node_regions(graph: ProvenanceGraph) -> tuple[NodeRegion, ...]:
    regions: list[NodeRegion] = []
    for index, edge in enumerate(graph.edges):
        y = 92 + index * 92
        regions.append(NodeRegion(edge.source, "rect", (36, y, 321, y + 56)))
        regions.append(NodeRegion(edge.target, "rect", (524, y, 809, y + 56)))
    return tuple(regions)


def _fallback_edge_regions(graph: ProvenanceGraph) -> tuple[EdgeRegion, ...]:
    regions: list[EdgeRegion] = []
    for index, _edge in enumerate(graph.edges):
        y = 92 + index * 92
        regions.append(EdgeRegion(index, "rect", (345, y + 16, 500, y + 40)))
    return tuple(regions)

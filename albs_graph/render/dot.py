from __future__ import annotations

from albs_graph.model import ProvenanceGraph


NODE_COLORS = {
    "source_package": "#E8F5E9",
    "git_repository": "#E3F2FD",
    "git_commit": "#E3F2FD",
    "cas_attestation": "#FFF8E1",
    "build_task": "#F3E5F5",
    "build_environment": "#F5F5F5",
    "srpm": "#E0F7FA",
    "binary_rpm": "#E0F7FA",
    "signature": "#FFF3E0",
    "repository_release": "#E8EAF6",
    "errata": "#FFEBEE",
    "cve": "#FFCDD2",
    "sbom": "#F1F8E9",
    "external_package": "#F5F5F5",
    "dependency_spec": "#ECEFF1",
}


def graph_to_dot(graph: ProvenanceGraph) -> str:
    lines = [
        "digraph albs_provenance {",
        '  graph [rankdir=LR, bgcolor="white", fontname="Inter"];',
        '  node [shape=box, style="rounded,filled", fontname="Inter", fontsize=10, margin="0.08,0.06"];',
        '  edge [fontname="Inter", fontsize=9, color="#546E7A", arrowsize=0.7];',
    ]
    for node in graph.nodes.values():
        node_type = str(node.type)
        color = NODE_COLORS.get(node_type, "#FFFFFF")
        label = _escape(f"{node_type}\\n{node.label}")
        lines.append(f'  "{_escape(node.id)}" [label="{label}", fillcolor="{color}"];')
    for edge in graph.edges:
        relation = _escape(str(edge.relation))
        lines.append(
            f'  "{_escape(edge.source)}" -> "{_escape(edge.target)}" [label="{relation}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', "'")

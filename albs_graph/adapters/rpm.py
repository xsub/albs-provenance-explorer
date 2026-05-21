from __future__ import annotations

import subprocess
from pathlib import Path

from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation


class RpmQueryError(RuntimeError):
    pass


def graph_from_local_rpm(path: str | Path) -> ProvenanceGraph:
    rpm_path = Path(path)
    if not rpm_path.exists():
        raise FileNotFoundError(rpm_path)

    graph = ProvenanceGraph()
    rpm_id = f"rpmfile:{rpm_path.name}"
    graph.add_node(
        Node(
            rpm_id,
            NodeType.BINARY_RPM,
            rpm_path.name,
            {"path": str(rpm_path), "provenance_completeness": "rpm-metadata-only"},
        )
    )

    for provided in _rpm_query(rpm_path, "provides"):
        node_id = f"provide:{rpm_path.name}:{provided}"
        graph.add_node(Node(node_id, NodeType.EXTERNAL_PACKAGE, provided, {"kind": "provide"}))
        graph.add_edge(rpm_id, node_id, Relation.PROVIDES)

    for required in _rpm_query(rpm_path, "requires"):
        node_id = f"require:{rpm_path.name}:{required}"
        graph.add_node(Node(node_id, NodeType.EXTERNAL_PACKAGE, required, {"kind": "runtime_requirement"}))
        graph.add_edge(rpm_id, node_id, Relation.REQUIRES_RUNTIME)

    return graph


def _rpm_query(path: Path, query: str) -> list[str]:
    try:
        result = subprocess.run(
            ["rpm", "-qp", f"--{query}", str(path)],
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise RpmQueryError("rpm command not found; install rpm tooling or use mock mode") from exc

    if result.returncode != 0:
        raise RpmQueryError(result.stderr.strip() or f"rpm query failed for {path}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]

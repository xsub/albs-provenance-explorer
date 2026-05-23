from __future__ import annotations

import subprocess
from pathlib import Path

from albs_graph.dependency import (
    DependencyScope,
    DependencySpec,
    Ecosystem,
    PackageIdentity,
    ResolutionState,
    dependency_edge_metadata,
    dependency_node_metadata,
    dependency_spec_node_id,
)
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
        spec = _rpm_dependency_spec(
            provided,
            scope=DependencyScope.PROVIDED,
            state=ResolutionState.PROVIDED,
            source="rpm -qp --provides",
        )
        node_id = f"provide:{rpm_path.name}:{_safe_id(provided)}"
        graph.add_node(
            Node(
                node_id,
                NodeType.EXTERNAL_PACKAGE,
                provided,
                dependency_node_metadata(spec) | {"kind": "provide"},
            )
        )
        graph.add_edge(rpm_id, node_id, Relation.PROVIDES, **dependency_edge_metadata(spec))

    for required in _rpm_query(rpm_path, "requires"):
        spec = _rpm_dependency_spec(
            required,
            scope=DependencyScope.RUNTIME,
            state=ResolutionState.DECLARED,
            source="rpm -qp --requires",
        )
        node_id = dependency_spec_node_id(spec)
        graph.add_node(
            Node(
                node_id,
                NodeType.DEPENDENCY_SPEC,
                required,
                dependency_node_metadata(spec) | {"kind": "runtime_requirement"},
            )
        )
        edge_metadata = dependency_edge_metadata(spec)
        graph.add_edge(rpm_id, node_id, Relation.DECLARES_DEPENDENCY, **edge_metadata)
        graph.add_edge(rpm_id, node_id, Relation.REQUIRES_RUNTIME, **edge_metadata)

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
        raise RpmQueryError(
            "rpm command not found; install rpm tooling or inspect a synthetic fixture separately"
        ) from exc

    if result.returncode != 0:
        raise RpmQueryError(result.stderr.strip() or f"rpm query failed for {path}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _rpm_dependency_spec(
    expression: str,
    *,
    scope: DependencyScope,
    state: ResolutionState,
    source: str,
) -> DependencySpec:
    return DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, _rpm_expression_name(expression)),
        requested=expression,
        scope=scope,
        resolution_state=state,
        source=source,
        raw={"expression": expression},
    )


def _rpm_expression_name(expression: str) -> str:
    return expression.split(maxsplit=1)[0]


def _safe_id(value: str) -> str:
    return value.replace("/", "_").replace(" ", "_")

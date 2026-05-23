from pathlib import Path
from typing import Any

from albs_graph.adapters import rpm as rpm_adapter
from albs_graph.dependency import (
    DependencyContext,
    DependencyCoverageSummary,
    DependencyScope,
    DependencySpec,
    Ecosystem,
    PackageIdentity,
    ResolutionState,
    package_identity_from_purl,
    summarize_dependency_coverage,
)
from albs_graph.model import NodeType, Relation


def test_package_identity_from_purl_preserves_ecosystem_and_context() -> None:
    identity = package_identity_from_purl("pkg:maven/org.apache.commons/commons-lang3@3.14.0")
    spec = DependencySpec(
        identity=identity,
        requested="[3.12,4)",
        scope=DependencyScope.RUNTIME,
        resolution_state=ResolutionState.RESOLVED,
        context=DependencyContext(os="linux", arch="x86_64", language_version="17"),
        source="maven",
    )

    data = spec.to_dict()

    assert data["identity"]["ecosystem"] == Ecosystem.MAVEN
    assert data["identity"]["namespace"] == "org.apache.commons"
    assert data["requested"] == "[3.12,4)"
    assert data["context"] == {
        "os": "linux",
        "arch": "x86_64",
        "language_version": "17",
    }


def test_rpm_adapter_emits_normalized_dependency_specs(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    rpm_path = tmp_path / "synthetic-core.rpm"
    rpm_path.write_bytes(b"rpm")

    def fake_rpm_query(path: Path, query: str) -> list[str]:
        assert path == rpm_path
        if query == "provides":
            return ["synthetic-core = 1.0.0-1.el9"]
        return ["libcrypto.so.3()(64bit)", "config(synthetic-core) = 1.0.0-1.el9"]

    monkeypatch.setattr(rpm_adapter, "_rpm_query", fake_rpm_query)

    graph = rpm_adapter.graph_from_local_rpm(rpm_path)
    dependency_nodes = graph.find_by_type(NodeType.DEPENDENCY_SPEC)
    provided_nodes = graph.find_by_type(NodeType.EXTERNAL_PACKAGE)
    summary: DependencyCoverageSummary = summarize_dependency_coverage(graph)

    assert len(dependency_nodes) == 2
    assert len(provided_nodes) == 1
    assert summary.ecosystems == {"rpm": 3}
    assert summary.scopes == {"runtime": 2, "provided": 1}
    assert any(edge.relation == Relation.DECLARES_DEPENDENCY for edge in graph.edges)


def test_dependency_context_serializes_environment_selectors() -> None:
    identity = PackageIdentity(Ecosystem.PYPI, "torch", version="2.3.0")
    spec = DependencySpec(
        identity=identity,
        requested="torch[gpu]>=2.3",
        scope=DependencyScope.OPTIONAL,
        resolution_state=ResolutionState.DECLARED,
        context=DependencyContext(os="linux", extras=("gpu",)),
        source="poetry",
    )

    assert spec.to_dict()["context"] == {"os": "linux", "extras": ["gpu"]}

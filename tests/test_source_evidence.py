from __future__ import annotations

from pathlib import Path

from albs_graph.adapters.albs import graph_from_build_metadata, parse_build_metadata
from albs_graph.adapters.source import attach_source_evidence
from albs_graph.model import NodeType, Relation


def test_source_evidence_attaches_spec_manifest_and_file_inventory(tmp_path: Path) -> None:
    metadata = parse_build_metadata(
        {
            "id": 987,
            "package": "demo",
            "source_repository": "https://git.example.invalid/rpms/demo.git",
            "commit": "abc123",
            "source_cas_hash": "cas123",
            "binary_rpms": [],
        }
    )
    graph = graph_from_build_metadata(metadata)
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "demo.spec").write_text(
        "\n".join(
            [
                "Name: demo",
                "Source0: demo.tar.gz",
                "Patch0: demo-fix.patch",
                "BuildRequires: gcc, pkgconfig(openssl) >= 3",
                "Requires: bash >= 5",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (source_dir / "package.json").write_text('{"name": "demo-ui"}\n', encoding="utf-8")
    (source_dir / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    summary = attach_source_evidence(graph, metadata, source_dir)

    assert summary.files == 3
    assert summary.manifests == 1
    assert summary.spec_files == 1
    assert summary.dependency_specs == 3
    assert summary.source_refs == 1
    assert summary.patch_refs == 1
    assert summary.ecosystems == ("npm",)
    assert graph.nodes[summary.source_tree_id].metadata["dependency_specs"] == 3
    assert any(node.type == NodeType.SOURCE_MANIFEST for node in graph.nodes.values())
    assert any(
        node.type == NodeType.DEPENDENCY_SPEC
        and node.metadata["scope"] == "buildtime"
        and node.metadata["name"] == "gcc"
        for node in graph.nodes.values()
    )
    assert any(
        edge.relation == Relation.DESCRIBED_BY
        and edge.source == "src:demo"
        and edge.target == summary.source_tree_id
        for edge in graph.edges
    )


def test_source_evidence_can_skip_full_file_inventory(tmp_path: Path) -> None:
    metadata = parse_build_metadata(
        {
            "id": 988,
            "package": "demo",
            "source_repository": "https://git.example.invalid/rpms/demo.git",
            "commit": "abc123",
            "binary_rpms": [],
        }
    )
    graph = graph_from_build_metadata(metadata)
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "demo.spec").write_text("BuildRequires: make\n", encoding="utf-8")
    (source_dir / "implementation.c").write_text("void f(void) {}\n", encoding="utf-8")

    summary = attach_source_evidence(
        graph,
        metadata,
        source_dir,
        include_file_inventory=False,
    )

    assert summary.files == 1
    assert "source-file:988:implementation.c" not in graph.nodes
    assert summary.dependency_specs == 1

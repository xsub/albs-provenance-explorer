import json
from pathlib import Path

from albs_graph.adapters.sbom import attach_sbom, enrich_graph_with_build_sbom, import_sbom
from albs_graph.fixtures import build_synthetic_fixture_graph
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance.coverage import coverage_report


def test_import_cyclonedx_sbom_components(tmp_path: Path) -> None:
    sbom_path = tmp_path / "bom.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "synthetic-core",
                        "version": "1.0.0-1.el9",
                        "purl": "pkg:rpm/almalinux/synthetic-core@1.0.0-1.el9?arch=x86_64",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    graph = import_sbom(sbom_path)

    assert len(graph.find_by_type(NodeType.SBOM)) == 1
    assert len(graph.find_by_type(NodeType.EXTERNAL_PACKAGE)) == 1
    component = graph.find_by_type(NodeType.EXTERNAL_PACKAGE)[0]
    assert component.metadata["ecosystem"] == "rpm"
    assert component.metadata["scope"] == "unknown"
    assert component.metadata["resolution_state"] == "observed"
    assert component.metadata["dependency"]["identity"]["purl"].startswith("pkg:rpm/")


def test_import_multiarch_sbom_keeps_arch_variants_and_dedupes_repeats(tmp_path: Path) -> None:
    # A real AlmaLinux build SBOM lists the same NEVR per architecture; arch
    # variants are distinct artifacts (must not collide), while an identical
    # noarch component repeated across build tasks must dedupe rather than crash.
    sbom_path = tmp_path / "build.cdx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"name": "nginx-core", "version": "1.26.3-6.el10",
                     "purl": "pkg:rpm/almalinux/nginx-core@1.26.3-6.el10?arch=x86_64"},
                    {"name": "nginx-core", "version": "1.26.3-6.el10",
                     "purl": "pkg:rpm/almalinux/nginx-core@1.26.3-6.el10?arch=aarch64"},
                    {"name": "nginx-filesystem", "version": "1.26.3-6.el10",
                     "purl": "pkg:rpm/almalinux/nginx-filesystem@1.26.3-6.el10?arch=noarch"},
                    {"name": "nginx-filesystem", "version": "1.26.3-6.el10",
                     "purl": "pkg:rpm/almalinux/nginx-filesystem@1.26.3-6.el10?arch=noarch"},
                ],
            }
        ),
        encoding="utf-8",
    )

    graph = import_sbom(sbom_path)

    # 2 arch variants of nginx-core stay distinct; the repeated noarch dedupes.
    assert len(graph.find_by_type(NodeType.EXTERNAL_PACKAGE)) == 3


def _binary_rpm(node_id: str, name: str, arch: str) -> Node:
    return Node(
        node_id,
        NodeType.BINARY_RPM,
        f"{name}.{arch}.rpm",
        {
            "name": name,
            "arch": arch,
            "security_identity": {"cpe": None, "cpe_candidates": [], "cpe_status": "candidate_only"},
        },
    )


def _build_sbom_file(tmp_path: Path) -> Path:
    sbom = tmp_path / "build.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "name": "nginx-core",
                        "version": "1.26.3-6.el10",
                        "cpe": "cpe:2.3:a:almalinux:nginx-core:1.26.3-6.el10:*:*:*:*:*:*:*",
                        "purl": "pkg:rpm/almalinux/nginx-core@1.26.3-6.el10?arch=x86_64",
                        "hashes": [{"alg": "SHA-256", "content": "deadbeef"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return sbom


def test_build_sbom_sets_vendor_cpe_and_moves_identity_axis(tmp_path: Path) -> None:
    # A build SBOM's vendor CPE is matched to the build's own RPM by (name, arch);
    # it sets a verified CPE (source=almalinux_sbom), which the identity axis counts.
    graph = ProvenanceGraph()
    graph.add_node(_binary_rpm("rpm:nginx-core:x86_64", "nginx-core", "x86_64"))

    result = enrich_graph_with_build_sbom(graph, _build_sbom_file(tmp_path))

    assert result.matched == 1
    assert result.cpes_set == 1
    node = graph.nodes["rpm:nginx-core:x86_64"]
    identity = node.metadata["security_identity"]
    assert identity["cpe"] == "cpe:2.3:a:almalinux:nginx-core:1.26.3-6.el10:*:*:*:*:*:*:*"
    assert identity["cpe_source"] == "almalinux_sbom"
    assert node.metadata["sbom_sha256"] == "deadbeef"
    # The identity axis (verified CPE) now counts this binary.
    assert coverage_report(graph).identity.covered == 1
    # A described_by edge links the RPM to the SBOM node.
    assert any(e.target.startswith("sbom:") for e in graph.outgoing("rpm:nginx-core:x86_64"))


def test_build_sbom_skips_wrong_arch_and_preexisting_cpe(tmp_path: Path) -> None:
    graph = ProvenanceGraph()
    graph.add_node(_binary_rpm("rpm:nginx-core:aarch64", "nginx-core", "aarch64"))  # arch mismatch
    already = _binary_rpm("rpm:nginx-core:x86_64", "nginx-core", "x86_64")
    already.metadata["security_identity"]["cpe"] = "cpe:2.3:a:nvd:nginx-core:1:*:*:*:*:*:*:*"
    graph.add_node(already)

    result = enrich_graph_with_build_sbom(graph, _build_sbom_file(tmp_path))

    # x86_64 node matches but already has an (NVD) CPE -> not overridden; aarch64 has no component.
    assert result.matched == 1
    assert result.cpes_set == 0
    assert graph.nodes["rpm:nginx-core:x86_64"].metadata["security_identity"]["cpe"].endswith(
        "nvd:nginx-core:1:*:*:*:*:*:*:*"
    )


def test_attach_sbom_to_rpm_adds_described_by_edge(tmp_path: Path) -> None:
    graph = build_synthetic_fixture_graph()
    sbom_path = tmp_path / "spdx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "synthetic SPDX",
                "packages": [{"name": "synthetic-core", "versionInfo": "1.0.0-1.el9"}],
            }
        ),
        encoding="utf-8",
    )

    attach_sbom(graph, "rpm:synthetic-core:1.0.0-1.el9:x86_64", sbom_path)

    assert any(
        edge.target == "sbom:spdx:synthetic SPDX"
        for edge in graph.outgoing("rpm:synthetic-core:1.0.0-1.el9:x86_64")
    )

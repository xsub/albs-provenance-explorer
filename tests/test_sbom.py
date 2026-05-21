import json
from pathlib import Path

from albs_graph.adapters.sbom import attach_sbom, import_sbom
from albs_graph.mock_data import build_mock_openssl_graph
from albs_graph.model import NodeType


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
                        "name": "openssl-libs",
                        "version": "3.0.7-28.el9_4",
                        "purl": "pkg:rpm/almalinux/openssl-libs@3.0.7-28.el9_4?arch=x86_64",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    graph = import_sbom(sbom_path)

    assert len(graph.find_by_type(NodeType.SBOM)) == 1
    assert len(graph.find_by_type(NodeType.EXTERNAL_PACKAGE)) == 1


def test_attach_sbom_to_rpm_adds_described_by_edge(tmp_path: Path) -> None:
    graph = build_mock_openssl_graph()
    sbom_path = tmp_path / "spdx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "openssl SPDX",
                "packages": [{"name": "openssl-libs", "versionInfo": "3.0.7-28.el9_4"}],
            }
        ),
        encoding="utf-8",
    )

    attach_sbom(graph, "rpm:openssl-libs:3.0.7-28.el9_4:x86_64", sbom_path)

    assert any(
        edge.target == "sbom:spdx:openssl SPDX"
        for edge in graph.outgoing("rpm:openssl-libs:3.0.7-28.el9_4:x86_64")
    )

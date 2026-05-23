import json
from pathlib import Path

from albs_graph.adapters.sbom import attach_sbom, import_sbom
from albs_graph.fixtures import build_synthetic_fixture_graph
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

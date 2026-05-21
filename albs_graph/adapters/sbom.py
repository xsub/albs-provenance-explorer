from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation


def import_sbom(path: str | Path, attach_to: str | None = None) -> ProvenanceGraph:
    graph = ProvenanceGraph()
    attach_sbom(graph, attach_to, path)
    return graph


def attach_sbom(graph: ProvenanceGraph, rpm_node_id: str | None, sbom_path: str | Path) -> str:
    path = Path(sbom_path)
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("bomFormat") == "CycloneDX":
        return attach_cyclonedx_sbom(graph, rpm_node_id, path, data)
    if "spdxVersion" in data:
        return attach_spdx_sbom(graph, rpm_node_id, path, data)
    raise ValueError(f"Unsupported SBOM format for {path}")


def attach_cyclonedx_sbom(
    graph: ProvenanceGraph,
    rpm_node_id: str | None,
    sbom_path: Path,
    data: dict[str, Any],
) -> str:
    sbom_id = f"sbom:{data.get('serialNumber') or sbom_path.name}"
    graph.add_node(
        Node(
            sbom_id,
            NodeType.SBOM,
            sbom_path.name,
            {
                "format": "CycloneDX",
                "bomFormat": data.get("bomFormat"),
                "specVersion": data.get("specVersion"),
                "source_path": str(sbom_path),
            },
        )
    )
    if rpm_node_id:
        graph.add_edge(rpm_node_id, sbom_id, Relation.DESCRIBED_BY)

    for component in data.get("components", []):
        name = component.get("name")
        if not name:
            continue
        version = component.get("version", "unknown")
        component_id = _component_id("cyclonedx", name, version, component.get("purl"))
        graph.add_node(
            Node(
                component_id,
                NodeType.EXTERNAL_PACKAGE,
                f"{name} {version}",
                {"source": "CycloneDX", "component": component},
            )
        )
        graph.add_edge(sbom_id, component_id, Relation.DESCRIBED_BY)
    return sbom_id


def attach_spdx_sbom(
    graph: ProvenanceGraph,
    rpm_node_id: str | None,
    sbom_path: Path,
    data: dict[str, Any],
) -> str:
    document_name = str(data.get("name") or sbom_path.name)
    sbom_id = f"sbom:spdx:{document_name}"
    graph.add_node(
        Node(
            sbom_id,
            NodeType.SBOM,
            document_name,
            {
                "format": "SPDX",
                "spdxVersion": data.get("spdxVersion"),
                "source_path": str(sbom_path),
            },
        )
    )
    if rpm_node_id:
        graph.add_edge(rpm_node_id, sbom_id, Relation.DESCRIBED_BY)

    for package in data.get("packages", []):
        name = package.get("name")
        if not name:
            continue
        version = package.get("versionInfo", "unknown")
        purl = _external_ref_purl(package)
        component_id = _component_id("spdx", name, version, purl)
        graph.add_node(
            Node(
                component_id,
                NodeType.EXTERNAL_PACKAGE,
                f"{name} {version}",
                {"source": "SPDX", "package": package},
            )
        )
        graph.add_edge(sbom_id, component_id, Relation.DESCRIBED_BY)
    return sbom_id


def _external_ref_purl(package: dict[str, Any]) -> str | None:
    for ref in package.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            locator = ref.get("referenceLocator")
            return str(locator) if locator is not None else None
    return None


def _component_id(source: str, name: str, version: str, purl: str | None) -> str:
    if purl:
        try:
            from packageurl import PackageURL

            parsed = PackageURL.from_string(purl)
            return f"pkg:{parsed.type}:{parsed.namespace or '_'}:{parsed.name}:{parsed.version or version}"
        except ImportError:
            return purl
    return f"sbom-component:{source}:{name}:{version}"

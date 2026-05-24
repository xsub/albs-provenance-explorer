from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from albs_graph.dependency import (
    DependencyScope,
    DependencySpec,
    Ecosystem,
    PackageIdentity,
    ResolutionState,
    dependency_edge_metadata,
    dependency_node_metadata,
    package_identity_from_purl,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim


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
        purl = component.get("purl")
        spec = DependencySpec(
            identity=_identity_from_component(name, version, purl),
            scope=_cyclonedx_scope(component.get("scope")),
            resolution_state=ResolutionState.OBSERVED,
            source="CycloneDX",
            raw={"component": component},
        )
        component_id = _component_id("cyclonedx", name, version, purl)
        graph.add_node(
            Node(
                component_id,
                NodeType.EXTERNAL_PACKAGE,
                f"{name} {version}",
                dependency_node_metadata(spec)
                | {"source": "CycloneDX", "component": component},
            )
        )
        graph.add_edge(sbom_id, component_id, Relation.DESCRIBED_BY, **dependency_edge_metadata(spec))
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
        spec = DependencySpec(
            identity=_identity_from_component(name, version, purl),
            scope=DependencyScope.UNKNOWN,
            resolution_state=ResolutionState.OBSERVED,
            source="SPDX",
            raw={"package": package},
        )
        component_id = _component_id("spdx", name, version, purl)
        graph.add_node(
            Node(
                component_id,
                NodeType.EXTERNAL_PACKAGE,
                f"{name} {version}",
                dependency_node_metadata(spec) | {"source": "SPDX", "package": package},
            )
        )
        graph.add_edge(sbom_id, component_id, Relation.DESCRIBED_BY, **dependency_edge_metadata(spec))
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
            identity = package_identity_from_purl(purl, fallback_version=version)
            return f"pkg:{identity.ecosystem}:{identity.namespace or '_'}:{identity.name}:{identity.version or version}"
        except ImportError:
            return purl
    return f"sbom-component:{source}:{name}:{version}"


def _identity_from_component(
    name: str,
    version: str,
    purl: str | None,
) -> PackageIdentity:
    if purl:
        try:
            return package_identity_from_purl(purl, fallback_version=version)
        except ImportError:
            pass
    return PackageIdentity(Ecosystem.GENERIC, name, version=version)


def _cyclonedx_scope(value: object) -> DependencyScope:
    if value == "optional":
        return DependencyScope.OPTIONAL
    if value == "required":
        return DependencyScope.RUNTIME
    return DependencyScope.UNKNOWN


@dataclass(frozen=True)
class SbomClaimResult:
    sbom_id: str
    components: int
    claims_added: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "sbom_id": self.sbom_id,
            "components": self.components,
            "claims_added": self.claims_added,
        }


def cyclonedx_dependency_claims(subject_id: str, data: dict[str, Any]) -> list[DependencyClaim]:
    """Turn CycloneDX components into dependency claims for one subject.

    Each component is a concrete observed version of something present in the
    build, so it carries a version (from the PURL or ``version`` field) and feeds
    the reconciler as ``evidence="sbom"``. Unlike the legacy
    :func:`attach_cyclonedx_sbom` (which produced standalone EXTERNAL_PACKAGE
    nodes), these claims reconcile against other evidence on the same subject.
    """

    claims: list[DependencyClaim] = []
    for component in data.get("components", []):
        name = component.get("name")
        if not name:
            continue
        version = component.get("version")
        purl = component.get("purl")
        spec = DependencySpec(
            identity=_identity_from_component(str(name), str(version or ""), purl),
            scope=_cyclonedx_scope(component.get("scope")),
            resolution_state=ResolutionState.OBSERVED,
            source="CycloneDX",
            raw={
                "component": {
                    key: component.get(key)
                    for key in ("bom-ref", "type", "purl", "cpe", "version")
                    if component.get(key) is not None
                }
            },
        )
        claims.append(DependencyClaim(subject_id=subject_id, spec=spec, evidence="sbom"))
    return claims


def attach_cyclonedx_sbom_claims(
    graph: ProvenanceGraph,
    subject_id: str,
    sbom_path: str | Path,
) -> SbomClaimResult:
    """Attach a CycloneDX SBOM file to a subject as an SBOM node + claims.

    Adds the SBOM evidence node (and a ``described_by`` edge from the subject)
    and emits one dependency claim per component. The subject node must already
    exist in the graph.
    """

    path = Path(sbom_path)
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError(f"not a CycloneDX SBOM: {path}")

    sbom_id = f"sbom:{data.get('serialNumber') or path.name}"
    graph.add_node(
        Node(
            sbom_id,
            NodeType.SBOM,
            path.name,
            {
                "format": "CycloneDX",
                "bomFormat": data.get("bomFormat"),
                "specVersion": data.get("specVersion"),
                "source_path": str(path),
            },
        )
    )
    graph.add_edge(subject_id, sbom_id, Relation.DESCRIBED_BY)

    claims = cyclonedx_dependency_claims(subject_id, data)
    for claim in claims:
        add_dependency_claim(graph, claim)
    return SbomClaimResult(
        sbom_id=sbom_id,
        components=len(data.get("components", [])),
        claims_added=len(claims),
    )

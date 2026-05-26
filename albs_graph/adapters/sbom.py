from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote

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
        if component_id in graph.nodes:
            continue  # same NEVRA.arch already present (e.g. a noarch built per arch task)
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
        if component_id in graph.nodes:
            continue  # same NEVRA.arch already present
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
            # Include arch: a real multi-arch build SBOM lists the same NEVR per
            # architecture, and an arch-variant RPM is a distinct artifact, so the
            # node id must keep them apart (otherwise import collapses/conflicts).
            arch = identity.qualifiers.get("arch")
            suffix = f":{arch}" if arch else ""
            return (
                f"pkg:{identity.ecosystem}:{identity.namespace or '_'}:"
                f"{identity.name}:{identity.version or version}{suffix}"
            )
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
                },
                "licenses": _cyclonedx_licenses(component),
            },
        )
        claims.append(DependencyClaim(subject_id=subject_id, spec=spec, evidence="sbom"))
    return claims


def _cyclonedx_licenses(component: dict[str, Any]) -> list[str]:
    """Extract license ids / expressions from a CycloneDX component."""

    licenses: list[str] = []
    for entry in component.get("licenses", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("expression"):
            licenses.append(str(entry["expression"]))
        elif isinstance(entry.get("license"), dict):
            value = entry["license"].get("id") or entry["license"].get("name")
            if value:
                licenses.append(str(value))
    return licenses


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


@dataclass(frozen=True)
class SbomEnrichmentResult:
    """Outcome of matching a build SBOM's components to the build's binary RPMs."""

    sbom_id: str
    components: int
    matched: int
    cpes_set: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "sbom_id": self.sbom_id,
            "components": self.components,
            "matched": self.matched,
            "cpes_set": self.cpes_set,
        }


def enrich_graph_with_build_sbom(
    graph: ProvenanceGraph,
    sbom_path: str | Path,
    *,
    node_selector: Callable[[Node], bool] | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> SbomEnrichmentResult:
    """Enrich the build's *own* binary RPMs from a CycloneDX **build** SBOM.

    Unlike :func:`attach_cyclonedx_sbom_claims` (components-as-deps-of-a-subject),
    a build SBOM (e.g. ``alma-sbom build --build-id``) describes the build's RPMs
    themselves. We match each component to its binary-RPM node by ``(name, arch)``
    and attach real evidence: a ``described_by`` edge to the SBOM, the component
    PURL/SHA-256, and -- crucially for the ``identity`` axis -- the vendor-asserted
    CPE the SBOM carries (``cpe_source="almalinux_sbom"``, distinct from an NVD
    dictionary match). A node that already has a verified CPE is left untouched.
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

    # Match by (name, version-release, arch) so a merged graph or a duplicate
    # component set (two builds, same name, different versions) attaches the right
    # CPE/hash/PURL - not the first same-name component. An unambiguous (name,
    # arch) fallback still matches when a node or component lacks a parseable
    # version-release (e.g. minimal test nodes); an ambiguous fallback is skipped
    # rather than guessing.
    exact: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    by_name_arch: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
    for component in data.get("components", []):
        name = component.get("name")
        if not name:
            continue
        arch = _component_arch(component)
        vr = _component_version_release(component)
        if vr:
            exact.setdefault((str(name), vr, arch), component)
        by_name_arch.setdefault((str(name), arch), []).append(component)

    matched = 0
    cpes_set = 0
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        name = node.metadata.get("name")
        if not name:
            continue
        arch = node.metadata.get("arch") or node.metadata.get("build_arch")
        arch_str = str(arch) if arch else None
        node_vr = _node_version_release(node.metadata)
        component = exact.get((str(name), node_vr, arch_str)) if node_vr else None
        if component is None:
            candidates = by_name_arch.get((str(name), arch_str)) or by_name_arch.get(
                (str(name), None)
            )
            if candidates and len(candidates) == 1:
                component = candidates[0]  # unambiguous name+arch fallback
        if component is None:
            continue
        matched += 1
        graph.add_edge(node.id, sbom_id, Relation.DESCRIBED_BY)
        purl = component.get("purl")
        if purl:
            node.metadata["sbom_purl"] = purl
        sha256 = _component_sha256(component)
        if sha256:
            node.metadata["sbom_sha256"] = sha256
        cpe = component.get("cpe")
        if cpe and _apply_sbom_cpe(node.metadata, str(cpe)):
            cpes_set += 1
    if on_progress:
        on_progress(
            f"build SBOM matched {matched} RPMs, set {cpes_set} vendor CPEs from {path.name}"
        )
    return SbomEnrichmentResult(sbom_id, len(data.get("components", [])), matched, cpes_set)


def _component_arch(component: dict[str, Any]) -> str | None:
    match = re.search(r"[?&]arch=([^&]+)", str(component.get("purl") or ""))
    return match.group(1) if match else None


def _purl_version_release(purl: str) -> str | None:
    """The ``version-release`` (the part after ``@``, before qualifiers) of a PURL."""

    match = re.search(r"@([^?#]+)", purl)
    return unquote(match.group(1)) if match else None


def _component_version_release(component: dict[str, Any]) -> str | None:
    vr = _purl_version_release(str(component.get("purl") or ""))
    if vr:
        return vr
    # CycloneDX `version` may carry an epoch ("2:1.26.3-6.el10"); the RPM NEVRA
    # has no epoch in the version-release, so strip it for a symmetric key.
    version = str(component.get("version") or "")
    return version.split(":", 1)[-1] or None


def _node_version_release(metadata: dict[str, Any]) -> str | None:
    version = metadata.get("version")
    if version:
        release = metadata.get("release")
        return f"{version}-{release}" if release else str(version)
    return _purl_version_release(str(metadata.get("purl") or ""))


def _component_sha256(component: dict[str, Any]) -> str | None:
    for entry in component.get("hashes", []):
        if isinstance(entry, dict) and str(entry.get("alg", "")).upper().replace("-", "") == "SHA256":
            content = entry.get("content")
            return str(content) if content else None
    return None


def _apply_sbom_cpe(metadata: dict[str, Any], cpe: str) -> bool:
    """Set the vendor-asserted CPE on a node's security_identity (in place).

    The status is ``vendor_asserted`` - distinct from the ``verified`` an NVD
    dictionary match yields. Both establish a CPE identity (and both count toward
    the identity axis), but they are different evidence strengths, so the label
    stays honest: this is AlmaLinux asserting its own artifact's CPE, not a match
    confirmed against an external dictionary. Returns False if the node already
    carries a CPE (e.g. an NVD verification), so the SBOM never downgrades it.
    """

    identity = metadata.get("security_identity")
    if not isinstance(identity, dict):
        identity = {"cpe": None, "cpe_candidates": [], "cpe_status": "unresolved"}
        metadata["security_identity"] = identity
    if identity.get("cpe"):
        return False
    identity["cpe"] = cpe
    identity["cpe_status"] = "vendor_asserted"
    identity["cpe_source"] = "almalinux_sbom"
    candidates = identity.get("cpe_candidates")
    if isinstance(candidates, list):
        candidates.append({"cpe23": cpe, "source": "almalinux_sbom", "verified": True})
    return True

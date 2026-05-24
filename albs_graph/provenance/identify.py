"""``identify`` — trace every element behind a file in the distribution.

Given a path (``/usr/sbin/nginx``, a config, a doc, anything), find the package
that owns it and walk the provenance graph to report the full lineage: the
source package, git repo + commit, CAS source attestation, build task and
environment, SRPM, the binary RPM itself, its signature, release repository,
artifact CAS attestation, attached SBOM, and its resolved dependencies — i.e.
everything that took part in creating and installing that entity.

Ownership is resolved from (in order): an explicit ``owner_package``, an
injectable ``owner_lookup`` (e.g. wrapping ``rpm -qf`` / ``dnf provides`` on an
AlmaLinux host), the host ``rpm -qf`` if present, or a match against ELF paths
recorded by rung-4 payload analysis. The graph traversal itself is offline and
fully testable.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable

from albs_graph.model import NodeType, ProvenanceGraph, Relation

# role label -> the node types that carry it, in creation order.
_PROVENANCE_RELATIONS = (
    Relation.SIGNED_AS,
    Relation.RELEASED_TO,
    Relation.AUTHENTICATED_BY,
    Relation.DESCRIBED_BY,
)

OwnerLookup = Callable[[str], str | None]


@dataclass(frozen=True)
class IdentifiedElement:
    id: str
    type: str
    label: str
    role: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "type": self.type, "label": self.label, "role": self.role}


@dataclass(frozen=True)
class IdentifyReport:
    file: str
    package: str | None
    found: bool
    elements: list[IdentifiedElement] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    provenance_complete: bool = False
    security_context_complete: bool = False
    detail: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "package": self.package,
            "found": self.found,
            "provenance_complete": self.provenance_complete,
            "security_context_complete": self.security_context_complete,
            "elements": [element.to_dict() for element in self.elements],
            "dependencies": self.dependencies,
            "detail": self.detail,
        }


def identify_file(
    graph: ProvenanceGraph,
    filepath: str,
    *,
    owner_package: str | None = None,
    owner_lookup: OwnerLookup | None = None,
    arch: str | None = None,
) -> IdentifyReport:
    """Trace the provenance of the package that owns ``filepath``."""

    package = owner_package or _resolve_owner(graph, filepath, owner_lookup)
    if not package:
        return IdentifyReport(filepath, None, False, detail="could not determine owning package")

    rpm_node = _find_binary_rpm(graph, package, arch)
    if rpm_node is None:
        return IdentifyReport(
            filepath, package, False, detail=f"package {package} not present in this graph"
        )

    elements = _creation_chain(graph, rpm_node)
    elements += _evidence_elements(graph, rpm_node, {element.id for element in elements})
    report = graph.trust_path_report(rpm_node)
    dependencies = _dependencies(graph, rpm_node)
    return IdentifyReport(
        file=filepath,
        package=package,
        found=True,
        elements=elements,
        dependencies=dependencies,
        provenance_complete=report.provenance_complete,
        security_context_complete=report.security_context_complete,
    )


def _resolve_owner(
    graph: ProvenanceGraph, filepath: str, owner_lookup: OwnerLookup | None
) -> str | None:
    if owner_lookup is not None:
        owner = owner_lookup(filepath)
        if owner:
            return owner
    owner = _owner_from_elf_paths(graph, filepath)
    if owner:
        return owner
    return _host_rpm_qf(filepath)


def _owner_from_elf_paths(graph: ProvenanceGraph, filepath: str) -> str | None:
    needle = filepath.lstrip(".")
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        analysis = node.metadata.get("elf_analysis")
        if not isinstance(analysis, dict):
            continue
        paths: list[str] = []
        for key in ("static", "dlopen"):
            value = analysis.get(key)
            if isinstance(value, list):
                paths.extend(str(item) for item in value)
        if any(path.lstrip(".") == needle for path in paths):
            owner = node.metadata.get("name")
            if owner:
                return str(owner)
    return None


def _host_rpm_qf(filepath: str) -> str | None:
    if shutil.which("rpm") is None:
        return None
    try:
        process = subprocess.run(
            ["rpm", "-qf", "--qf", "%{NAME}", filepath],
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:  # pragma: no cover - race with which()
        return None
    name = process.stdout.strip()
    return name if process.returncode == 0 and name and "not owned" not in name else None


def _find_binary_rpm(graph: ProvenanceGraph, package: str, arch: str | None) -> str | None:
    candidates = [
        node
        for node in graph.find_by_type(NodeType.BINARY_RPM)
        if str(node.metadata.get("name") or "") == package
        or node.label.startswith(f"{package}-")
    ]
    if arch:
        candidates = [node for node in candidates if node.metadata.get("arch") == arch]
    if not candidates:
        return None
    candidates.sort(key=lambda node: (node.metadata.get("arch") != "x86_64", node.id))
    return candidates[0].id


def _creation_chain(graph: ProvenanceGraph, rpm_node: str) -> list[IdentifiedElement]:
    roles = {
        str(NodeType.SOURCE_PACKAGE): "source_package",
        str(NodeType.GIT_REPOSITORY): "git_repository",
        str(NodeType.GIT_COMMIT): "git_commit",
        str(NodeType.CAS_ATTESTATION): "cas_source_attestation",
        str(NodeType.BUILD_TASK): "build_task",
        str(NodeType.BINARY_RPM): "binary_rpm",
    }
    elements: list[IdentifiedElement] = []
    for node_id in graph.source_to_artifact_path(rpm_node):
        node = graph.nodes[node_id]
        elements.append(
            IdentifiedElement(
                node.id, str(node.type), node.label, roles.get(str(node.type), "element")
            )
        )
    # build environment + SRPM hang off the build task in the chain.
    build_tasks = [e.id for e in elements if e.role == "build_task"]
    for build_task in build_tasks:
        for edge in graph.outgoing(build_task, Relation.BUILT_IN):
            node = graph.nodes[edge.target]
            elements.append(IdentifiedElement(node.id, str(node.type), node.label, "build_environment"))
        for edge in graph.outgoing(build_task, Relation.PRODUCES):
            node = graph.nodes[edge.target]
            if node.type == NodeType.SRPM:
                elements.append(IdentifiedElement(node.id, str(node.type), node.label, "srpm"))
    return elements


def _evidence_elements(
    graph: ProvenanceGraph, rpm_node: str, already: set[str]
) -> list[IdentifiedElement]:
    role_by_type = {
        str(NodeType.SIGNATURE): "signature",
        str(NodeType.REPOSITORY_RELEASE): "repository_release",
        str(NodeType.CAS_ATTESTATION): "cas_artifact_attestation",
        str(NodeType.SBOM): "sbom",
    }
    elements: list[IdentifiedElement] = []
    for relation in _PROVENANCE_RELATIONS:
        for edge in graph.outgoing(rpm_node, relation):
            if edge.target in already:
                continue
            already.add(edge.target)
            node = graph.nodes[edge.target]
            elements.append(
                IdentifiedElement(
                    node.id, str(node.type), node.label, role_by_type.get(str(node.type), "evidence")
                )
            )
    return elements


def _dependencies(graph: ProvenanceGraph, rpm_node: str) -> list[str]:
    names: set[str] = set()
    for relation in (Relation.REQUIRES_RUNTIME, Relation.DECLARES_DEPENDENCY):
        for edge in graph.outgoing(rpm_node, relation):
            node = graph.nodes[edge.target]
            names.add(str(node.metadata.get("name") or node.label))
    return sorted(names)

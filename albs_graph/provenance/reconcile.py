"""Multi-evidence dependency reconciliation.

The graph does not collapse a dependency into a single resolved edge. Instead
every evidence source -- a manifest declaration, a lockfile pin, a resolver
run, an RPM header soname, an ELF ``DT_NEEDED`` entry -- contributes a
:class:`DependencyClaim`. The reconciler groups claims that describe the *same
logical dependency* (same subject, same package coordinate, same context) and
emits a ``DEPENDENCY_RESOLUTION`` verdict node plus ``CONFLICTS_WITH`` /
``CORROBORATES`` edges between the underlying claims.

Crucially, the reconciler does **not** evaluate version ranges. Deciding
whether ``3.0.9`` satisfies ``>=3.2`` is the authoritative resolver's job (see
``albs_graph.dependency.resolver``); reimplementing per-ecosystem version math
here is exactly the mistake the architecture avoids. The reconciler only
detects *cross-source* disagreement it can establish soundly: different
concrete versions, mismatched linkage, and artifacts shipping code that no
declaration or resolution mentions. Range violations are surfaced when a
resolver *asserts* them via the ``range_satisfied=False`` claim flag.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from albs_graph.dependency.model import (
    DependencySpec,
    Linkage,
    ResolutionState,
    dependency_edge_metadata,
    dependency_node_metadata,
)
from albs_graph.dependency.resolver import ResolverResult
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation


class Agreement(StrEnum):
    """The verdict for a reconciled logical dependency."""

    CONSENSUS = "consensus"  # >=2 independent evidence sources agree on one version
    COMPATIBLE = "compatible"  # exactly one concrete version, nothing contradicts it
    CONFLICT = "conflict"  # sources disagree (see ConflictKind)
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # no concrete version anywhere


class ConflictKind(StrEnum):
    VERSION_DRIFT = "version_drift"  # sources assert different concrete versions
    RANGE_VIOLATION = "range_violation"  # resolver flagged version outside declared range
    PRESENCE_UNDECLARED = "presence_undeclared"  # shipped/observed but never declared/resolved
    LINKAGE_MISMATCH = "linkage_mismatch"  # sources disagree on static vs dynamic
    IDENTITY_MISMATCH = "identity_mismatch"  # same coordinate maps to different identities


# How a piece of evidence relates to the dependency lifecycle. Used to tell a
# manifest declaration apart from a thing actually present in a built artifact.
_DECLARED_CLASSES = frozenset({"declared", "locked", "resolved"})
_ARTIFACT_CLASS = "artifact"


@dataclass(frozen=True)
class DependencyClaim:
    """One source's observation of a dependency relationship.

    ``subject_id`` is the consuming artifact (e.g. a binary RPM node). ``spec``
    carries the package identity (including asserted version, if any), scope,
    linkage and resolution state. ``evidence`` records which rung produced it.
    """

    subject_id: str
    spec: DependencySpec
    evidence: str
    range_satisfied: bool | None = None

    @property
    def asserted_version(self) -> str | None:
        return self.spec.identity.version

    @property
    def evidence_class(self) -> str:
        return _evidence_class(self.evidence, self.spec.resolution_state)


@dataclass(frozen=True)
class DependencyConflict:
    subject_id: str
    coordinate: str
    kind: ConflictKind
    versions: tuple[str, ...]
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject_id,
            "coordinate": self.coordinate,
            "kind": str(self.kind),
            "versions": list(self.versions),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class ReconciliationReport:
    resolutions: int
    agreements: dict[str, int]
    conflicts: list[DependencyConflict] = field(default_factory=list)

    @property
    def conflict_count(self) -> int:
        return len(self.conflicts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolutions": self.resolutions,
            "agreements": self.agreements,
            "conflict_count": self.conflict_count,
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
        }


def claim_node_id(claim: DependencyClaim) -> str:
    coordinate = claim.spec.identity.coordinates()
    version = claim.asserted_version or "any"
    return f"claim:{_safe(claim.subject_id)}|{_safe(coordinate)}|{_safe(claim.evidence)}|{_safe(version)}"


def add_dependency_claim(graph: ProvenanceGraph, claim: DependencyClaim) -> str:
    """Add a single claim node and link it from its subject.

    The subject node must already exist in the graph.
    """

    node_id = claim_node_id(claim)
    context_key = _context_key(claim.spec.context.to_dict())
    metadata = dependency_node_metadata(claim.spec) | {
        "kind": "dependency_claim",
        "subject": claim.subject_id,
        "evidence": claim.evidence,
        "evidence_class": claim.evidence_class,
        "asserted_version": claim.asserted_version,
        "context_key": context_key,
        "group_key": _group_key(claim, context_key),
    }
    if claim.range_satisfied is not None:
        metadata["range_satisfied"] = claim.range_satisfied
    graph.add_node(Node(node_id, NodeType.DEPENDENCY_CLAIM, claim.spec.identity.name, metadata))
    edge_metadata = dependency_edge_metadata(claim.spec) | {"evidence": claim.evidence}
    graph.add_edge(claim.subject_id, node_id, Relation.DECLARES_DEPENDENCY, **edge_metadata)
    return node_id


def claims_from_resolver_result(result: ResolverResult, subject_id: str) -> list[DependencyClaim]:
    """Turn a resolver's output into claims for one consuming subject."""

    tool = result.tool
    claims: list[DependencyClaim] = []
    for spec in result.resolved:
        claims.append(DependencyClaim(subject_id, spec, evidence=f"resolver:{tool}"))
    for spec in result.unresolved:
        claims.append(DependencyClaim(subject_id, spec, evidence=f"resolver:{tool}:unresolved"))
    return claims


def add_resolver_result(graph: ProvenanceGraph, result: ResolverResult, subject_id: str) -> list[str]:
    """Merge a resolver result into the graph as dependency claims."""

    return [
        add_dependency_claim(graph, claim)
        for claim in claims_from_resolver_result(result, subject_id)
    ]


def reconcile_dependency_claims(graph: ProvenanceGraph) -> ReconciliationReport:
    """Group claim nodes and write resolution verdicts + conflict edges in place."""

    groups: dict[str, list[Node]] = defaultdict(list)
    for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM):
        group_key = str(node.metadata.get("group_key", node.id))
        groups[group_key].append(node)

    agreements: Counter[str] = Counter()
    conflicts: list[DependencyConflict] = []
    resolution_count = 0

    for group_key in sorted(groups):
        members = sorted(groups[group_key], key=lambda node: node.id)
        verdict, kinds, chosen = _evaluate_group(members)
        agreements[str(verdict)] += 1
        resolution_count += 1

        subject_id = str(members[0].metadata.get("subject", ""))
        coordinate = _coordinate_of(members[0])
        resolution_id = f"dep-res:{group_key}"
        evidence_sources = sorted({str(node.metadata.get("evidence", "")) for node in members})
        versions = sorted({v for node in members if (v := _version_of(node)) is not None})

        graph.add_node(
            Node(
                resolution_id,
                NodeType.DEPENDENCY_RESOLUTION,
                coordinate,
                {
                    "kind": "dependency_resolution",
                    "subject": subject_id,
                    "coordinate": coordinate,
                    "agreement": str(verdict),
                    "chosen_version": chosen,
                    "conflict_kinds": [str(kind) for kind in kinds],
                    "evidence": evidence_sources,
                    "versions": versions,
                    "claim_count": len(members),
                },
            )
        )
        for node in members:
            graph.add_edge(resolution_id, node.id, Relation.OBSERVED_AS, evidence=node.metadata.get("evidence"))

        _link_claims(graph, members)

        if kinds:
            conflicts.append(
                DependencyConflict(
                    subject_id=subject_id,
                    coordinate=coordinate,
                    kind=kinds[0],
                    versions=tuple(versions),
                    evidence=tuple(evidence_sources),
                )
            )

    return ReconciliationReport(
        resolutions=resolution_count,
        agreements=dict(agreements),
        conflicts=conflicts,
    )


def _evaluate_group(members: list[Node]) -> tuple[Agreement, list[ConflictKind], str | None]:
    versions = {v for node in members if (v := _version_of(node)) is not None}
    linkages = {
        linkage
        for node in members
        if (linkage := str(node.metadata.get("linkage", Linkage.UNKNOWN))) != str(Linkage.UNKNOWN)
    }
    classes = {str(node.metadata.get("evidence_class", "")) for node in members}
    range_violated = any(node.metadata.get("range_satisfied") is False for node in members)

    kinds: list[ConflictKind] = []
    if len(versions) > 1:
        kinds.append(ConflictKind.VERSION_DRIFT)
    if range_violated:
        kinds.append(ConflictKind.RANGE_VIOLATION)
    if len(linkages) > 1:
        kinds.append(ConflictKind.LINKAGE_MISMATCH)
    if _ARTIFACT_CLASS in classes and not (classes & _DECLARED_CLASSES):
        kinds.append(ConflictKind.PRESENCE_UNDECLARED)

    if kinds:
        return Agreement.CONFLICT, kinds, None
    if not versions:
        return Agreement.INSUFFICIENT_EVIDENCE, [], None

    chosen = next(iter(versions))
    sources_with_version = {
        str(node.metadata.get("evidence", "")) for node in members if _version_of(node) == chosen
    }
    if len(sources_with_version) >= 2:
        return Agreement.CONSENSUS, [], chosen
    return Agreement.COMPATIBLE, [], chosen


def _link_claims(graph: ProvenanceGraph, members: list[Node]) -> None:
    """Add CORROBORATES / CONFLICTS_WITH edges between claim pairs (one direction)."""

    for i, left in enumerate(members):
        for right in members[i + 1 :]:
            left_version = _version_of(left)
            right_version = _version_of(right)
            if left_version is not None and right_version is not None:
                if left_version == right_version:
                    graph.add_edge(left.id, right.id, Relation.CORROBORATES, on="version")
                else:
                    graph.add_edge(
                        left.id,
                        right.id,
                        Relation.CONFLICTS_WITH,
                        kind=str(ConflictKind.VERSION_DRIFT),
                    )
            left_linkage = str(left.metadata.get("linkage", Linkage.UNKNOWN))
            right_linkage = str(right.metadata.get("linkage", Linkage.UNKNOWN))
            if (
                left_linkage != str(Linkage.UNKNOWN)
                and right_linkage != str(Linkage.UNKNOWN)
                and left_linkage != right_linkage
            ):
                graph.add_edge(
                    left.id,
                    right.id,
                    Relation.CONFLICTS_WITH,
                    kind=str(ConflictKind.LINKAGE_MISMATCH),
                )


def _version_of(node: Node) -> str | None:
    value = node.metadata.get("asserted_version")
    return str(value) if value else None


def _coordinate_of(node: Node) -> str:
    dependency = node.metadata.get("dependency")
    if isinstance(dependency, dict):
        identity = dependency.get("identity")
        if isinstance(identity, dict):
            ecosystem = identity.get("ecosystem", "generic")
            namespace = identity.get("namespace")
            name = identity.get("name", node.label)
            prefix = f"{namespace}/" if namespace else ""
            return f"{ecosystem}:{prefix}{name}"
    return node.label


def _evidence_class(evidence: str, state: ResolutionState) -> str:
    lowered = evidence.lower()
    if any(token in lowered for token in ("rpm_header", "soname", "elf", "needed", "dlopen", "bom")):
        return _ARTIFACT_CLASS
    if "lockfile" in lowered or state == ResolutionState.LOCKED:
        return "locked"
    if "resolver" in lowered or state == ResolutionState.RESOLVED:
        return "resolved"
    if "provides" in lowered or state == ResolutionState.PROVIDED:
        return "provided"
    return "declared"


def _group_key(claim: DependencyClaim, context_key: str) -> str:
    identity = claim.spec.identity
    namespace = identity.namespace or ""
    return f"{_safe(claim.subject_id)}|{identity.ecosystem}/{namespace}/{identity.name}|{context_key}"


def _context_key(context: dict[str, Any]) -> str:
    if not context:
        return "default"
    parts = []
    for key, value in sorted(context.items()):
        if isinstance(value, list):
            value = ",".join(str(item) for item in value)
        parts.append(f"{key}={value}")
    return "&".join(parts)


def _safe(value: str) -> str:
    return value.replace(" ", "_").replace("|", "_")

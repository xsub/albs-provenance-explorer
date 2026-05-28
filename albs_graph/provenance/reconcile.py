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
from typing import Any

from albs_graph.nevra import distro_generation
from albs_graph.vercmp import version_compare
from albs_graph.dependency.model import (
    DependencySpec,
    Linkage,
    ResolutionState,
    dependency_edge_metadata,
    dependency_node_metadata,
)
from albs_graph.dependency.resolver import ResolverResult
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from .reconcile_rules import (
    Agreement,
    ConflictKind,
    ContextIssue,
    ResolutionGroup,
    distinct_versions,
    evaluate_group,
    version_of,
)

# Re-exported for stable import paths (coverage / tests import these from here).
__all__ = [
    "Agreement",
    "ConflictKind",
    "ContextIssue",
    "DependencyClaim",
    "DependencyConflict",
    "ReconciliationReport",
    "ResolutionDetail",
    "add_dependency_claim",
    "add_resolver_result",
    "claim_node_id",
    "claims_from_resolver_result",
    "reconcile_dependency_claims",
    "resolution_details",
]


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
    context_issues: dict[str, int] = field(default_factory=dict)

    @property
    def conflict_count(self) -> int:
        return len(self.conflicts)

    @property
    def cross_distro_count(self) -> int:
        """Resolutions whose deps were resolved against a different distro.

        Counted as a *context issue*, independent of the agreement verdict: such
        a resolution can still be CONSENSUS on its (foreign-distro) version.
        """

        return self.context_issues.get(str(ContextIssue.CROSS_DISTRO), 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolutions": self.resolutions,
            "agreements": self.agreements,
            "conflict_count": self.conflict_count,
            "context_issues": self.context_issues,
            "cross_distro_count": self.cross_distro_count,
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
        }


@dataclass(frozen=True)
class ResolutionDetail:
    """One reconciled dependency group, for verbose per-item reporting."""

    subject_id: str
    coordinate: str
    agreement: str
    versions: tuple[str, ...]
    evidence: tuple[str, ...]
    context_issue: str | None = None
    distro_mismatch: bool = False
    subject_distro: str | None = None
    dependency_distros: tuple[str, ...] = ()


def resolution_details(graph: ProvenanceGraph) -> list[ResolutionDetail]:
    """Read-only listing of each resolution group written by the reconciler.

    Used by verbose CLI output to expand the "Reconciled dependencies: N"
    summary into the concrete coordinates, verdicts and evidence sources.
    """

    details: list[ResolutionDetail] = []
    for node in graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION):
        md = node.metadata
        details.append(
            ResolutionDetail(
                subject_id=str(md.get("subject", "")),
                coordinate=str(md.get("coordinate", node.label)),
                agreement=str(md.get("agreement", "")),
                versions=tuple(str(v) for v in (md.get("versions") or [])),
                evidence=tuple(str(e) for e in (md.get("evidence") or [])),
                context_issue=(str(ci) if (ci := md.get("context_issue")) else None),
                distro_mismatch=bool(md.get("distro_mismatch")),
                subject_distro=(str(sd) if (sd := md.get("subject_distro")) else None),
                dependency_distros=tuple(str(d) for d in (md.get("dependency_distros") or [])),
            )
        )
    return sorted(details, key=lambda d: (d.subject_id, d.coordinate))


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
    """Group claim nodes and write resolution verdicts + conflict edges in place.

    **Idempotent.** Any prior reconciliation state (``DEPENDENCY_RESOLUTION``
    nodes + their ``OBSERVED_AS`` edges, plus ``CORROBORATES`` /
    ``CONFLICTS_WITH`` edges between claims) is purged before rebuilding. So
    re-running -- on a fresh graph, or on a saved graph after new evidence
    lands -- never duplicates edges nor raises ``Conflicting node definition
    for dep-res:...``.
    """

    _purge_prior_reconciliation(graph)

    groups: dict[str, list[Node]] = defaultdict(list)
    for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM):
        group_key = str(node.metadata.get("group_key", node.id))
        groups[group_key].append(node)

    # PRESENCE_UNDECLARED is only meaningful for a subject that has declaration
    # evidence somewhere: an artifact-observed dependency is "undeclared" only
    # relative to a manifest/lockfile/resolver that could have declared it. With
    # header-only ingest (no declaration source at all) a lone observation is
    # not a conflict, just unreconciled evidence.
    subjects_with_declarations = {
        str(node.metadata.get("subject", ""))
        for nodes in groups.values()
        for node in nodes
        if str(node.metadata.get("evidence_class", "")) in _DECLARED_CLASSES
    }

    agreements: Counter[str] = Counter()
    context_issue_counts: Counter[str] = Counter()
    conflicts: list[DependencyConflict] = []
    resolution_count = 0

    for group_key in sorted(groups):
        members = sorted(groups[group_key], key=lambda node: node.id)
        subject_id = str(members[0].metadata.get("subject", ""))
        group = _build_group(
            members,
            subject_id=subject_id,
            subject_has_declarations=subject_id in subjects_with_declarations,
            subject_distro=_subject_distro(graph, subject_id),
        )
        # All policy lives in the rules now: version drift, declared-range
        # violations, linkage mismatches, presence gaps and (orthogonally)
        # cross-distro context. The combiner folds their findings into one verdict.
        result = evaluate_group(group)
        kinds = result.conflict_kinds
        context_issue = str(result.context_issue) if result.context_issue else None

        agreements[str(result.agreement)] += 1
        if context_issue is not None:
            context_issue_counts[context_issue] += 1
        resolution_count += 1

        coordinate = _coordinate_of(members[0])
        resolution_id = f"dep-res:{group_key}"
        evidence_sources = sorted({str(node.metadata.get("evidence", "")) for node in members})
        versions = sorted(set(group.version_strings))

        graph.add_node(
            Node(
                resolution_id,
                NodeType.DEPENDENCY_RESOLUTION,
                coordinate,
                {
                    "kind": "dependency_resolution",
                    "subject": subject_id,
                    "coordinate": coordinate,
                    "agreement": str(result.agreement),
                    "context_issue": context_issue,
                    "chosen_version": result.chosen_version,
                    "conflict_kinds": [str(kind) for kind in kinds],
                    "evidence": evidence_sources,
                    "versions": versions,
                    "claim_count": len(members),
                    "distro_mismatch": result.context_issue == ContextIssue.CROSS_DISTRO,
                    "subject_distro": group.subject_distro,
                    "dependency_distros": list(group.dependency_distros),
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
        context_issues=dict(context_issue_counts),
    )


def _build_group(
    members: list[Node],
    *,
    subject_id: str,
    subject_has_declarations: bool,
    subject_distro: str | None,
) -> ResolutionGroup:
    """Precompute the per-group facts the reconciliation rules operate on.

    All graph/metadata reading happens here once; the rules then see only plain
    fields (see :class:`ResolutionGroup`). A soname coordinate (``libz.so.1``)
    lives in a different space than a package, so it is flagged here and the
    presence rule skips it.
    """

    version_strings = tuple(v for node in members if (v := version_of(node)) is not None)
    linkages = frozenset(
        linkage
        for node in members
        if (linkage := str(node.metadata.get("linkage", Linkage.UNKNOWN))) != str(Linkage.UNKNOWN)
    )
    classes = {str(node.metadata.get("evidence_class", "")) for node in members}
    coordinate_name = str(members[0].metadata.get("name", ""))
    dependency_distros = tuple(
        sorted({tag for v in version_strings if (tag := distro_generation(v))})
    )
    return ResolutionGroup(
        members=tuple(members),
        subject_id=subject_id,
        subject_has_declarations=subject_has_declarations,
        subject_distro=subject_distro,
        version_strings=version_strings,
        # Semantic equivalence classes (rpmvercmp), not raw strings: "1.01" and
        # "1.1" are the same version, so they do not count as drift.
        version_classes=tuple(distinct_versions(list(version_strings))),
        linkages=linkages,
        has_artifact_evidence=_ARTIFACT_CLASS in classes,
        has_declared_class=bool(classes & _DECLARED_CLASSES),
        is_soname_group=".so" in coordinate_name,
        dependency_distros=dependency_distros,
        range_satisfied_false=any(
            node.metadata.get("range_satisfied") is False for node in members
        ),
    )


def _link_claims(graph: ProvenanceGraph, members: list[Node]) -> None:
    """Add CORROBORATES / CONFLICTS_WITH edges between claim pairs (one direction)."""

    for i, left in enumerate(members):
        for right in members[i + 1 :]:
            left_version = version_of(left)
            right_version = version_of(right)
            if left_version is not None and right_version is not None:
                # Use rpmvercmp, not string equality, so 1.01 and 1.1 corroborate
                # (matching the verdict path) instead of a false VERSION_DRIFT edge.
                if version_compare(left_version, right_version) == 0:
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


def _subject_distro(graph: ProvenanceGraph, subject_id: str) -> str | None:
    """The build's distro generation, read from the subject RPM's release/EVR."""

    node = graph.nodes.get(subject_id)
    if node is None:
        return None
    for value in (node.metadata.get("release"), node.metadata.get("version"), node.label):
        tag = distro_generation(str(value) if value is not None else None)
        if tag:
            return tag
    return None


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
    # An SBOM is a resolved/observed component list, not raw artifact inspection.
    # Check it before the "bom" artifact token so "sbom" is not misread as ELF
    # binary analysis (which "static_bom" et al. genuinely are). A soname_provider
    # claim is the *resolved* package behind a soname, so it is resolved-class too
    # (checked before the "soname" artifact token).
    if "sbom" in lowered or "provider" in lowered:
        return "resolved"
    # RPM REQUIRES are the package's declared dependency contract (often
    # versioned/constrained), distinct from auto-derived soname/ELF artifact
    # facts -- so they are a declaration baseline, not an artifact observation.
    if "rpm_header_requires" in lowered:
        return "declared"
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


def _purge_prior_reconciliation(graph: ProvenanceGraph) -> None:
    """Remove DEPENDENCY_RESOLUTION nodes + reconcile-emitted edges in place.

    Reconciliation is rebuild-from-claims; the previous run's output must not
    leak into the next one (duplicate OBSERVED_AS / CORROBORATES edges, or a
    stale resolution node whose verdict no longer matches the new evidence).
    Claim nodes themselves are preserved -- they are the *inputs* to
    reconciliation, owned by the adapters that emitted them.
    """

    for node in list(graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION)):
        graph.remove_node(node.id)
    graph.remove_edges_where(
        lambda edge: edge.relation in (Relation.CORROBORATES, Relation.CONFLICTS_WITH)
    )

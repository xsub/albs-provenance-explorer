"""Reconciliation policy as independent rules.

The reconciler used to decide every verdict inside one ``_evaluate_group``
function: version drift, declared-range violations, linkage mismatches,
artifact-presence gaps, and (latterly) cross-distro context. That made it a
single growing policy hub. This module factors each policy into a small
:class:`ReconciliationRule` that inspects a precomputed :class:`ResolutionGroup`
and emits a :class:`RuleFinding` (conflict kinds and/or context issues) -- so a
new policy is a new rule object, independently testable, rather than another
branch in a monolith.

The vocabulary types (:class:`Agreement`, :class:`ConflictKind`,
:class:`ContextIssue`) live here too, so rules and the verdict combiner can share
them without importing ``reconcile`` (which would cycle). ``reconcile`` imports
and re-exports them, so their public import path is unchanged.

The split is deliberate: a **rule** answers "is this group internally
consistent / context-valid?" and emits findings; the **combiner**
(:func:`evaluate_group`) folds the findings plus the version-agreement question
into a single :class:`EvaluationResult`. Coverage policy lives elsewhere again
(it reads the agreement + context issue off the resolution node).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from albs_graph.model import Node
from albs_graph.vercmp import version_compare


class Agreement(StrEnum):
    """The verdict for a reconciled logical dependency.

    Agreement answers *only* "do the evidence sources agree on a version?" It is
    deliberately orthogonal to whether the dependency is valid for the subject's
    build context: a version-consistent CONSENSUS can still be the wrong distro
    generation. That second axis is a :class:`ContextIssue`, not an agreement
    verdict, so coverage policy can weigh the two independently.
    """

    CONSENSUS = "consensus"  # >=2 independent evidence sources agree on one version
    COMPATIBLE = "compatible"  # exactly one concrete version, nothing contradicts it
    CONFLICT = "conflict"  # sources disagree (see ConflictKind)
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # no concrete version anywhere


class ContextIssue(StrEnum):
    """A dependency that is internally consistent yet invalid for the subject.

    Orthogonal to :class:`Agreement`: the sources can fully agree (CONSENSUS)
    while the resolved package is still wrong for the build's context. A
    resolution carrying a context issue is treated as unresolved by coverage.
    """

    CROSS_DISTRO = "cross_distro"  # resolved against a different distro generation than the build


class ConflictKind(StrEnum):
    VERSION_DRIFT = "version_drift"  # sources assert different concrete versions
    RANGE_VIOLATION = "range_violation"  # resolver flagged version outside declared range
    PRESENCE_UNDECLARED = "presence_undeclared"  # shipped/observed but never declared/resolved
    LINKAGE_MISMATCH = "linkage_mismatch"  # sources disagree on static vs dynamic
    IDENTITY_MISMATCH = "identity_mismatch"  # same coordinate maps to different identities


@dataclass(frozen=True)
class ResolutionGroup:
    """Precomputed facts about one logical-dependency group, shared by all rules.

    The graph-touching work (reading claim metadata, distro extraction, version
    equivalence-classing) is done once by the caller; rules see only plain
    fields, which keeps each rule pure and trivially testable.
    """

    members: tuple[Node, ...]
    subject_id: str
    subject_has_declarations: bool
    subject_distro: str | None
    version_strings: tuple[str, ...]  # every concrete version present (with repeats)
    version_classes: tuple[str, ...]  # distinct versions under rpmvercmp
    linkages: frozenset[str]  # the non-unknown linkages asserted
    has_artifact_evidence: bool  # something is present only in a built artifact
    has_declared_class: bool  # something is a declaration/lockfile/resolver claim
    is_soname_group: bool  # the coordinate is a soname (libz.so.1), not a package
    dependency_distros: tuple[str, ...]  # distro generations of the resolved versions
    range_satisfied_false: bool  # a resolver explicitly flagged range_satisfied=False


@dataclass(frozen=True)
class RuleFinding:
    """What one rule emits: conflict kinds and/or context issues (often empty)."""

    conflict_kinds: tuple[ConflictKind, ...] = ()
    context_issues: tuple[ContextIssue, ...] = ()


class ReconciliationRule(Protocol):
    """A single reconciliation policy: inspect a group, emit findings.

    ``name`` is a read-only property so a frozen dataclass field satisfies it.
    """

    @property
    def name(self) -> str: ...

    def check(self, group: ResolutionGroup) -> RuleFinding: ...


@dataclass(frozen=True)
class VersionDriftRule:
    name: str = "version_drift"

    def check(self, group: ResolutionGroup) -> RuleFinding:
        # More than one semantic version-equivalence class => sources disagree.
        if len(group.version_classes) > 1:
            return RuleFinding(conflict_kinds=(ConflictKind.VERSION_DRIFT,))
        return RuleFinding()


@dataclass(frozen=True)
class RangeViolationRule:
    name: str = "range_violation"

    def check(self, group: ResolutionGroup) -> RuleFinding:
        # Either a resolver asserted the violation, or a declared relational
        # constraint is unmet by a concrete version we can soundly check.
        if group.range_satisfied_false or _constraint_violated(
            group.members, list(group.version_strings)
        ):
            return RuleFinding(conflict_kinds=(ConflictKind.RANGE_VIOLATION,))
        return RuleFinding()


@dataclass(frozen=True)
class LinkageMismatchRule:
    name: str = "linkage_mismatch"

    def check(self, group: ResolutionGroup) -> RuleFinding:
        if len(group.linkages) > 1:
            return RuleFinding(conflict_kinds=(ConflictKind.LINKAGE_MISMATCH,))
        return RuleFinding()


@dataclass(frozen=True)
class PresenceUndeclaredRule:
    name: str = "presence_undeclared"

    def check(self, group: ResolutionGroup) -> RuleFinding:
        # Something present in a built artifact that no declaration/resolution
        # mentions -- but only meaningful when the subject has declarations at all,
        # and never for a soname (a different coordinate space than packages).
        if (
            group.subject_has_declarations
            and group.has_artifact_evidence
            and not group.is_soname_group
            and not group.has_declared_class
        ):
            return RuleFinding(conflict_kinds=(ConflictKind.PRESENCE_UNDECLARED,))
        return RuleFinding()


@dataclass(frozen=True)
class CrossDistroRule:
    name: str = "cross_distro"

    def check(self, group: ResolutionGroup) -> RuleFinding:
        # The resolved deps belong to a different distro generation than the build
        # (e.g. an el9 build resolved on an el10 host). Not a cross-source conflict
        # -- the sources agree -- so it is a context issue, not a ConflictKind.
        if (
            group.subject_distro
            and group.dependency_distros
            and group.subject_distro not in group.dependency_distros
        ):
            return RuleFinding(context_issues=(ContextIssue.CROSS_DISTRO,))
        return RuleFinding()


# Order matters: the first conflict kind becomes the reported DependencyConflict
# kind, so this preserves the historical version -> range -> linkage -> presence
# precedence. Cross-distro is last and emits a context issue, not a conflict.
DEFAULT_RULES: tuple[ReconciliationRule, ...] = (
    VersionDriftRule(),
    RangeViolationRule(),
    LinkageMismatchRule(),
    PresenceUndeclaredRule(),
    CrossDistroRule(),
)


@dataclass(frozen=True)
class EvaluationResult:
    agreement: Agreement
    conflict_kinds: tuple[ConflictKind, ...]
    context_issue: ContextIssue | None
    chosen_version: str | None


def evaluate_group(
    group: ResolutionGroup,
    rules: tuple[ReconciliationRule, ...] = DEFAULT_RULES,
) -> EvaluationResult:
    """Fold the rule findings plus the version-agreement question into a verdict.

    Conflicts win (any conflict kind -> CONFLICT); otherwise the verdict is the
    version-agreement level. Context issues are independent of the verdict -- a
    cross-distro group can still be honest CONSENSUS -- so they ride alongside.
    """

    conflict_kinds: list[ConflictKind] = []
    context_issues: list[ContextIssue] = []
    for rule in rules:
        finding = rule.check(group)
        conflict_kinds.extend(finding.conflict_kinds)
        context_issues.extend(finding.context_issues)

    context_issue = context_issues[0] if context_issues else None

    if conflict_kinds:
        return EvaluationResult(Agreement.CONFLICT, tuple(conflict_kinds), context_issue, None)
    if not group.version_classes:
        return EvaluationResult(Agreement.INSUFFICIENT_EVIDENCE, (), context_issue, None)

    chosen = group.version_classes[0]
    agreement = (
        Agreement.CONSENSUS if _sources_agreeing(group, chosen) >= 2 else Agreement.COMPATIBLE
    )
    return EvaluationResult(agreement, (), context_issue, chosen)


def version_of(node: Node) -> str | None:
    value = node.metadata.get("asserted_version")
    return str(value) if value else None


def distinct_versions(versions: list[str]) -> list[str]:
    """Representatives of the semantic version-equivalence classes (rpmvercmp)."""

    reps: list[str] = []
    for version in versions:
        if not any(version_compare(version, rep) == 0 for rep in reps):
            reps.append(version)
    return reps


def _sources_agreeing(group: ResolutionGroup, chosen: str) -> int:
    """Distinct evidence sources whose concrete version equals ``chosen``."""

    return len(
        {
            str(node.metadata.get("evidence", ""))
            for node in group.members
            if (current := version_of(node)) is not None and version_compare(current, chosen) == 0
        }
    )


# Relational constraint, e.g. "openssl-libs >= 1:3.0.7" -> (">=", "1:3.0.7").
_CONSTRAINT = re.compile(r"(>=|<=|>|<)\s*([0-9][^\s,)\]]*)")


def _constraint_violated(members: tuple[Node, ...], concrete_versions: list[str]) -> bool:
    """True if a declared relational constraint is unmet by a concrete version.

    Detects e.g. a manifest requiring ``>= 3.2`` while the shipped/resolved
    version is ``3.0.7`` (the AlmaLinux-backport range case). Only relational
    operators are evaluated (``=`` provides/config are skipped to avoid noise),
    and epochs are stripped before comparison.
    """

    if not concrete_versions:
        return False
    for node in members:
        match = _CONSTRAINT.search(_requested_of(node))
        if not match:
            continue
        operator, bound = match.group(1), match.group(2)
        if any(not _satisfies(version, operator, bound) for version in concrete_versions):
            return True
    return False


def _requested_of(node: Node) -> str:
    dependency = node.metadata.get("dependency")
    if isinstance(dependency, dict):
        return str(dependency.get("requested") or "")
    return ""


def _satisfies(version: str, operator: str, bound: str) -> bool:
    comparison = version_compare(_strip_epoch(version), _strip_epoch(bound))
    if operator == ">=":
        return comparison >= 0
    if operator == ">":
        return comparison > 0
    if operator == "<=":
        return comparison <= 0
    return comparison < 0


def _strip_epoch(version: str) -> str:
    return version.split(":", 1)[1] if ":" in version else version

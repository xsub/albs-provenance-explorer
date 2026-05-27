from albs_graph.provenance.reconcile_rules import (
    DEFAULT_RULES,
    Agreement,
    ConflictKind,
    ContextIssue,
    CrossDistroRule,
    IdentityMismatchRule,
    LinkageMismatchRule,
    PresenceUndeclaredRule,
    RangeViolationRule,
    ResolutionGroup,
    VersionDriftRule,
    evaluate_group,
)
from albs_graph.model import Node, NodeType


def _group(**overrides: object) -> ResolutionGroup:
    defaults: dict[str, object] = dict(
        members=(),
        subject_id="rpm:app:x86_64",
        subject_has_declarations=False,
        subject_distro=None,
        version_strings=(),
        version_classes=(),
        linkages=frozenset(),
        has_artifact_evidence=False,
        has_declared_class=False,
        is_soname_group=False,
        dependency_distros=(),
        range_satisfied_false=False,
    )
    defaults.update(overrides)
    return ResolutionGroup(**defaults)  # type: ignore[arg-type]


def test_each_rule_fires_only_on_its_own_condition() -> None:
    assert VersionDriftRule().check(_group(version_classes=("1", "2"))).conflict_kinds == (
        ConflictKind.VERSION_DRIFT,
    )
    assert VersionDriftRule().check(_group(version_classes=("1",))).conflict_kinds == ()

    assert RangeViolationRule().check(_group(range_satisfied_false=True)).conflict_kinds == (
        ConflictKind.RANGE_VIOLATION,
    )

    assert LinkageMismatchRule().check(
        _group(linkages=frozenset({"static", "dynamic"}))
    ).conflict_kinds == (ConflictKind.LINKAGE_MISMATCH,)

    presence = _group(subject_has_declarations=True, has_artifact_evidence=True)
    assert PresenceUndeclaredRule().check(presence).conflict_kinds == (
        ConflictKind.PRESENCE_UNDECLARED,
    )
    # ... but never for a soname coordinate, even with artifact evidence.
    soname = _group(subject_has_declarations=True, has_artifact_evidence=True, is_soname_group=True)
    assert PresenceUndeclaredRule().check(soname).conflict_kinds == ()

    cross = _group(subject_distro="el9", dependency_distros=("el10",))
    assert CrossDistroRule().check(cross).context_issues == (ContextIssue.CROSS_DISTRO,)
    # Same generation (different minor handled upstream) -> no issue.
    assert CrossDistroRule().check(
        _group(subject_distro="el9", dependency_distros=("el9",))
    ).context_issues == ()


def test_default_rules_are_the_named_policies() -> None:
    assert [rule.name for rule in DEFAULT_RULES] == [
        "version_drift",
        "identity_mismatch",
        "range_violation",
        "linkage_mismatch",
        "presence_undeclared",
        "cross_distro",
    ]


def _claim_node(node_id: str, name: str, version: str | None, purl: str | None) -> Node:
    metadata: dict[str, object] = {"name": name}
    if version is not None:
        metadata["asserted_version"] = version
    if purl is not None:
        metadata["purl"] = purl
    return Node(node_id, NodeType.DEPENDENCY_CLAIM, name, metadata)


def test_identity_mismatch_fires_on_same_version_different_purl() -> None:
    # Two sources agree zlib is 1.2.11 but disagree on the PURL coordinate.
    members = (
        _claim_node("c1", "zlib", "1.2.11", "pkg:rpm/almalinux/zlib@1.2.11?arch=x86_64"),
        _claim_node("c2", "zlib", "1.2.11", "pkg:rpm/almalinux/zlib@1.2.11?arch=aarch64"),
    )
    finding = IdentityMismatchRule().check(_group(members=members, version_classes=("1.2.11",)))
    assert finding.conflict_kinds == (ConflictKind.IDENTITY_MISMATCH,)


def test_identity_mismatch_silent_without_two_purls_or_on_drift() -> None:
    same_purl = (
        _claim_node("c1", "zlib", "1.2.11", "pkg:rpm/almalinux/zlib@1.2.11?arch=x86_64"),
        _claim_node("c2", "zlib", "1.2.11", "pkg:rpm/almalinux/zlib@1.2.11?arch=x86_64"),
    )
    assert IdentityMismatchRule().check(_group(members=same_purl)).conflict_kinds == ()

    one_purl = (
        _claim_node("c1", "zlib", "1.2.11", "pkg:rpm/almalinux/zlib@1.2.11"),
        _claim_node("c2", "zlib", "1.2.11", None),  # soname/header claim, no PURL
    )
    assert IdentityMismatchRule().check(_group(members=one_purl)).conflict_kinds == ()

    # Different versions are VERSION_DRIFT's job, not identity mismatch.
    drift = (
        _claim_node("c1", "zlib", "1.2.11", "pkg:rpm/almalinux/zlib@1.2.11"),
        _claim_node("c2", "zlib", "1.2.13", "pkg:rpm/almalinux/zlib@1.2.13"),
    )
    assert IdentityMismatchRule().check(_group(members=drift)).conflict_kinds == ()


def test_conflict_wins_and_keeps_rule_order() -> None:
    # Both version drift and linkage mismatch fire; the verdict is CONFLICT and
    # the first kind follows DEFAULT_RULES order (version drift before linkage).
    result = evaluate_group(
        _group(version_classes=("1", "2"), linkages=frozenset({"static", "dynamic"}))
    )
    assert result.agreement == Agreement.CONFLICT
    assert result.conflict_kinds[0] == ConflictKind.VERSION_DRIFT
    assert ConflictKind.LINKAGE_MISMATCH in result.conflict_kinds
    assert result.chosen_version is None


def test_context_issue_is_orthogonal_to_the_verdict() -> None:
    # A cross-distro group that also has a real conflict keeps both signals: the
    # agreement is CONFLICT, and the context issue rides alongside it.
    result = evaluate_group(
        _group(
            version_classes=("1", "2"),
            subject_distro="el9",
            dependency_distros=("el10",),
        )
    )
    assert result.agreement == Agreement.CONFLICT
    assert result.context_issue == ContextIssue.CROSS_DISTRO


def test_rules_are_pluggable() -> None:
    # The same drifting group: with the version-drift rule it is a CONFLICT;
    # drop that rule and the group is no longer judged to conflict.
    drift = _group(version_classes=("1", "2"))
    assert evaluate_group(drift, rules=(VersionDriftRule(),)).agreement == Agreement.CONFLICT
    assert evaluate_group(drift, rules=()).agreement != Agreement.CONFLICT


def test_insufficient_evidence_when_no_concrete_version() -> None:
    assert evaluate_group(_group()).agreement == Agreement.INSUFFICIENT_EVIDENCE

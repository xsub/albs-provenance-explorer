"""Vulnerability-applicability report - the consumer payoff (F1).

Ties together what the other layers produced:

- **errata/CVE** (A2): the CVEs a build *addresses* (rpm -FIXES-> errata
  -FIXES-> cve),
- **verified CPE + distro-backport** (A1): how much to trust identity, and the
  caveat that a backported `.elN` package carries an upstream version that does
  not line up with a CVE's affected range,
- **linkage** (rung 4): `dlopen` (runtime-loaded code broadens reachability) and
  static objects (baked-in dependencies).

It answers, per package, "what CVEs are in play here, with what confidence, and
what is the reachability picture?" It does **not** invent CVE data - without a
CVE feed it reports the CVEs already linked via errata; the identity/backport/
linkage signals frame how reliable a naive version match would be.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.security.cve_feed import CveFeed

NodeSelector = Callable[[Node], bool]


@dataclass(frozen=True)
class PackageVulnAssessment:
    package: str
    arch: str | None
    cpe: str | None
    cpe_status: str
    # ``identity_established`` is true whenever a CPE is set (cpe_status is
    # either "verified" -- NVD dictionary match -- or "vendor_asserted" --
    # AlmaLinux's own SBOM). ``identity_externally_verified`` narrows to the
    # NVD case. The old single ``identity_verified`` field conflated the two
    # (was true only for NVD) while CVE matching still ran against vendor-
    # asserted CPEs -- the field name implied a stronger guarantee than the
    # CVE-matching behaviour actually delivered.
    identity_established: bool
    identity_externally_verified: bool
    distro_backport: bool
    errata: list[str]
    addressed_cves: list[str]
    potentially_affected_cves: list[str]
    dlopen: bool
    static_objects: int

    @property
    def version_match_reliable(self) -> bool:
        # A backported package ships an upstream version with downstream patches,
        # so matching that version against a CVE's affected range is misleading.
        return not self.distro_backport

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "arch": self.arch,
            "cpe": self.cpe,
            "cpe_status": self.cpe_status,
            "identity_established": self.identity_established,
            "identity_externally_verified": self.identity_externally_verified,
            "distro_backport": self.distro_backport,
            "version_match_reliable": self.version_match_reliable,
            "errata": self.errata,
            "addressed_cves": self.addressed_cves,
            "potentially_affected_cves": self.potentially_affected_cves,
            "dlopen": self.dlopen,
            "static_objects": self.static_objects,
        }


@dataclass(frozen=True)
class VulnReport:
    packages: list[PackageVulnAssessment] = field(default_factory=list)

    @property
    def addressed_cve_count(self) -> int:
        return len({cve for pkg in self.packages for cve in pkg.addressed_cves})

    @property
    def potentially_affected_count(self) -> int:
        return len({cve for pkg in self.packages for cve in pkg.potentially_affected_cves})

    def to_dict(self) -> dict[str, Any]:
        return {
            "packages": [pkg.to_dict() for pkg in self.packages],
            "package_count": len(self.packages),
            "addressed_cve_count": self.addressed_cve_count,
            "potentially_affected_count": self.potentially_affected_count,
        }


def vulnerability_report(
    graph: ProvenanceGraph,
    *,
    cve_feed: CveFeed | None = None,
    only_with_cves: bool = False,
    node_selector: NodeSelector | None = None,
) -> VulnReport:
    """Per-binary-RPM vulnerability-applicability assessment.

    With a ``cve_feed``, the verified CPE + version of each package is matched
    against the feed's affected ranges; matches not already addressed by an
    errata are reported as ``potentially_affected_cves`` (subject to the
    ``distro_backport`` caveat).
    """

    assessments: list[PackageVulnAssessment] = []
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        errata, cves = _errata_and_cves(graph, node.id)
        identity = node.metadata.get("security_identity")
        identity = identity if isinstance(identity, dict) else {}
        elf = node.metadata.get("elf_analysis")
        elf = elf if isinstance(elf, dict) else {}
        static = elf.get("static")
        potentially = _feed_matches(cve_feed, identity.get("cpe"), set(cves))
        if only_with_cves and not cves and not potentially:
            continue
        assessments.append(
            PackageVulnAssessment(
                package=str(node.metadata.get("name") or node.label),
                arch=_optional_str(node.metadata.get("arch")),
                cpe=_optional_str(identity.get("cpe")),
                cpe_status=str(identity.get("cpe_status", "unknown")),
                # Two CPE sources establish identity (vendor SBOM + NVD); only
                # NVD's dictionary match counts as externally verified.
                identity_established=bool(identity.get("cpe")),
                identity_externally_verified=identity.get("cpe_status") == "verified",
                distro_backport=bool(identity.get("distro_backport")),
                errata=errata,
                addressed_cves=cves,
                potentially_affected_cves=potentially,
                dlopen=bool(elf.get("dlopen")),
                static_objects=len(static) if isinstance(static, list) else 0,
            )
        )
    return VulnReport(packages=assessments)


def _feed_matches(cve_feed: CveFeed | None, cpe: Any, addressed: set[str]) -> list[str]:
    if cve_feed is None or not isinstance(cpe, str):
        return []
    parsed = _parse_cpe(cpe)
    if parsed is None:
        return []
    vendor, product, version = parsed
    return sorted(set(cve_feed.match(vendor, product, version)) - addressed)


def _parse_cpe(cpe23: str) -> tuple[str, str, str] | None:
    parts = cpe23.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    vendor, product, version = parts[3], parts[4], parts[5]
    if version in ("", "*"):
        return None
    return vendor, product, version


def _errata_and_cves(graph: ProvenanceGraph, rpm_id: str) -> tuple[list[str], list[str]]:
    errata: set[str] = set()
    cves: set[str] = set()
    for edge in graph.outgoing(rpm_id, Relation.FIXES):
        errata_node = graph.nodes[edge.target]
        if errata_node.type != NodeType.ERRATA:
            continue
        errata.add(errata_node.label)
        for cve_edge in graph.outgoing(errata_node.id, Relation.FIXES):
            cve_node = graph.nodes[cve_edge.target]
            if cve_node.type == NodeType.CVE:
                cves.add(cve_node.label)
    return sorted(errata), sorted(cves)


def _optional_str(value: Any) -> str | None:
    return str(value) if value else None

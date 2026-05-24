"""Five-axis coverage reporting.

"Maximal fulfillment" of the task is a measurable thing: drive each coverage
axis toward 1.0 and enumerate the irreducible residue rather than hiding it
behind a single green checkmark. The axes are deliberately orthogonal and
serve different consumers (vuln triage, license compliance, reproducibility),
so the report keeps them separate instead of collapsing to one score.

The numbers are computed from whatever evidence currently exists in the graph,
so a sparse graph honestly reports low coverage on the axes nothing has fed
yet (today: linkage, identity/CPE, resolution) while provenance stays high.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from albs_graph.model import NodeType, ProvenanceGraph, Relation

from .reconcile import Agreement

_RESOLVED_AGREEMENTS = frozenset({str(Agreement.CONSENSUS), str(Agreement.COMPATIBLE)})


@dataclass(frozen=True)
class AxisCoverage:
    name: str
    covered: int
    total: int

    @property
    def fraction(self) -> float:
        return self.covered / self.total if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "covered": self.covered,
            "total": self.total,
            "fraction": round(self.fraction, 4),
        }


@dataclass(frozen=True)
class CoverageReport:
    resolution: AxisCoverage
    linkage: AxisCoverage
    identity: AxisCoverage
    provenance: AxisCoverage
    security_context: AxisCoverage

    def axes(self) -> tuple[AxisCoverage, ...]:
        return (
            self.resolution,
            self.linkage,
            self.identity,
            self.provenance,
            self.security_context,
        )

    def to_dict(self) -> dict[str, Any]:
        return {axis.name: axis.to_dict() for axis in self.axes()}


def coverage_report(graph: ProvenanceGraph) -> CoverageReport:
    return CoverageReport(
        resolution=_resolution_axis(graph),
        linkage=_linkage_axis(graph),
        identity=_identity_axis(graph),
        provenance=_provenance_axis(graph),
        security_context=_security_context_axis(graph),
    )


def _resolution_axis(graph: ProvenanceGraph) -> AxisCoverage:
    resolutions = graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION)
    if resolutions:
        covered = sum(
            1
            for node in resolutions
            if str(node.metadata.get("agreement", "")) in _RESOLVED_AGREEMENTS
        )
        return AxisCoverage("resolution", covered, len(resolutions))

    # Fall back to raw claims/specs when nothing has been reconciled yet.
    specs = [
        node
        for node in graph.nodes.values()
        if node.type in {NodeType.DEPENDENCY_SPEC, NodeType.DEPENDENCY_CLAIM}
    ]
    covered = sum(
        1
        for node in specs
        if str(node.metadata.get("resolution_state", "")) in {"resolved", "locked"}
    )
    return AxisCoverage("resolution", covered, len(specs))


def _linkage_axis(graph: ProvenanceGraph) -> AxisCoverage:
    binaries = graph.find_by_type(NodeType.BINARY_RPM)
    linkage_relations = {Relation.REQUIRES_RUNTIME, Relation.PROVIDES, Relation.DECLARES_DEPENDENCY}
    covered = 0
    for node in binaries:
        has_linkage = any(
            edge.relation in linkage_relations
            and str(edge.metadata.get("linkage", "unknown")) != "unknown"
            for edge in graph.outgoing(node.id)
        )
        if has_linkage:
            covered += 1
    return AxisCoverage("linkage", covered, len(binaries))


def _identity_axis(graph: ProvenanceGraph) -> AxisCoverage:
    binaries = graph.find_by_type(NodeType.BINARY_RPM)
    covered = sum(1 for node in binaries if _has_verified_cpe(node.metadata))
    return AxisCoverage("identity", covered, len(binaries))


def _provenance_axis(graph: ProvenanceGraph) -> AxisCoverage:
    binaries = graph.find_by_type(NodeType.BINARY_RPM)
    covered = sum(
        1 for node in binaries if graph.trust_path_report(node.id).provenance_complete
    )
    return AxisCoverage("provenance", covered, len(binaries))


def _security_context_axis(graph: ProvenanceGraph) -> AxisCoverage:
    binaries = graph.find_by_type(NodeType.BINARY_RPM)
    covered = sum(
        1 for node in binaries if graph.trust_path_report(node.id).security_context_complete
    )
    return AxisCoverage("security_context", covered, len(binaries))


def _has_verified_cpe(metadata: dict[str, Any]) -> bool:
    """A binary counts toward identity coverage only with a *verified* CPE.

    Unverified ``cpe_candidates`` deliberately do not count -- asserting an
    official CPE without a verification adapter is the exact failure mode the
    security-identity layer forbids.
    """

    identity = metadata.get("security_identity")
    if isinstance(identity, dict):
        if identity.get("cpe"):
            return True
        return any(
            isinstance(candidate, dict) and candidate.get("verified")
            for candidate in identity.get("cpe_candidates", [])
        )
    return bool(metadata.get("cpe"))

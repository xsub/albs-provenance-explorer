"""UI-friendly findings derived from analysis reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from albs_graph.model import NodeType, ProvenanceGraph
from albs_graph.provenance.coverage import CoverageReport
from albs_graph.provenance.reconcile import ReconciliationReport


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    title: str
    subject: str | None = None
    detail: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "title": self.title,
            "subject": self.subject,
            "detail": self.detail,
            "metadata": self.metadata,
        }


def findings_for_analysis(
    graph: ProvenanceGraph,
    coverage: CoverageReport,
    reconciliation: ReconciliationReport,
) -> list[Finding]:
    """Summarize the highest-signal gaps for a UI findings panel."""

    findings: list[Finding] = []
    for axis in coverage.axes():
        if axis.total and axis.covered < axis.total:
            findings.append(
                Finding(
                    severity="warning",
                    code=f"coverage.{axis.name}",
                    title=f"{axis.name} coverage incomplete",
                    detail=f"{axis.covered}/{axis.total} covered",
                    metadata=axis.to_dict(),
                )
            )

    for conflict in reconciliation.conflicts:
        findings.append(
            Finding(
                severity="error",
                code=f"dependency.{conflict.kind}",
                title="Dependency evidence conflict",
                subject=conflict.subject_id,
                detail=f"{conflict.coordinate}: {', '.join(conflict.versions)}",
                metadata=conflict.to_dict(),
            )
        )

    if reconciliation.cross_distro_count:
        findings.append(
            Finding(
                severity="warning",
                code="dependency.cross_distro",
                title="Dependencies resolved in a different distro context",
                detail=f"{reconciliation.cross_distro_count} resolution groups affected",
                metadata={"count": reconciliation.cross_distro_count},
            )
        )

    # Aggregate trust-check gaps by check, not per (RPM x check): a 456-RPM
    # build with every artifact missing has_sbom + has_errata_link would
    # otherwise flood the panel with ~900 near-identical info rows. One row per
    # check carries the affected node ids in metadata so the drill-down (which
    # already queries per-check, not per-node) can expand them.
    missing_by_check: dict[str, list[str]] = {}
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        report = graph.trust_path_report(node.id)
        for missing in report.missing:
            missing_by_check.setdefault(missing, []).append(node.id)
    for check, nodes in sorted(missing_by_check.items()):
        findings.append(
            Finding(
                severity="info",
                code=f"trust.{check}",
                title=f"Trust check missing: {check}",
                detail=f"{len(nodes)} artifact(s)",
                metadata={"check": check, "nodes": nodes, "count": len(nodes)},
            )
        )

    return findings

"""License-compliance rollup over SBOM component claims.

Aggregates the licenses captured from CycloneDX components (by the SBOM ingest)
into a per-license count plus an explicit "unlicensed" bucket - the license
view a compliance consumer needs. Reports only what the SBOM carried; components
with no license field are surfaced as unknown rather than guessed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from albs_graph.model import NodeType, ProvenanceGraph


@dataclass(frozen=True)
class LicenseReport:
    components: int
    licenses: dict[str, int]
    unlicensed: list[str] = field(default_factory=list)

    @property
    def distinct_licenses(self) -> int:
        return len(self.licenses)

    def to_dict(self) -> dict[str, Any]:
        return {
            "components": self.components,
            "distinct_licenses": self.distinct_licenses,
            "licenses": self.licenses,
            "unlicensed": self.unlicensed,
        }


def license_report(graph: ProvenanceGraph) -> LicenseReport:
    """Roll up component licenses from SBOM dependency claims in the graph."""

    counts: Counter[str] = Counter()
    unlicensed: list[str] = []
    components = 0
    for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM):
        if node.metadata.get("evidence") != "sbom":
            continue
        dependency = node.metadata.get("dependency")
        raw = dependency.get("raw", {}) if isinstance(dependency, dict) else {}
        licenses = raw.get("licenses") if isinstance(raw, dict) else None
        components += 1
        if isinstance(licenses, list) and licenses:
            for license_id in licenses:
                counts[str(license_id)] += 1
        else:
            unlicensed.append(str(node.metadata.get("name") or node.label))
    return LicenseReport(
        components=components,
        licenses=dict(sorted(counts.items())),
        unlicensed=sorted(unlicensed),
    )

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Relation(StrEnum):
    STORED_IN = "stored_in"
    POINTS_TO = "points_to"
    AUTHENTICATED_BY = "authenticated_by"
    BUILT_BY = "built_by"
    BUILT_IN = "built_in"
    PRODUCES = "produces"
    TESTED_BY = "tested_by"
    SIGNED_AS = "signed_as"
    RELEASED_TO = "released_to"
    DESCRIBED_BY = "described_by"
    FIXES = "fixes"
    AFFECTED_BY = "affected_by"
    DERIVED_FROM = "derived_from"
    REQUIRES_RUNTIME = "requires_runtime"
    REQUIRES_BUILDTIME = "requires_buildtime"
    DECLARES_DEPENDENCY = "declares_dependency"
    PROVIDES = "provides"
    SUPERSEDES = "supersedes"
    CONTAINS = "contains"
    REFERENCES = "references"
    OBSERVED_AS = "observed_as"
    CORROBORATES = "corroborates"
    CONFLICTS_WITH = "conflicts_with"

    @classmethod
    def canonical(cls, relation: "Relation | str") -> "Relation | str":
        if relation == "used_by":
            return cls.BUILT_BY
        return relation


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    relation: Relation | str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": str(self.relation),
            "metadata": self.metadata,
        }

"""Read-only facade over a SQLite universe store for the M4 workbench.

The heavy lifting (recursive-CTE traversal, label search) lives in
``albs_graph.store``; this wraps those SQL helpers into typed rows so the GUI
(and tests) get a stable, dependency-light surface for "open a universe store,
search packages, walk dependents/dependencies, render dependency paths" without
ever loading the whole graph into memory. The store is opened per call, so the
facade itself is just a path holder -- cheap to construct and re-point.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from albs_graph import store


@dataclass(frozen=True)
class UniversePackageRow:
    """One node from a universe store search (a package or a capability)."""

    node_id: str
    node_type: str
    label: str

    def to_dict(self) -> dict[str, Any]:
        return {"node_id": self.node_id, "node_type": self.node_type, "label": self.label}


@dataclass(frozen=True)
class UniversePathRow:
    """One dependency path, with both the raw node ids and resolved labels."""

    hops: int
    node_ids: tuple[str, ...]
    labels: tuple[str, ...]

    @property
    def display(self) -> str:
        return " -> ".join(self.labels)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hops": self.hops,
            "node_ids": list(self.node_ids),
            "labels": list(self.labels),
            "display": self.display,
        }


class UniverseStore:
    """Typed, read-only view over a SQLite universe store."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    @property
    def schema_version(self) -> int:
        return store.schema_version(self.db_path)

    def search(self, needle: str, *, limit: int = 200) -> list[UniversePackageRow]:
        return [
            UniversePackageRow(node_id=node_id, node_type=node_type, label=label)
            for node_id, node_type, label in store.sql_search(
                self.db_path, needle, limit=limit
            )
        ]

    def dependencies(self, name: str) -> list[str]:
        return store.sql_dependencies(self.db_path, name)

    def dependents(self, name: str) -> list[str]:
        return store.sql_dependents(self.db_path, name)

    def reachable(self, start: str, *, max_depth: int = 16) -> list[str]:
        return store.sql_reachable_dependencies(self.db_path, start, max_depth=max_depth)

    def paths(
        self, start: str, target: str, *, max_depth: int = 8, max_paths: int = 25
    ) -> list[UniversePathRow]:
        raw = store.sql_dependency_paths(
            self.db_path, start, target, max_depth=max_depth, max_paths=max_paths
        )
        labels = store.sql_node_labels(self.db_path, [pid for path in raw for pid in path])
        return [
            UniversePathRow(
                hops=max(len(path) - 1, 0),
                node_ids=tuple(path),
                labels=tuple(labels.get(pid, pid) for pid in path),
            )
            for path in raw
        ]

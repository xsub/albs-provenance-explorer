"""Low-footprint SQLite persistence for a ProvenanceGraph / universe.

Deliberately minimal: stdlib ``sqlite3`` + JSON metadata, no extensions, no
external dependencies, no graph-DB. It gives "build once, query later" - persist
a (possibly large arch-wide) universe to a single file and either reload it whole
(`load_graph`) or run common one-hop queries directly in SQL without loading
everything into memory (`sql_dependents` / `sql_dependencies`).

A heavier backend (Postgres recursive CTEs, a real graph store, or a vector
overlay for similarity) is left to the bigger-system plan in docs/plan.md; this
module intentionally stays small.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from albs_graph.model import Node, ProvenanceGraph

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    type TEXT,
    label TEXT,
    metadata TEXT
);
CREATE TABLE IF NOT EXISTS edges (
    source TEXT,
    target TEXT,
    relation TEXT,
    metadata TEXT,
    PRIMARY KEY (source, target, relation)
);
CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
"""

# Edge relations that mean "X requires Y" (direction-sensitive queries).
_REQUIRES = ("requires_runtime", "declares_dependency")


@dataclass(frozen=True)
class StoreStats:
    nodes: int
    edges: int

    def to_dict(self) -> dict[str, int]:
        return {"nodes": self.nodes, "edges": self.edges}


def save_graph(graph: ProvenanceGraph, db_path: str | Path) -> StoreStats:
    """Persist a graph to a SQLite file (replacing any existing contents)."""

    connection = sqlite3.connect(str(db_path))
    try:
        connection.executescript(_SCHEMA)
        connection.execute("DELETE FROM nodes")
        connection.execute("DELETE FROM edges")
        connection.executemany(
            "INSERT OR REPLACE INTO nodes (id, type, label, metadata) VALUES (?, ?, ?, ?)",
            [
                (node.id, str(node.type), node.label, json.dumps(node.metadata, sort_keys=True))
                for node in graph.nodes.values()
            ],
        )
        edge_rows: list[tuple[str, str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for edge in graph.edges:
            key = (edge.source, edge.target, str(edge.relation))
            if key in seen:
                continue
            seen.add(key)
            edge_rows.append((*key, json.dumps(edge.metadata, sort_keys=True)))
        connection.executemany(
            "INSERT OR REPLACE INTO edges (source, target, relation, metadata) VALUES (?, ?, ?, ?)",
            edge_rows,
        )
        connection.commit()
        return StoreStats(nodes=len(graph.nodes), edges=len(edge_rows))
    finally:
        connection.close()


def load_graph(db_path: str | Path) -> ProvenanceGraph:
    """Reconstruct a ProvenanceGraph from a SQLite store."""

    connection = sqlite3.connect(str(db_path))
    try:
        graph = ProvenanceGraph()
        for node_id, node_type, label, metadata in connection.execute(
            "SELECT id, type, label, metadata FROM nodes"
        ):
            graph.add_node(Node(node_id, node_type, label, json.loads(metadata)))
        for source, target, relation, metadata in connection.execute(
            "SELECT source, target, relation, metadata FROM edges"
        ):
            if source in graph.nodes and target in graph.nodes:
                graph.add_edge(source, target, relation, **json.loads(metadata))
        return graph
    finally:
        connection.close()


def sql_dependents(
    db_path: str | Path, name: str, *, relations: tuple[str, ...] = _REQUIRES
) -> list[str]:
    """One-hop dependents of a capability/package, queried in SQL (no full load)."""

    connection = sqlite3.connect(str(db_path))
    try:
        targets = _matching_ids(connection, name)
        if not targets:
            return []
        query = (
            "SELECT DISTINCT n.label FROM edges e JOIN nodes n ON n.id = e.source "
            f"WHERE e.target IN ({_placeholders(targets)}) "
            f"AND e.relation IN ({_placeholders(relations)})"
        )
        return sorted(row[0] for row in connection.execute(query, (*targets, *relations)))
    finally:
        connection.close()


def sql_dependencies(
    db_path: str | Path, node: str, *, relations: tuple[str, ...] = _REQUIRES
) -> list[str]:
    """One-hop dependencies of a node, queried in SQL (no full load)."""

    connection = sqlite3.connect(str(db_path))
    try:
        sources = _matching_ids(connection, node)
        if not sources:
            return []
        query = (
            "SELECT DISTINCT n.label FROM edges e JOIN nodes n ON n.id = e.target "
            f"WHERE e.source IN ({_placeholders(sources)}) "
            f"AND e.relation IN ({_placeholders(relations)})"
        )
        return sorted(row[0] for row in connection.execute(query, (*sources, *relations)))
    finally:
        connection.close()


def _matching_ids(connection: sqlite3.Connection, needle: str) -> list[str]:
    rows = connection.execute(
        "SELECT id FROM nodes WHERE label = ? OR id = ? OR id = ? OR id LIKE ?",
        (needle, needle, f"pkg:{needle}", f"cap:%{needle}"),
    ).fetchall()
    return [row[0] for row in rows]


def _placeholders(values: tuple[str, ...] | list[str]) -> str:
    return ",".join("?" for _ in values)

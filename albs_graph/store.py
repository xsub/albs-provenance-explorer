"""Low-footprint SQLite persistence for a ProvenanceGraph / universe.

Stdlib ``sqlite3`` + JSON metadata, no extensions, no external dependencies,
no graph-DB. The store grew from "round-trip a built graph" into a small query
backend:

- **Versioned schema** (``schema_version`` table + a ``MIGRATIONS`` list)
  so re-opening a store written by an older release upgrades in place.
- **Replace and merge modes** for ``save_graph``: ``"replace"`` (default,
  unchanged from the original) wipes nodes/edges before writing; ``"merge"``
  upserts and **preserves edge metadata** by deep-merging both sides -- so
  multi-build / multi-arch accumulation does not lose claims.
- **Recursive-CTE queries** for the multi-hop universe walks the in-Python
  BFS used to do: ``sql_reachable_dependencies`` and ``sql_dependency_paths``.
  The CTE form runs entirely in SQLite, so a large repo-wide universe is
  walkable without loading the whole graph into memory.
- **Materialized analysis snapshots**: ``save_analysis_snapshot`` /
  ``load_analysis_snapshot`` persist a coverage / vuln / license report as a
  JSON blob keyed on ``(kind, subject_id)``. The latest snapshot per key wins;
  the table doubles as a per-run audit log.

A heavier backend (Postgres recursive CTEs at scale, a real graph store, or a
vector overlay for similarity) is still out of scope: this module stays small,
stdlib-only, and Mac/Linux-portable.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Sequence

from albs_graph.model import Node, ProvenanceGraph

_BASE_SCHEMA = """
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

# Migrations are applied in order. Each is keyed on the schema version it lifts
# the database *to* (so v0->v1 is in MIGRATIONS[1], v1->v2 in MIGRATIONS[2],
# etc.). v1 introduces the schema_version table itself (the base schema is
# legacy); v2 adds analysis_snapshots; v3 adds relation indexes used by the
# recursive-CTE queries.
Migration = Callable[[sqlite3.Connection], None]


def _migration_v1_init_schema_version(conn: sqlite3.Connection) -> None:
    conn.executescript(_BASE_SCHEMA)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "    version INTEGER PRIMARY KEY,"
        "    applied_at TEXT NOT NULL"
        ")"
    )


def _migration_v2_analysis_snapshots(conn: sqlite3.Connection) -> None:
    # One row per (kind, subject_id, recorded_at). The newest per (kind,
    # subject_id) wins in `load_analysis_snapshot`; older rows stay as an
    # audit trail. ``args`` records the inputs that produced the snapshot
    # (e.g. RunSpec field dump) so a reader can tell two runs apart.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS analysis_snapshots ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    kind TEXT NOT NULL,"
        "    subject_id TEXT NOT NULL,"
        "    payload TEXT NOT NULL,"
        "    args TEXT,"
        "    recorded_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_snapshots_kind_subject "
        "ON analysis_snapshots(kind, subject_id, recorded_at DESC)"
    )


def _migration_v3_relation_index(conn: sqlite3.Connection) -> None:
    # Recursive-CTE walks filter by `relation IN (...)`; this composite index
    # lets the planner prune by relation before joining target rows.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_edges_source_relation "
        "ON edges(source, relation)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_edges_target_relation "
        "ON edges(target, relation)"
    )


MIGRATIONS: tuple[Migration, ...] = (
    _migration_v1_init_schema_version,
    _migration_v2_analysis_snapshots,
    _migration_v3_relation_index,
)


# Edge relations that mean "X requires Y" (direction-sensitive queries).
_REQUIRES = ("requires_runtime", "declares_dependency")
# Walk-style queries (incl. PROVIDES) so a soname capability bridges to its
# provider package -- mirrors universe._TRAVERSE_RELATIONS.
_TRAVERSE = ("requires_runtime", "declares_dependency", "provides")


@dataclass(frozen=True)
class StoreStats:
    nodes: int
    edges: int

    def to_dict(self) -> dict[str, int]:
        return {"nodes": self.nodes, "edges": self.edges}


SaveMode = Literal["replace", "merge"]


def save_graph(
    graph: ProvenanceGraph,
    db_path: str | Path,
    *,
    mode: SaveMode = "replace",
) -> StoreStats:
    """Persist a graph to a SQLite file.

    ``mode="replace"`` (default, original behaviour) wipes nodes + edges and
    writes the graph from scratch. ``mode="merge"`` upserts both, deep-merging
    metadata so multi-build / multi-arch accumulation does not lose claims:
    when the same ``(source, target, relation)`` edge appears with metadata in
    both stores, the union wins and lists are concatenated + deduplicated.
    """

    connection = sqlite3.connect(str(db_path))
    try:
        _ensure_schema(connection)
        if mode == "replace":
            connection.execute("DELETE FROM nodes")
            connection.execute("DELETE FROM edges")
            connection.executemany(
                "INSERT INTO nodes (id, type, label, metadata) VALUES (?, ?, ?, ?)",
                [
                    (node.id, str(node.type), node.label, json.dumps(node.metadata, sort_keys=True))
                    for node in graph.nodes.values()
                ],
            )
            edge_rows = list(_unique_edge_rows(graph))
            connection.executemany(
                "INSERT INTO edges (source, target, relation, metadata) VALUES (?, ?, ?, ?)",
                edge_rows,
            )
            stats = StoreStats(nodes=len(graph.nodes), edges=len(edge_rows))
        else:
            # merge: deep-merge node metadata then edge metadata.
            for node in graph.nodes.values():
                _upsert_node(connection, node)
            edge_count = 0
            for edge in graph.edges:
                _upsert_edge(
                    connection, edge.source, edge.target, str(edge.relation), edge.metadata
                )
                edge_count += 1
            stats = StoreStats(nodes=len(graph.nodes), edges=edge_count)
        connection.commit()
        return stats
    finally:
        connection.close()


def load_graph(db_path: str | Path) -> ProvenanceGraph:
    """Reconstruct a ProvenanceGraph from a SQLite store."""

    connection = sqlite3.connect(str(db_path))
    try:
        _ensure_schema(connection)
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
        _ensure_schema(connection)
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
        _ensure_schema(connection)
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


def sql_reachable_dependencies(
    db_path: str | Path,
    start: str,
    *,
    max_depth: int = 16,
    relations: tuple[str, ...] = _TRAVERSE,
) -> list[str]:
    """Transitive closure of dependencies reachable from a start node.

    Runs as a recursive CTE in SQLite so even a large arch-wide universe walks
    without ever loading the whole graph into Python. ``max_depth`` caps the
    walk so a self-referential cluster cannot loop forever (in practice the
    universe is a DAG and the cap is generous; depth-16 matches what the
    in-memory BFS hit in our test fixtures).
    """

    connection = sqlite3.connect(str(db_path))
    try:
        _ensure_schema(connection)
        starts = _matching_ids(connection, start)
        if not starts:
            return []
        placeholders_starts = _placeholders(starts)
        placeholders_rels = _placeholders(relations)
        # The CTE seeds with the start nodes (depth 0) and walks edges until
        # max_depth. UNION (not UNION ALL) deduplicates so cycles terminate.
        query = (
            "WITH RECURSIVE walk(id, depth) AS ("
            f"  SELECT id, 0 FROM nodes WHERE id IN ({placeholders_starts})"
            "  UNION"
            "  SELECT e.target, walk.depth + 1 FROM edges e JOIN walk ON e.source = walk.id"
            f"  WHERE e.relation IN ({placeholders_rels}) AND walk.depth < ?"
            ") "
            "SELECT DISTINCT n.label FROM walk JOIN nodes n ON n.id = walk.id "
            f"WHERE walk.id NOT IN ({placeholders_starts})"
        )
        params = (*starts, *relations, max_depth, *starts)
        return sorted(row[0] for row in connection.execute(query, params))
    finally:
        connection.close()


def sql_dependency_paths(
    db_path: str | Path,
    start: str,
    target: str,
    *,
    max_depth: int = 8,
    max_paths: int = 25,
    relations: tuple[str, ...] = _TRAVERSE,
) -> list[list[str]]:
    """All dependency paths from a start node to any node matching ``target``.

    Recursive CTE that carries the path as a delimited string so SQLite can
    cycle-detect (``instr(path, '|' || target || '|')``). Caller gets paths
    capped at ``max_paths`` (oldest-first, the natural CTE order) and bounded
    by ``max_depth`` hops.
    """

    connection = sqlite3.connect(str(db_path))
    try:
        _ensure_schema(connection)
        starts = _matching_ids(connection, start)
        targets = _matching_ids(connection, target)
        if not starts or not targets:
            return []
        placeholders_starts = _placeholders(starts)
        placeholders_targets = _placeholders(targets)
        placeholders_rels = _placeholders(relations)
        # The path is stored as `|id1|id2|...|tail|`. Cycle check: don't extend
        # if the candidate target is already inside the delimiter-wrapped path.
        query = (
            "WITH RECURSIVE walk(tail, path, depth) AS ("
            f"  SELECT id, '|' || id || '|', 0 FROM nodes WHERE id IN ({placeholders_starts})"
            "  UNION ALL"
            "  SELECT e.target, walk.path || e.target || '|', walk.depth + 1 "
            "  FROM edges e JOIN walk ON e.source = walk.tail "
            f"  WHERE e.relation IN ({placeholders_rels}) "
            "  AND walk.depth < ? "
            "  AND instr(walk.path, '|' || e.target || '|') = 0"
            ") "
            f"SELECT path FROM walk WHERE tail IN ({placeholders_targets}) AND depth > 0 "
            "LIMIT ?"
        )
        params = (*starts, *relations, max_depth, *targets, max_paths)
        return [
            [token for token in row[0].split("|") if token]
            for row in connection.execute(query, params)
        ]
    finally:
        connection.close()


def sql_search(
    db_path: str | Path, needle: str, *, limit: int = 200
) -> list[tuple[str, str, str]]:
    """Search nodes by label or id substring; returns ``(id, type, label)``.

    Used by the Universe workbench's package search; an empty needle lists the
    first ``limit`` nodes (label order) so opening a store shows something.
    """

    connection = sqlite3.connect(str(db_path))
    try:
        _ensure_schema(connection)
        like = f"%{needle}%"
        rows = connection.execute(
            "SELECT id, type, label FROM nodes WHERE label LIKE ? OR id LIKE ? "
            "ORDER BY label, id LIMIT ?",
            (like, like, limit),
        ).fetchall()
        return [(row[0], row[1], row[2]) for row in rows]
    finally:
        connection.close()


def sql_node_labels(db_path: str | Path, ids: Sequence[str]) -> dict[str, str]:
    """Resolve node ids to labels in one query (e.g. to render a path)."""

    unique = list(dict.fromkeys(ids))
    if not unique:
        return {}
    connection = sqlite3.connect(str(db_path))
    try:
        _ensure_schema(connection)
        rows = connection.execute(
            f"SELECT id, label FROM nodes WHERE id IN ({_placeholders(unique)})",
            tuple(unique),
        ).fetchall()
        return {row[0]: row[1] for row in rows}
    finally:
        connection.close()


def save_analysis_snapshot(
    db_path: str | Path,
    kind: str,
    subject_id: str,
    payload: dict[str, Any],
    *,
    args: dict[str, Any] | None = None,
    recorded_at: datetime | None = None,
) -> int:
    """Persist an analysis report (coverage / vuln / license) keyed on ``(kind, subject_id)``.

    Older snapshots for the same key stay in the table as an audit trail;
    ``load_analysis_snapshot`` returns the most recent. Returns the new row id.
    """

    moment = (recorded_at or datetime.now(timezone.utc)).isoformat()
    connection = sqlite3.connect(str(db_path))
    try:
        _ensure_schema(connection)
        cursor = connection.execute(
            "INSERT INTO analysis_snapshots (kind, subject_id, payload, args, recorded_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                kind,
                subject_id,
                json.dumps(payload, sort_keys=True),
                json.dumps(args, sort_keys=True) if args is not None else None,
                moment,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid or 0)
    finally:
        connection.close()


def load_analysis_snapshot(
    db_path: str | Path, kind: str, subject_id: str
) -> dict[str, Any] | None:
    """Load the most recent analysis snapshot for ``(kind, subject_id)``.

    Returns ``None`` when no snapshot has been recorded; otherwise a dict
    with ``kind``, ``subject_id``, ``payload``, ``args``, ``recorded_at``.
    """

    connection = sqlite3.connect(str(db_path))
    try:
        _ensure_schema(connection)
        row = connection.execute(
            "SELECT payload, args, recorded_at FROM analysis_snapshots "
            "WHERE kind = ? AND subject_id = ? "
            "ORDER BY recorded_at DESC, id DESC LIMIT 1",
            (kind, subject_id),
        ).fetchone()
        if row is None:
            return None
        payload_json, args_json, recorded_at = row
        return {
            "kind": kind,
            "subject_id": subject_id,
            "payload": json.loads(payload_json),
            "args": json.loads(args_json) if args_json else None,
            "recorded_at": recorded_at,
        }
    finally:
        connection.close()


def schema_version(db_path: str | Path) -> int:
    """Return the migrated schema version of a store (0 if uninitialised)."""

    connection = sqlite3.connect(str(db_path))
    try:
        return _read_schema_version(connection)
    finally:
        connection.close()


# --- Internals ---------------------------------------------------------------


def _ensure_schema(connection: sqlite3.Connection) -> None:
    """Apply any pending migrations to bring the DB to the latest version.

    Idempotent: each migration runs only once. A brand-new database walks
    every migration; an existing one applies just the missing ones. The
    base schema (legacy nodes/edges tables) is also created here so a fresh
    open works without a separate ``CREATE TABLE`` step.
    """

    current = _read_schema_version(connection)
    target = len(MIGRATIONS)
    for version in range(current + 1, target + 1):
        migration = MIGRATIONS[version - 1]
        migration(connection)
        connection.execute(
            "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, ?)",
            (version, datetime.now(timezone.utc).isoformat()),
        )
    connection.commit()


def _read_schema_version(connection: sqlite3.Connection) -> int:
    # A fresh DB has no schema_version table; the first migration creates it.
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if row is None:
        return 0
    versions = connection.execute(
        "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
    ).fetchone()
    return int(versions[0]) if versions else 0


def _unique_edge_rows(graph: ProvenanceGraph) -> Iterable[tuple[str, str, str, str]]:
    seen: set[tuple[str, str, str]] = set()
    for edge in graph.edges:
        key = (edge.source, edge.target, str(edge.relation))
        if key in seen:
            continue
        seen.add(key)
        yield (*key, json.dumps(edge.metadata, sort_keys=True))


def _upsert_node(connection: sqlite3.Connection, node: Node) -> None:
    """Insert a node or deep-merge its metadata with the existing row."""

    row = connection.execute(
        "SELECT metadata FROM nodes WHERE id = ?", (node.id,)
    ).fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO nodes (id, type, label, metadata) VALUES (?, ?, ?, ?)",
            (node.id, str(node.type), node.label, json.dumps(node.metadata, sort_keys=True)),
        )
        return
    merged = _deep_merge(json.loads(row[0]), node.metadata)
    connection.execute(
        "UPDATE nodes SET type = ?, label = ?, metadata = ? WHERE id = ?",
        (str(node.type), node.label, json.dumps(merged, sort_keys=True), node.id),
    )


def _upsert_edge(
    connection: sqlite3.Connection,
    source: str,
    target: str,
    relation: str,
    metadata: dict[str, Any],
) -> None:
    """Insert an edge or deep-merge its metadata with the existing row."""

    row = connection.execute(
        "SELECT metadata FROM edges WHERE source = ? AND target = ? AND relation = ?",
        (source, target, relation),
    ).fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO edges (source, target, relation, metadata) VALUES (?, ?, ?, ?)",
            (source, target, relation, json.dumps(metadata, sort_keys=True)),
        )
        return
    merged = _deep_merge(json.loads(row[0]), metadata)
    connection.execute(
        "UPDATE edges SET metadata = ? WHERE source = ? AND target = ? AND relation = ?",
        (json.dumps(merged, sort_keys=True), source, target, relation),
    )


def _deep_merge(base: Any, incoming: Any) -> Any:
    """Merge two JSON-shaped values; lists are concatenated + de-duped in place.

    Dicts merge key-by-key (incoming wins on scalar conflicts); lists union
    while preserving order (base first, then incoming additions); other types
    are taken from incoming. Designed for edge.metadata where additive evidence
    accumulation (multiple "evidence" sources, multiple "claim" ids) is the
    expected shape.
    """

    if isinstance(base, dict) and isinstance(incoming, dict):
        merged = dict(base)
        for key, value in incoming.items():
            if key in merged:
                merged[key] = _deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged
    if isinstance(base, list) and isinstance(incoming, list):
        seen: list[Any] = list(base)
        for item in incoming:
            if item not in seen:
                seen.append(item)
        return seen
    return incoming


def _matching_ids(connection: sqlite3.Connection, needle: str) -> list[str]:
    # Trailing wildcard too, so a partial capability (`libssl`) matches
    # `cap:rpm:libssl.so.3` -- mirroring the in-memory substring matcher rather
    # than only an exact suffix.
    rows = connection.execute(
        "SELECT id FROM nodes WHERE label = ? OR id = ? OR id = ? OR id LIKE ?",
        (needle, needle, f"pkg:{needle}", f"cap:%{needle}%"),
    ).fetchall()
    return [row[0] for row in rows]


def _placeholders(values: tuple[str, ...] | list[str]) -> str:
    return ",".join("?" for _ in values)

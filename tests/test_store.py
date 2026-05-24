from pathlib import Path

from albs_graph.provenance import dependencies_of, dependents_of, universe_from_dot
from albs_graph.store import load_graph, save_graph, sql_dependencies, sql_dependents

_DOT = """
digraph g {
"nginx-core" -> "openssl-libs"
"nginx-core" -> "glibc"
"openssl-libs" -> "glibc"
"curl" -> "glibc"
}
"""


def test_save_load_round_trip(tmp_path: Path) -> None:
    universe = universe_from_dot(_DOT)
    db = tmp_path / "universe.db"

    stats = save_graph(universe, db)
    assert stats.nodes == len(universe.nodes)
    assert stats.edges == len(universe.edges)

    loaded = load_graph(db)
    assert set(loaded.nodes) == set(universe.nodes)
    assert len(loaded.edges) == len(universe.edges)
    # Edges round-trip with working relations.
    assert dependents_of(loaded, "glibc") == dependents_of(universe, "glibc")


def test_sql_dependents_matches_in_memory(tmp_path: Path) -> None:
    universe = universe_from_dot(_DOT)
    db = tmp_path / "universe.db"
    save_graph(universe, db)

    assert sql_dependents(db, "glibc") == dependents_of(universe, "glibc")


def test_sql_dependencies_matches_in_memory(tmp_path: Path) -> None:
    universe = universe_from_dot(_DOT)
    db = tmp_path / "universe.db"
    save_graph(universe, db)

    assert sql_dependencies(db, "nginx-core") == dependencies_of(universe, "pkg:nginx-core")


def test_sql_query_on_missing_name_is_empty(tmp_path: Path) -> None:
    db = tmp_path / "universe.db"
    save_graph(universe_from_dot(_DOT), db)

    assert sql_dependents(db, "does-not-exist") == []

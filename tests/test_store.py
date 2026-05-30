from pathlib import Path

from albs_graph.dependency import DependencySpec, Ecosystem, Linkage, PackageIdentity, ResolutionState
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance import (
    DependencyClaim,
    add_dependency_claim,
    build_universe,
    dependencies_of,
    dependents_of,
    reachable_dependencies,
    universe_from_dot,
)
from albs_graph.store import (
    load_analysis_snapshot,
    load_graph,
    save_analysis_snapshot,
    save_graph,
    schema_version,
    sql_dependencies,
    sql_dependency_paths,
    sql_dependents,
    sql_reachable_dependencies,
)

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


def test_sql_partial_capability_matches_like_in_memory(tmp_path: Path) -> None:
    # A partial capability needle ("libssl") must match cap:rpm:libssl.so.3 via
    # SQL too, mirroring the in-memory substring matcher (regression: the LIKE
    # had no trailing wildcard, so only an exact suffix matched).
    graph = ProvenanceGraph()
    graph.add_node(Node("rpm:app", NodeType.BINARY_RPM, "app", {"name": "app", "arch": "x86_64"}))
    spec = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, "libssl.so.3"),
        linkage=Linkage.DYNAMIC,
        resolution_state=ResolutionState.OBSERVED,
    )
    add_dependency_claim(graph, DependencyClaim("rpm:app", spec, evidence="elf_dt_needed"))
    universe = build_universe(graph)
    db = tmp_path / "u.db"
    save_graph(universe, db)

    assert sql_dependents(db, "libssl.so.3") == dependents_of(universe, "libssl.so.3")
    assert sql_dependents(db, "libssl") == dependents_of(universe, "libssl")
    assert "app" in sql_dependents(db, "libssl")


def test_sql_query_on_missing_name_is_empty(tmp_path: Path) -> None:
    db = tmp_path / "universe.db"
    save_graph(universe_from_dot(_DOT), db)

    assert sql_dependents(db, "does-not-exist") == []


def test_schema_versioning_lifts_a_fresh_store_to_the_latest(tmp_path: Path) -> None:
    # A brand-new store is uninitialised until the first call touches it; after
    # any operation it sits at the latest schema version. Idempotent: re-opening
    # does not re-apply migrations.
    db = tmp_path / "u.db"
    assert schema_version(db) == 0  # untouched (the SELECT itself initialises)

    save_graph(universe_from_dot(_DOT), db)
    v = schema_version(db)
    assert v >= 3  # at least v1+v2+v3 (base + snapshots + relation index)

    # Re-opening keeps the same version (no re-application).
    load_graph(db)
    assert schema_version(db) == v


def test_merge_mode_deep_merges_edge_metadata_across_two_writes(tmp_path: Path) -> None:
    # Two ProvenanceGraphs that share one (source, target, relation) edge but
    # carry different evidence lists must accumulate -- not overwrite -- when
    # merged into the same store. This is what makes multi-build / multi-arch
    # accumulation work without losing claims.
    def _graph_with_edge(evidence: list[str]) -> ProvenanceGraph:
        g = ProvenanceGraph()
        g.add_node(Node("rpm:app", NodeType.BINARY_RPM, "app", {"name": "app"}))
        g.add_node(
            Node("cap:libfoo.so.1", NodeType.EXTERNAL_PACKAGE, "libfoo.so.1", {})
        )
        g.add_edge(
            "rpm:app", "cap:libfoo.so.1", "requires_runtime",
            evidence=evidence,
            note="seen-in-build",
        )
        return g

    db = tmp_path / "m.db"
    save_graph(_graph_with_edge(["build-1", "elf_needed"]), db, mode="merge")
    save_graph(_graph_with_edge(["build-2", "elf_needed"]), db, mode="merge")

    merged = load_graph(db)
    edge = next(
        e for e in merged.edges
        if e.source == "rpm:app" and e.target == "cap:libfoo.so.1"
    )
    # Lists unionised (order preserved, no dupe of "elf_needed").
    assert edge.metadata["evidence"] == ["build-1", "elf_needed", "build-2"]
    # Scalar carried through unchanged.
    assert edge.metadata["note"] == "seen-in-build"


def test_merge_preserves_existing_nodes_when_new_writes_add_only_edges(tmp_path: Path) -> None:
    # Regression-shaped: a second-build write often adds new edges to a node
    # that already exists in the store. The node's existing metadata must not
    # be lost, and new keys from the second write must accumulate.
    g1 = ProvenanceGraph()
    g1.add_node(Node("rpm:app", NodeType.BINARY_RPM, "app", {"name": "app", "build_id": 1}))
    db = tmp_path / "m.db"
    save_graph(g1, db, mode="merge")

    g2 = ProvenanceGraph()
    g2.add_node(Node("rpm:app", NodeType.BINARY_RPM, "app", {"build_id": 2, "arch": "x86_64"}))
    save_graph(g2, db, mode="merge")

    loaded = load_graph(db)
    meta = loaded.nodes["rpm:app"].metadata
    # name was only in g1, arch only in g2 -- both survive.
    assert meta["name"] == "app"
    assert meta["arch"] == "x86_64"
    # Scalar conflict: incoming wins (g2's build_id).
    assert meta["build_id"] == 2


def test_replace_mode_wipes_before_writing(tmp_path: Path) -> None:
    # Default mode is unchanged: a second save replaces the first entirely.
    db = tmp_path / "r.db"
    save_graph(universe_from_dot(_DOT), db)  # default = replace
    first = load_graph(db)

    small = ProvenanceGraph()
    small.add_node(Node("rpm:only", NodeType.BINARY_RPM, "only", {}))
    save_graph(small, db)  # default = replace -> wipes first
    second = load_graph(db)

    assert "nginx-core" in {n.label for n in first.nodes.values()}
    assert set(second.nodes) == {"rpm:only"}


def test_sql_reachable_dependencies_matches_in_memory_bfs(tmp_path: Path) -> None:
    # The recursive CTE must produce the same transitive closure as the
    # in-Python BFS for the same start node; that's the whole point of moving
    # the walk into SQL (no full graph load).
    universe = universe_from_dot(_DOT)
    db = tmp_path / "u.db"
    save_graph(universe, db)

    in_memory = sorted(
        universe.nodes[node_id].label
        for node_id in reachable_dependencies(universe, "pkg:nginx-core")
    )
    assert sql_reachable_dependencies(db, "nginx-core") == in_memory


def test_sql_reachable_dependencies_max_depth_caps_walk(tmp_path: Path) -> None:
    # A chain A -> B -> C -> D walked from A with max_depth=1 reaches only B.
    g = ProvenanceGraph()
    for token in ("a", "b", "c", "d"):
        g.add_node(Node(f"pkg:{token}", NodeType.BINARY_RPM, token, {"name": token}))
    g.add_edge("pkg:a", "pkg:b", "requires_runtime")
    g.add_edge("pkg:b", "pkg:c", "requires_runtime")
    g.add_edge("pkg:c", "pkg:d", "requires_runtime")
    db = tmp_path / "chain.db"
    save_graph(g, db)

    assert sql_reachable_dependencies(db, "a", max_depth=1) == ["b"]
    assert sql_reachable_dependencies(db, "a", max_depth=2) == ["b", "c"]
    assert sql_reachable_dependencies(db, "a", max_depth=8) == ["b", "c", "d"]


def test_sql_dependency_paths_finds_chains_and_dedupes_cycles(tmp_path: Path) -> None:
    # nginx-core -> openssl-libs -> glibc is the expected path; the CTE also
    # finds the direct edge nginx-core -> glibc. Both paths must come back.
    universe = universe_from_dot(_DOT)
    db = tmp_path / "u.db"
    save_graph(universe, db)

    paths = sql_dependency_paths(db, "nginx-core", "glibc")
    chains = {tuple(p) for p in paths}
    # Direct edge + two-hop chain via openssl-libs.
    assert ("pkg:nginx-core", "pkg:glibc") in chains
    assert ("pkg:nginx-core", "pkg:openssl-libs", "pkg:glibc") in chains


def test_sql_dependency_paths_respects_max_depth_and_max_paths(tmp_path: Path) -> None:
    universe = universe_from_dot(_DOT)
    db = tmp_path / "u.db"
    save_graph(universe, db)

    # max_depth=1 only catches the direct edge, not the via-openssl chain.
    paths_shallow = sql_dependency_paths(db, "nginx-core", "glibc", max_depth=1)
    assert all(len(p) == 2 for p in paths_shallow)
    # max_paths caps the result count.
    paths_capped = sql_dependency_paths(db, "nginx-core", "glibc", max_paths=1)
    assert len(paths_capped) == 1


def test_analysis_snapshot_round_trips_and_returns_most_recent(tmp_path: Path) -> None:
    db = tmp_path / "snap.db"
    save_analysis_snapshot(
        db, "coverage", "rpm:demo:x86_64",
        {"axes": {"provenance": 0.5}}, args={"build_id": 1},
    )
    save_analysis_snapshot(
        db, "coverage", "rpm:demo:x86_64",
        {"axes": {"provenance": 1.0}}, args={"build_id": 2},
    )
    # Different (kind, subject) is independent.
    save_analysis_snapshot(db, "vuln", "rpm:demo:x86_64", {"packages": []})

    snap = load_analysis_snapshot(db, "coverage", "rpm:demo:x86_64")
    assert snap is not None
    # Most recent wins.
    assert snap["payload"]["axes"]["provenance"] == 1.0
    assert snap["args"] == {"build_id": 2}

    vuln = load_analysis_snapshot(db, "vuln", "rpm:demo:x86_64")
    assert vuln is not None and vuln["payload"] == {"packages": []}

    # Missing key -> None.
    assert load_analysis_snapshot(db, "coverage", "rpm:nope") is None

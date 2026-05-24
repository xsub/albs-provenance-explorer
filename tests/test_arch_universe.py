from albs_graph.dependency import (
    DependencySpec,
    Ecosystem,
    Linkage,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance import (
    DependencyClaim,
    add_dependency_claim,
    build_arch_universe,
    dependencies_of,
    dependency_paths,
    dependents_of,
    merge_graphs,
    universe_from_dot,
)

_BASEOS = """
digraph baseos {
"glibc" -> "filesystem"
"zlib" -> "glibc"
"openssl-libs" -> "glibc"
}
"""

_APPSTREAM = """
digraph appstream {
"nginx-core" -> "openssl-libs"
"nginx-core" -> "zlib"
"nginx-core" -> "glibc"
}
"""


def test_merge_graphs_dedups_shared_nodes() -> None:
    merged = merge_graphs([universe_from_dot(_BASEOS), universe_from_dot(_APPSTREAM)])

    # glibc/zlib/openssl-libs appear in both dots but exist once.
    names = sorted(node.label for node in merged.find_by_type(NodeType.BINARY_RPM))
    assert names == ["filesystem", "glibc", "nginx-core", "openssl-libs", "zlib"]


def test_arch_universe_connects_across_repos() -> None:
    universe = build_arch_universe(dots=[_BASEOS, _APPSTREAM])

    # glibc is required by everything across both repos.
    assert dependents_of(universe, "glibc") == ["nginx-core", "openssl-libs", "zlib"]
    # A cross-repo chain exists: appstream nginx-core -> baseos glibc -> filesystem.
    rendered = {
        " -> ".join(universe.nodes[n].label for n in path)
        for path in dependency_paths(universe, "pkg:nginx-core", "filesystem")
    }
    assert any("glibc -> filesystem" in chain for chain in rendered)


def test_arch_universe_merges_dot_topology_with_claim_evidence() -> None:
    graph = ProvenanceGraph()
    graph.add_node(
        Node("rpm:nginx-core:x86_64", NodeType.BINARY_RPM, "nginx-core", {"name": "nginx-core", "arch": "x86_64"})
    )
    spec = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, "libc.so.6"),
        linkage=Linkage.DYNAMIC,
        resolution_state=ResolutionState.OBSERVED,
    )
    add_dependency_claim(graph, DependencyClaim("rpm:nginx-core:x86_64", spec, evidence="elf_dt_needed"))

    universe = build_arch_universe(dots=[_APPSTREAM], graphs=[graph], arch="x86_64")

    deps = dependencies_of(universe, "pkg:nginx-core")
    # package edges from the dot AND the soname capability from the claim.
    assert "openssl-libs" in deps
    assert "libc.so.6" in deps

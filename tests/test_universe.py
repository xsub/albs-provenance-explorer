from albs_graph.dependency import (
    DependencySpec,
    Ecosystem,
    Linkage,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.provenance import (
    DependencyClaim,
    add_dependency_claim,
    build_universe,
    dependencies_of,
    dependency_paths,
    dependents_of,
    neighborhood_subgraph,
    path_subgraph,
    reachable_dependencies,
    universe_from_dot,
)

_REPO_DOT = """
digraph packages {
"nginx-core" -> "openssl-libs"
"nginx-core" -> "glibc"
"openssl-libs" -> "glibc"
"curl" -> "openssl-libs"
"curl" -> "glibc"
"zlib" -> "glibc"
}
"""


def test_universe_from_dot_connects_libc_to_everything() -> None:
    universe = universe_from_dot(_REPO_DOT)

    assert len(universe.find_by_type(NodeType.BINARY_RPM)) == 5
    # glibc is required by everything else in the repo graph.
    assert dependents_of(universe, "glibc") == ["curl", "nginx-core", "openssl-libs", "zlib"]
    assert dependencies_of(universe, "pkg:nginx-core") == ["glibc", "openssl-libs"]


def test_universe_from_dot_handles_repograph_block_form() -> None:
    # `dnf repograph` block form: A -> { B C }. Each token is a real edge, so the
    # universe must connect them (regression: blocks were parsed as a chain).
    dot = (
        'digraph packages {\n'
        '"curl" -> {\n"openssl-libs"\n"glibc"\n}\n'
        '"openssl-libs" -> {\n"glibc"\n}\n'
        '}'
    )
    universe = universe_from_dot(dot)
    assert dependents_of(universe, "glibc") == ["curl", "openssl-libs"]
    assert dependencies_of(universe, "pkg:curl") == ["glibc", "openssl-libs"]


def test_universe_traversal_finds_chains_to_libc() -> None:
    universe = universe_from_dot(_REPO_DOT)
    paths = dependency_paths(universe, "pkg:nginx-core", "glibc")

    rendered = {" -> ".join(universe.nodes[n].label for n in path) for path in paths}
    assert "nginx-core -> glibc" in rendered
    assert "nginx-core -> openssl-libs -> glibc" in rendered
    assert "pkg:glibc" in reachable_dependencies(universe, "pkg:nginx-core")


def test_path_subgraph_keeps_only_chain_nodes() -> None:
    universe = universe_from_dot(_REPO_DOT)
    paths = dependency_paths(universe, "pkg:nginx-core", "glibc")
    sub = path_subgraph(universe, paths)

    labels = {node.label for node in sub.nodes.values()}
    assert labels == {"nginx-core", "openssl-libs", "glibc"}
    assert sub.edges  # the chain edges are preserved


def test_neighborhood_subgraph_dependents_and_dependencies() -> None:
    universe = universe_from_dot(_REPO_DOT)

    dependents = neighborhood_subgraph(universe, "glibc", incoming=True)
    assert {n.label for n in dependents.nodes.values()} == {
        "glibc", "nginx-core", "openssl-libs", "curl", "zlib"
    }

    deps = neighborhood_subgraph(universe, "pkg:nginx-core", incoming=False)
    assert {n.label for n in deps.nodes.values()} == {"nginx-core", "openssl-libs", "glibc"}


def test_build_universe_shares_capability_nodes_and_provider_links() -> None:
    graph = ProvenanceGraph()
    for name in ("app-one", "app-two"):
        graph.add_node(Node(f"rpm:{name}", NodeType.BINARY_RPM, name, {"name": name, "arch": "x86_64"}))

    for subject in ("rpm:app-one", "rpm:app-two"):
        spec = DependencySpec(
            identity=PackageIdentity(Ecosystem.RPM, "libc.so.6"),
            linkage=Linkage.DYNAMIC,
            resolution_state=ResolutionState.OBSERVED,
        )
        add_dependency_claim(graph, DependencyClaim(subject, spec, evidence="elf_dt_needed"))
    # one subject also has the resolved provider claim
    provider = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, "glibc", namespace="almalinux", version="2.34-1.el9"),
        linkage=Linkage.DYNAMIC,
        resolution_state=ResolutionState.RESOLVED,
        raw={"soname": "libc.so.6", "provider": "glibc-2.34-1.el9.x86_64"},
    )
    add_dependency_claim(graph, DependencyClaim("rpm:app-one", provider, evidence="soname_provider"))

    universe = build_universe(graph)

    # The single libc.so.6 capability node is shared by both apps.
    assert "cap:rpm:libc.so.6" in universe.nodes
    assert set(dependents_of(universe, "libc.so.6")) == {"app-one", "app-two"}
    # glibc (the provider) links to the libc.so.6 capability.
    provides = [
        e for e in universe.edges if e.relation == Relation.PROVIDES and e.target == "cap:rpm:libc.so.6"
    ]
    assert len(provides) == 1

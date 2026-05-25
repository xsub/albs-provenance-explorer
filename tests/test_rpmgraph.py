from albs_graph.adapters.rpmgraph import (
    enrich_graph_with_rpmgraph,
    parse_dot_edges,
    run_repograph,
)
from albs_graph.dependency import Ecosystem, ResolutionState
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance import make_binary_rpm_selector

_REPOGRAPH_DOT = """
digraph packages {
"nginx-core" -> "openssl-libs";
"nginx-core" -> "zlib";
"nginx-core" -> "glibc";
"openssl-libs" -> "glibc";
"not-in-build" -> "something";
}
"""

_RPMGRAPH_NEVRA_DOT = """
digraph XYZ {
    rankdir=LR
    "nginx-core-1.20.1-16.el9_4.1.x86_64" -> "zlib-1.2.11-40.el9.x86_64"
}
"""


def _graph_with(names: list[str], arch: str = "x86_64") -> ProvenanceGraph:
    graph = ProvenanceGraph()
    for name in names:
        graph.add_node(
            Node(
                f"rpm:{name}:{arch}",
                NodeType.BINARY_RPM,
                f"{name}-1-1.el9.{arch}.rpm",
                {"name": name, "arch": arch},
            )
        )
    return graph


def test_parse_dot_edges_handles_quoted_and_unquoted() -> None:
    edges = parse_dot_edges(_REPOGRAPH_DOT)
    assert ("nginx-core", "openssl-libs") in edges
    assert ("openssl-libs", "glibc") in edges
    assert len(edges) == 5


def test_parse_dot_edges_captures_multiple_edges_per_line() -> None:
    # Regression: a single line with several edges must yield them all.
    edges = parse_dot_edges('digraph g { "a" -> "b"  "c" -> "b"  "a" -> "c" }')
    assert edges == [("a", "b"), ("c", "b"), ("a", "c")]


def test_parse_dot_edges_expands_repograph_block_form() -> None:
    # Modern `dnf repograph` emits `A -> { B C ... }` spanning lines; each token
    # in the block is an edge A -> token, and the "{" must never become a node.
    dot = (
        'digraph packages {\n'
        '"389-ds-base" [color="0.89 0.99 1.0"];\n'
        '"389-ds-base" -> {\n"perl-libs"\n"nss"\n"zlib-ng-compat"\n}\n'
        '"nss" -> "glibc";\n'
        '}'
    )
    edges = parse_dot_edges(dot)
    assert ("389-ds-base", "perl-libs") in edges
    assert ("389-ds-base", "nss") in edges
    assert ("389-ds-base", "zlib-ng-compat") in edges
    assert ("nss", "glibc") in edges  # simple edge still captured
    assert all(dst != "{" for _src, dst in edges)  # no brace garbage
    # No phantom edge to the color attribute string.
    assert all("0.89" not in dst for _src, dst in edges)


def test_run_repograph_selects_repo_with_repo_flag() -> None:
    # Regression: `dnf repograph appstream` is rejected; the repo goes via --repo.
    captured: dict[str, list[str]] = {}

    def runner(args: list[str]) -> tuple[int, str]:
        captured["args"] = args
        return 0, "digraph g {}"

    run_repograph("appstream", runner=runner)
    assert captured["args"] == ["dnf", "repograph", "--repo", "appstream"]


def test_enrich_adds_resolved_claims_for_matching_subjects() -> None:
    graph = _graph_with(["nginx-core"])
    result = enrich_graph_with_rpmgraph(graph, _REPOGRAPH_DOT)

    assert result.edges == 5
    assert result.matched_edges == 3  # only the three nginx-core -> X edges
    assert result.claims_added == 3
    claim_targets = {
        node.metadata.get("name") for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM)
    }
    assert claim_targets == {"openssl-libs", "zlib", "glibc"}
    for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM):
        assert node.metadata.get("resolution_state") == str(ResolutionState.RESOLVED)
        assert node.metadata.get("ecosystem") == str(Ecosystem.RPM)


def test_enrich_parses_nevra_versions() -> None:
    graph = _graph_with(["nginx-core"])
    enrich_graph_with_rpmgraph(graph, _RPMGRAPH_NEVRA_DOT, evidence="rpmgraph")

    claims = graph.find_by_type(NodeType.DEPENDENCY_CLAIM)
    assert len(claims) == 1
    assert claims[0].metadata.get("name") == "zlib"
    assert claims[0].metadata.get("version") == "1.2.11-40.el9"


def test_enrich_respects_node_selector() -> None:
    graph = _graph_with(["nginx-core"])
    selector = make_binary_rpm_selector(package="something-else")
    result = enrich_graph_with_rpmgraph(graph, _REPOGRAPH_DOT, node_selector=selector)

    assert result.claims_added == 0
    assert graph.find_by_type(NodeType.DEPENDENCY_CLAIM) == []

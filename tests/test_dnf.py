from typing import Any

from albs_graph.adapters import dnf
from albs_graph.adapters.dnf import (
    enrich_graph_with_dnf,
    parse_nevra,
    repoquery,
    whatprovides,
)
from albs_graph.dependency import DependencyScope, ResolutionState
from albs_graph.model import Node, NodeType, ProvenanceGraph


def _runner(args: list[str]) -> tuple[int, str]:
    if "--requires" in args and "--resolve" in args:
        return 0, "glibc-2.34-100.el9_4.2.x86_64\nopenssl-libs-1:3.0.7-27.el9.x86_64\n"
    if "--recommends" in args:
        return 0, "logrotate-3.18.0-9.el9.noarch\n"
    if "--suggests" in args:
        return 0, ""
    if "--conflicts" in args:
        return 0, "nginx < 1:1.20\n"
    if "--obsoletes" in args:
        return 0, ""
    if "--whatprovides" in args:
        return 0, "openssl-libs-1:3.0.7-27.el9.x86_64\n"
    return 0, ""


def _graph() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:nginx-core:x86_64",
            NodeType.BINARY_RPM,
            "nginx-core-1.20.1-16.el9_4.1.x86_64.rpm",
            {"name": "nginx-core", "arch": "x86_64"},
        )
    )
    return graph


def test_parse_nevra_handles_epoch_arch_and_capability_tails() -> None:
    assert parse_nevra("openssl-libs-1:3.0.7-27.el9.x86_64") == ("openssl-libs", "1:3.0.7-27.el9")
    assert parse_nevra("glibc") == ("glibc", None)
    assert parse_nevra("openssl-libs >= 1:3.0.7") == ("openssl-libs", None)


def test_repoquery_and_whatprovides_use_runner() -> None:
    assert "glibc-2.34-100.el9_4.2.x86_64" in repoquery(
        "nginx-core", relation="requires", resolve=True, runner=_runner
    )
    assert whatprovides("libssl.so.3()(64bit)", runner=_runner) == [
        "openssl-libs-1:3.0.7-27.el9.x86_64"
    ]


def test_enrich_adds_resolved_runtime_and_weak_claims() -> None:
    graph = _graph()
    result = enrich_graph_with_dnf(graph, runner=_runner)

    assert result.available is True
    assert result.resolved_claims == 2  # glibc + openssl-libs
    assert result.weak_claims == 1  # logrotate (recommends)
    assert result.relations_recorded == 1  # one conflicts line

    claims = {n.metadata["name"]: n for n in graph.find_by_type(NodeType.DEPENDENCY_CLAIM)}
    assert set(claims) == {"glibc", "openssl-libs", "logrotate"}
    assert claims["glibc"].metadata["scope"] == str(DependencyScope.RUNTIME)
    assert claims["logrotate"].metadata["scope"] == str(DependencyScope.OPTIONAL)
    assert claims["openssl-libs"].metadata["resolution_state"] == str(ResolutionState.RESOLVED)
    assert claims["openssl-libs"].metadata["version"] == "1:3.0.7-27.el9"

    relations = graph.nodes["rpm:nginx-core:x86_64"].metadata["dnf_relations"]
    assert relations["conflicts"] == ["nginx < 1:1.20"]


def test_enrich_without_weak_only_runtime() -> None:
    graph = _graph()
    result = enrich_graph_with_dnf(graph, runner=_runner, include_weak=False)

    assert result.resolved_claims == 2
    assert result.weak_claims == 0


def test_enrich_unavailable_does_not_break(monkeypatch: Any) -> None:
    monkeypatch.setattr(dnf, "dnf_available", lambda: False)
    graph = _graph()
    result = enrich_graph_with_dnf(graph)  # no runner, dnf absent

    assert result.available is False
    assert result.resolved_claims == 0
    assert graph.find_by_type(NodeType.DEPENDENCY_CLAIM) == []

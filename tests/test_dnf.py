from typing import Any

from albs_graph.adapters import dnf
from albs_graph.adapters.dnf import (
    enrich_graph_with_dnf,
    package_licenses,
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


def test_package_licenses_maps_names_to_real_licenses() -> None:
    # `dnf repoquery --qf '%{name}\t%{license}'`: license strings carry spaces
    # but never tabs; multiple repo builds of one name dedupe to the first seen.
    def runner(args: list[str]) -> tuple[int, str]:
        assert "--qf" in args and "%{name}\t%{license}" in args
        return 0, (
            "nginx-core\tBSD-2-Clause\n"
            "glibc\tLGPL-2.1-or-later AND LGPL-2.1-only\n"
            "openssl-libs\tApache-2.0\n"
            "glibc\tLGPL-2.1-or-later AND LGPL-2.1-only\n"  # duplicate build, ignored
        )

    licenses = package_licenses(["nginx-core", "glibc", "openssl-libs"], runner=runner)
    assert licenses == {
        "nginx-core": "BSD-2-Clause",
        "glibc": "LGPL-2.1-or-later AND LGPL-2.1-only",
        "openssl-libs": "Apache-2.0",
    }


def test_enrich_scopes_repoquery_to_the_node_arch() -> None:
    # A node's dnf resolution must be queried for its own arch (name.arch), so a
    # multi-arch graph does not have every arch inherit the host arch's deps.
    queried_specs: list[str] = []

    def runner(args: list[str]) -> tuple[int, str]:
        queried_specs.append(args[-1])  # the package spec is the trailing arg
        return 0, ""

    enrich_graph_with_dnf(_graph(), runner=runner)  # node nginx-core, arch x86_64

    assert queried_specs  # at least one query ran
    assert all(spec == "nginx-core.x86_64" for spec in queried_specs)


def test_package_licenses_empty_names_skips_dnf() -> None:
    def runner(_args: list[str]) -> tuple[int, str]:  # pragma: no cover - must not run
        raise AssertionError("dnf should not be invoked for an empty name list")

    assert package_licenses([], runner=runner) == {}

import json

from albs_graph.dependency import (
    DependencySpec,
    Ecosystem,
    PackageIdentity,
    ResolutionState,
    ResolverRequest,
    resolver_for,
)
from albs_graph.dependency.native_resolvers import CargoResolver, GoResolver
from albs_graph.dependency.resolver import NullResolver
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance import add_resolver_result, coverage_report, reconcile_dependency_claims


def _go_runner(_args: list[str], _cwd: str | None) -> tuple[int, str]:
    return 0, "example.com/myapp\ngithub.com/foo/bar v1.2.3\ngolang.org/x/sys v0.10.0\n"


def test_go_resolver_parses_modules_and_skips_main() -> None:
    result = GoResolver(runner=_go_runner).resolve(ResolverRequest(Ecosystem.GO, "/proj/go.mod"))

    versions = {s.identity.name: s.identity.version for s in result.resolved}
    assert versions == {"github.com/foo/bar": "v1.2.3", "golang.org/x/sys": "v0.10.0"}
    assert result.tool == "go"
    assert all(s.resolution_state == ResolutionState.RESOLVED for s in result.resolved)


def test_go_resolver_failure_marks_requested_unresolvable() -> None:
    spec = DependencySpec(identity=PackageIdentity(Ecosystem.GO, "github.com/x/y"))
    request = ResolverRequest(Ecosystem.GO, "/proj/go.mod", requested=(spec,))
    result = GoResolver(runner=lambda _a, _c: (1, "boom")).resolve(request)

    assert result.resolved == ()
    assert len(result.unresolved) == 1
    assert result.unresolved[0].resolution_state == ResolutionState.UNRESOLVABLE


def test_cargo_resolver_parses_packages() -> None:
    output = json.dumps(
        {"packages": [{"name": "serde", "version": "1.0.0"}, {"name": "libc", "version": "0.2.1"}]}
    )
    result = CargoResolver(runner=lambda _a, _c: (0, output)).resolve(
        ResolverRequest(Ecosystem.CARGO, "/proj/Cargo.toml")
    )

    assert {s.identity.name for s in result.resolved} == {"serde", "libc"}
    assert result.tool == "cargo"


def test_resolver_for_factory() -> None:
    assert isinstance(resolver_for(Ecosystem.GO), GoResolver)
    assert isinstance(resolver_for(Ecosystem.CARGO), CargoResolver)
    assert isinstance(resolver_for(Ecosystem.PYPI), NullResolver)


def test_resolved_deps_feed_graph_and_resolution_axis() -> None:
    graph = ProvenanceGraph()
    graph.add_node(Node("rpm:app", NodeType.BINARY_RPM, "app", {"name": "app"}))
    result = GoResolver(runner=_go_runner).resolve(ResolverRequest(Ecosystem.GO, "/proj/go.mod"))

    add_resolver_result(graph, result, "rpm:app")
    reconcile_dependency_claims(graph)
    report = coverage_report(graph)

    assert report.resolution.covered == 2  # both versioned Go deps resolve -> COMPATIBLE
    assert report.resolution.total == 2

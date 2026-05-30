import json

from albs_graph.dependency import (
    DependencySpec,
    Ecosystem,
    PackageIdentity,
    ResolutionState,
    ResolverRequest,
    resolver_for,
)
from albs_graph.dependency.native_resolvers import (
    CargoResolver,
    GoResolver,
    MavenResolver,
    NpmResolver,
    PypiResolver,
)
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


def test_cargo_resolver_skips_workspace_and_root_crates() -> None:
    # cargo metadata lists the local crate(s) in `packages`; the workspace members
    # are the package being built, not dependencies, so they must be dropped.
    output = json.dumps(
        {
            "packages": [
                {"name": "myapp", "version": "0.1.0", "id": "path+file:///proj#myapp@0.1.0"},
                {"name": "serde", "version": "1.0.0", "id": "registry+https://x#serde@1.0.0"},
            ],
            "workspace_members": ["path+file:///proj#myapp@0.1.0"],
        }
    )
    result = CargoResolver(runner=lambda _a, _c: (0, output)).resolve(
        ResolverRequest(Ecosystem.CARGO, "/proj/Cargo.toml")
    )

    assert {s.identity.name for s in result.resolved} == {"serde"}  # myapp (root) excluded


def test_resolver_for_factory() -> None:
    assert isinstance(resolver_for(Ecosystem.GO), GoResolver)
    assert isinstance(resolver_for(Ecosystem.CARGO), CargoResolver)
    assert isinstance(resolver_for(Ecosystem.PYPI), PypiResolver)
    assert isinstance(resolver_for(Ecosystem.MAVEN), MavenResolver)
    assert isinstance(resolver_for(Ecosystem.NPM), NpmResolver)
    # An ecosystem still without a wired resolver (Gradle today) gets the Null one.
    assert isinstance(resolver_for(Ecosystem.GRADLE), NullResolver)


# ---- PypiResolver -----------------------------------------------------------


def _pip_report(packages: list[tuple[str, str]]) -> str:
    return json.dumps(
        {
            "version": "1",
            "install": [
                {"metadata": {"name": name, "version": version}}
                for name, version in packages
            ],
        }
    )


def test_pypi_resolver_parses_dry_run_report_into_resolved_specs() -> None:
    output = _pip_report([("requests", "2.31.0"), ("urllib3", "2.0.7")])
    result = PypiResolver(runner=lambda _a, _c: (0, output)).resolve(
        ResolverRequest(Ecosystem.PYPI, "/proj/requirements.txt")
    )

    versions = {s.identity.name: s.identity.version for s in result.resolved}
    assert versions == {"requests": "2.31.0", "urllib3": "2.0.7"}
    assert result.tool == "pip"
    assert all(s.resolution_state == ResolutionState.RESOLVED for s in result.resolved)


def test_pypi_resolver_failure_marks_requested_unresolvable() -> None:
    spec = DependencySpec(identity=PackageIdentity(Ecosystem.PYPI, "requests"))
    request = ResolverRequest(Ecosystem.PYPI, "/proj/requirements.txt", requested=(spec,))
    result = PypiResolver(runner=lambda _a, _c: (1, "")).resolve(request)

    assert result.resolved == ()
    assert len(result.unresolved) == 1
    assert result.unresolved[0].resolution_state == ResolutionState.UNRESOLVABLE


def test_pypi_resolver_missing_pip_marks_unresolvable_not_raises() -> None:
    def _missing(_a: list[str], _c: str | None) -> tuple[int, str]:
        raise FileNotFoundError("pip not installed")

    spec = DependencySpec(identity=PackageIdentity(Ecosystem.PYPI, "x"))
    result = PypiResolver(runner=_missing).resolve(
        ResolverRequest(Ecosystem.PYPI, "/proj/requirements.txt", requested=(spec,))
    )
    assert result.resolved == ()
    assert len(result.unresolved) == 1


def test_pypi_resolver_unparseable_output_is_unresolved() -> None:
    spec = DependencySpec(identity=PackageIdentity(Ecosystem.PYPI, "x"))
    # pip succeeded (exit 0) but emitted something that is not the report JSON.
    result = PypiResolver(runner=lambda _a, _c: (0, "not json")).resolve(
        ResolverRequest(Ecosystem.PYPI, "/proj/requirements.txt", requested=(spec,))
    )
    assert result.resolved == ()
    assert len(result.unresolved) == 1


# ---- MavenResolver ----------------------------------------------------------


_MVN_OUTPUT = """\
[INFO] Scanning for projects...
[INFO]
[INFO] -----------------< com.example:demo:jar:1.0.0 >-----------------
[INFO] Building demo 1.0.0
[INFO] --- maven-dependency-plugin:3.6.0:list (default-cli) @ demo ---
[INFO]
[INFO] The following files have been resolved:
[INFO]    com.google.guava:guava:jar:32.1.3-jre:compile
[INFO]    com.google.code.findbugs:jsr305:jar:3.0.2:compile
[INFO]    org.slf4j:slf4j-api:jar:2.0.9:runtime
[INFO]
[INFO] ------------------------------------------------------------------
[INFO] BUILD SUCCESS
"""


def test_maven_resolver_parses_dependency_list_into_g_a_coords() -> None:
    result = MavenResolver(runner=lambda _a, _c: (0, _MVN_OUTPUT)).resolve(
        ResolverRequest(Ecosystem.MAVEN, "/proj/pom.xml")
    )

    names = {s.identity.name for s in result.resolved}
    versions = {s.identity.name: s.identity.version for s in result.resolved}
    # coord is groupId:artifactId; jar packaging is dropped (it's the type, not identity).
    assert names == {
        "com.google.guava:guava",
        "com.google.code.findbugs:jsr305",
        "org.slf4j:slf4j-api",
    }
    assert versions["com.google.guava:guava"] == "32.1.3-jre"
    assert versions["org.slf4j:slf4j-api"] == "2.0.9"
    assert result.tool == "mvn"


def test_maven_resolver_accepts_optional_classifier_token() -> None:
    # Maven supports g:a:p:classifier:v:scope -- one extra token. The regex must
    # still pull out the right version when the classifier is present.
    output = (
        "[INFO] The following files have been resolved:\n"
        "[INFO]    org.example:lib:jar:tests:1.2.3:test\n"
    )
    result = MavenResolver(runner=lambda _a, _c: (0, output)).resolve(
        ResolverRequest(Ecosystem.MAVEN, "/proj/pom.xml")
    )
    assert len(result.resolved) == 1
    spec = result.resolved[0]
    assert spec.identity.name == "org.example:lib"
    assert spec.identity.version == "1.2.3"


def test_maven_resolver_failure_marks_requested_unresolvable() -> None:
    spec = DependencySpec(identity=PackageIdentity(Ecosystem.MAVEN, "g:a"))
    result = MavenResolver(runner=lambda _a, _c: (1, "[ERROR] boom")).resolve(
        ResolverRequest(Ecosystem.MAVEN, "/proj/pom.xml", requested=(spec,))
    )
    assert result.resolved == ()
    assert len(result.unresolved) == 1


# ---- NpmResolver ------------------------------------------------------------


def test_npm_resolver_walks_recursive_dependency_tree_unique() -> None:
    # A nested tree where 'lodash' appears twice (transitively under two
    # different parents) must collapse to one resolved spec, not two.
    tree = {
        "name": "myapp",
        "version": "1.0.0",
        "dependencies": {
            "react": {
                "version": "18.2.0",
                "dependencies": {
                    "loose-envify": {"version": "1.4.0"},
                },
            },
            "axios": {
                "version": "1.6.0",
                "dependencies": {
                    "lodash": {"version": "4.17.21"},
                },
            },
            "lodash": {"version": "4.17.21"},  # same version appears at top too
        },
    }
    result = NpmResolver(runner=lambda _a, _c: (0, json.dumps(tree))).resolve(
        ResolverRequest(Ecosystem.NPM, "/proj/package.json")
    )

    names = sorted({s.identity.name for s in result.resolved})
    versions = {s.identity.name: s.identity.version for s in result.resolved}
    assert names == ["axios", "lodash", "loose-envify", "react"]
    # 'myapp' (the root) is not in the dependencies tree; it must not appear.
    assert "myapp" not in names
    # Lodash collapsed to one spec across the two appearances.
    assert sum(1 for s in result.resolved if s.identity.name == "lodash") == 1
    assert versions["react"] == "18.2.0"
    assert result.tool == "npm"


def test_npm_resolver_tolerates_nonzero_exit_when_tree_is_present() -> None:
    # npm exits non-zero on peer-dep warnings but still emits the valid tree.
    # The resolver must accept that case (rather than discard the tree).
    tree = {"name": "x", "version": "1.0.0", "dependencies": {"react": {"version": "18.2.0"}}}
    result = NpmResolver(runner=lambda _a, _c: (1, json.dumps(tree))).resolve(
        ResolverRequest(Ecosystem.NPM, "/proj/package.json")
    )
    assert {s.identity.name for s in result.resolved} == {"react"}


def test_npm_resolver_nonzero_exit_and_empty_tree_is_unresolved() -> None:
    spec = DependencySpec(identity=PackageIdentity(Ecosystem.NPM, "x"))
    result = NpmResolver(runner=lambda _a, _c: (1, json.dumps({}))).resolve(
        ResolverRequest(Ecosystem.NPM, "/proj/package.json", requested=(spec,))
    )
    assert result.resolved == ()
    assert len(result.unresolved) == 1


def test_npm_resolver_garbled_json_is_unresolved() -> None:
    spec = DependencySpec(identity=PackageIdentity(Ecosystem.NPM, "x"))
    result = NpmResolver(runner=lambda _a, _c: (0, "not json at all")).resolve(
        ResolverRequest(Ecosystem.NPM, "/proj/package.json", requested=(spec,))
    )
    assert result.resolved == ()
    assert len(result.unresolved) == 1


def test_resolved_deps_feed_graph_and_resolution_axis() -> None:
    graph = ProvenanceGraph()
    graph.add_node(Node("rpm:app", NodeType.BINARY_RPM, "app", {"name": "app"}))
    result = GoResolver(runner=_go_runner).resolve(ResolverRequest(Ecosystem.GO, "/proj/go.mod"))

    add_resolver_result(graph, result, "rpm:app")
    reconcile_dependency_claims(graph)
    report = coverage_report(graph)

    assert report.resolution.covered == 2  # both versioned Go deps resolve -> COMPATIBLE
    assert report.resolution.total == 2

from albs_graph.adapters.dnf import (
    build_soname_index,
    collect_soname_names,
    resolve_soname_claims,
)
from albs_graph.dependency import (
    DependencySpec,
    Ecosystem,
    Linkage,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance import (
    Agreement,
    ConflictKind,
    DependencyClaim,
    add_dependency_claim,
    reconcile_dependency_claims,
)

SUBJECT = "rpm:app:1.0:x86_64"
_PROVIDERS = {
    "libz.so.1()(64bit)": "zlib-1.2.11-40.el9.x86_64",
    "libssl.so.3()(64bit)": "openssl-libs-1:3.0.7-27.el9.x86_64",
}


def _graph() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(Node(SUBJECT, NodeType.BINARY_RPM, "app", {"name": "app", "arch": "x86_64"}))
    return graph


def _soname_claim(soname: str, evidence: str = "elf_dt_needed") -> DependencyClaim:
    spec = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, soname),
        linkage=Linkage.DYNAMIC,
        resolution_state=ResolutionState.OBSERVED,
    )
    return DependencyClaim(SUBJECT, spec, evidence=evidence)


def _pkg_claim(name: str, version: str, evidence: str) -> DependencyClaim:
    spec = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, name, namespace="almalinux", version=version),
        resolution_state=ResolutionState.OBSERVED,
    )
    return DependencyClaim(SUBJECT, spec, evidence=evidence)


def _whatprovides_runner(args: list[str]) -> tuple[int, str]:
    capability = args[-1]
    provider = _PROVIDERS.get(capability)
    return 0, (provider + "\n" if provider else "")


def test_collect_soname_names() -> None:
    graph = _graph()
    add_dependency_claim(graph, _soname_claim("libz.so.1"))
    add_dependency_claim(graph, _soname_claim("libssl.so.3", evidence="rpm_header_soname"))

    assert collect_soname_names(graph) == ["libssl.so.3", "libz.so.1"]


def test_build_soname_index_uses_whatprovides() -> None:
    index = build_soname_index(["libz.so.1", "libssl.so.3"], runner=_whatprovides_runner)

    assert index["libz.so.1"] == "zlib-1.2.11-40.el9.x86_64"
    assert index["libssl.so.3"] == "openssl-libs-1:3.0.7-27.el9.x86_64"


def test_resolve_adds_package_provider_claims() -> None:
    graph = _graph()
    add_dependency_claim(graph, _soname_claim("libz.so.1"))
    result = resolve_soname_claims(graph, {"libz.so.1": "zlib-1.2.11-40.el9.x86_64"})

    assert result.sonames == 1
    assert result.resolved == 1
    assert result.claims_added == 1
    provider = next(
        node
        for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM)
        if node.metadata.get("evidence") == "soname_provider"
    )
    assert provider.metadata["name"] == "zlib"
    assert provider.metadata["version"] == "1.2.11-40.el9"


def test_resolved_soname_corroborates_sbom_package() -> None:
    graph = _graph()
    add_dependency_claim(graph, _soname_claim("libz.so.1"))
    add_dependency_claim(graph, _pkg_claim("zlib", "1.2.11-40.el9", evidence="sbom"))
    resolve_soname_claims(graph, {"libz.so.1": "zlib-1.2.11-40.el9.x86_64"})

    report = reconcile_dependency_claims(graph)
    zlib = next(
        node
        for node in graph.find_by_type(NodeType.DEPENDENCY_RESOLUTION)
        if node.metadata.get("coordinate", "").endswith("zlib")
    )
    # SBOM + soname_provider agree on the same version -> consensus, no conflict.
    assert zlib.metadata["agreement"] == str(Agreement.CONSENSUS)
    assert report.conflict_count == 0


def test_elf_soname_not_flagged_undeclared_with_sbom_present() -> None:
    # Regression: rung-4 "elf_dt_needed" sonames carry no "soname" token, so the
    # old evidence-string check would falsely flag them once an SBOM made the
    # subject "have declarations". Soname detection is now name-based.
    graph = _graph()
    add_dependency_claim(graph, _pkg_claim("zlib", "1.2.11-40.el9", evidence="sbom"))
    add_dependency_claim(graph, _soname_claim("libssl.so.3", evidence="elf_dt_needed"))

    report = reconcile_dependency_claims(graph)

    assert not any(c.kind == ConflictKind.PRESENCE_UNDECLARED for c in report.conflicts)

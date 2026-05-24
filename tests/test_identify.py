from typing import Any

from albs_graph.fixtures import build_synthetic_fixture_graph
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance import identify_file
from albs_graph.provenance import identify as identify_mod


def test_identify_traces_full_creation_chain() -> None:
    graph = build_synthetic_fixture_graph()
    report = identify_file(graph, "/usr/sbin/synthetic", owner_package="synthetic-core")

    assert report.found is True
    assert report.package == "synthetic-core"
    roles = {element.role for element in report.elements}
    assert {
        "source_package",
        "git_repository",
        "git_commit",
        "build_task",
        "build_environment",
        "srpm",
        "binary_rpm",
        "signature",
        "repository_release",
        "sbom",
    } <= roles
    assert report.provenance_complete is True
    assert report.security_context_complete is True
    assert report.dependencies  # at least the fixture runtime dependency


def test_identify_uses_owner_lookup() -> None:
    graph = build_synthetic_fixture_graph()
    report = identify_file(graph, "/anything", owner_lookup=lambda _p: "synthetic-core")

    assert report.found is True
    assert report.package == "synthetic-core"


def test_identify_resolves_owner_from_elf_paths() -> None:
    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:foo",
            NodeType.BINARY_RPM,
            "foo-1-1.el9.x86_64.rpm",
            {"name": "foo", "elf_analysis": {"dlopen": ["./usr/bin/foo"], "static": []}},
        )
    )
    report = identify_file(graph, "/usr/bin/foo")

    assert report.found is True
    assert report.package == "foo"
    assert {element.role for element in report.elements} == {"binary_rpm"}


def test_identify_falls_back_to_dnf_when_rpm_qf_misses(monkeypatch: Any) -> None:
    # When the file is not installed locally (rpm -qf misses), dnf repoquery
    # --file resolves the owning package from the repos.
    monkeypatch.setattr(identify_mod, "_host_rpm_qf", lambda _p: None)
    monkeypatch.setattr(identify_mod, "_host_dnf_file_owner", lambda _p: "synthetic-core")
    graph = build_synthetic_fixture_graph()

    report = identify_file(graph, "/usr/sbin/synthetic")

    assert report.found is True
    assert report.package == "synthetic-core"


def test_identify_reports_not_found_for_unknown_package() -> None:
    graph = build_synthetic_fixture_graph()
    report = identify_file(graph, "/nope", owner_package="ghost-package")

    assert report.found is False
    assert report.detail is not None

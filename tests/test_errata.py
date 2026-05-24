import json
from pathlib import Path

from albs_graph.adapters.errata import attach_errata_file
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.provenance import coverage_report

_ERRATA = {
    "id": "ALSA-2026-1234",
    "type": "security",
    "severity": "Important",
    "issued": "2026-01-01",
    "cves": ["CVE-2026-1111", "CVE-2026-2222"],
}


def _errata_file(tmp_path: Path) -> Path:
    path = tmp_path / "errata.json"
    path.write_text(json.dumps(_ERRATA), encoding="utf-8")
    return path


def _subject_graph() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(Node("rpm:nginx-core", NodeType.BINARY_RPM, "nginx-core", {"name": "nginx-core"}))
    return graph


def test_attach_errata_creates_errata_and_cve_nodes(tmp_path: Path) -> None:
    graph = _subject_graph()
    errata_id = attach_errata_file(graph, "rpm:nginx-core", _errata_file(tmp_path))

    assert errata_id == "errata:ALSA-2026-1234"
    assert len(graph.find_by_type(NodeType.ERRATA)) == 1
    assert len(graph.find_by_type(NodeType.CVE)) == 2
    assert any(
        edge.relation == Relation.FIXES and edge.source == "rpm:nginx-core" for edge in graph.edges
    )


def test_errata_plus_sbom_completes_security_context(tmp_path: Path) -> None:
    graph = _subject_graph()
    # An attached SBOM gives has_sbom; security context still needs errata.
    graph.add_node(Node("sbom:nginx-core", NodeType.SBOM, "nginx-core.cdx.json", {}))
    graph.add_edge("rpm:nginx-core", "sbom:nginx-core", Relation.DESCRIBED_BY)
    assert graph.trust_path_report("rpm:nginx-core").security_context_complete is False

    attach_errata_file(graph, "rpm:nginx-core", _errata_file(tmp_path))

    assert graph.trust_path_report("rpm:nginx-core").security_context_complete is True
    assert coverage_report(graph).security_context.covered == 1

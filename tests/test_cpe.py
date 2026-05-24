from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance import coverage_report
from albs_graph.security import cpe_security_identity
from albs_graph.security.cpe import CpeDictionary, verify_graph_cpe, verify_security_identity

_DICT = CpeDictionary.from_cpe23(
    [
        "cpe:2.3:a:nginx:nginx-core:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:foo:libfoo:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:bar:libfoo:*:*:*:*:*:*:*:*",  # two vendors -> ambiguous
    ]
)


def test_dictionary_parses_vendor_product() -> None:
    assert _DICT.vendors_for("nginx-core") == ["nginx"]
    assert _DICT.vendors_for("libfoo") == ["bar", "foo"]
    assert _DICT.vendors_for("absent") == []


def test_verify_single_vendor_sets_cpe() -> None:
    identity = cpe_security_identity("nginx-core", "1.20.1")
    assert verify_security_identity(identity, _DICT) == "verified"
    assert identity["cpe"].startswith("cpe:2.3:a:nginx:nginx-core:1.20.1")
    assert any(candidate.get("verified") for candidate in identity["cpe_candidates"])


def test_verify_ambiguous_vendor_does_not_assert_cpe() -> None:
    identity = cpe_security_identity("libfoo", "1.0")
    assert verify_security_identity(identity, _DICT) == "ambiguous_vendor"
    assert identity.get("cpe") is None
    assert identity["cpe_vendor_candidates"] == ["bar", "foo"]


def test_verify_graph_moves_identity_axis_and_flags_backport() -> None:
    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:nginx-core",
            NodeType.BINARY_RPM,
            "nginx-core",
            {
                "name": "nginx-core",
                "arch": "x86_64",
                "release": "16.el9_4.1",
                "security_identity": cpe_security_identity("nginx-core", "1.20.1"),
            },
        )
    )
    assert coverage_report(graph).identity.covered == 0

    result = verify_graph_cpe(graph, _DICT)

    assert result.verified == 1
    assert result.backported == 1
    assert coverage_report(graph).identity.covered == 1
    assert graph.nodes["rpm:nginx-core"].metadata["security_identity"]["distro_backport"] is True

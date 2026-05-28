from copy import deepcopy

from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.model.patch import RecordingGraph
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


def _seeded_graph() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:nginx-core",
            NodeType.BINARY_RPM,
            "nginx-core",
            {
                "name": "nginx-core",
                "arch": "x86_64",
                "release": "16.el10_2.alma.1",
                "security_identity": cpe_security_identity("nginx-core", "1.20.1"),
            },
        )
    )
    return graph


def test_verify_graph_cpe_on_a_copy_does_not_mutate_the_original() -> None:
    # Regression: ProvenanceGraph.copy() used to be shallow, so verify_graph_cpe
    # mutating identity (or a nested cpe_candidates entry) in place leaked back
    # into the source graph -- dry_run was a lie. With the deep copy in copy()
    # + the cpe adapter routing through update_metadata, the source stays clean.
    source = _seeded_graph()
    original_identity = deepcopy(source.nodes["rpm:nginx-core"].metadata["security_identity"])

    clone = source.copy()
    verify_graph_cpe(clone, _DICT)

    assert clone.nodes["rpm:nginx-core"].metadata["security_identity"]["cpe_status"] == "verified"
    # The source must be byte-identical to its pre-verification state.
    assert source.nodes["rpm:nginx-core"].metadata["security_identity"] == original_identity


def test_verify_graph_cpe_changes_are_captured_in_the_evidence_patch() -> None:
    # Regression: in-place mutation of identity bypassed RecordingGraph, so CPE
    # verification never showed up in the patch (silent change). Routing through
    # update_metadata makes it appear in metadata_updates.
    recorder = RecordingGraph(_seeded_graph())
    verify_graph_cpe(recorder, _DICT)

    assert any(
        "security_identity" in updates for _, updates in recorder.patch.metadata_updates
    ), "CPE verification did not surface in EvidencePatch.metadata_updates"

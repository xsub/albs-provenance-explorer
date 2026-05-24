from typing import Any

from albs_graph.adapters import rpmsig
from albs_graph.adapters.rpmsig import (
    checksig_bytes,
    parse_checksig,
    verify_graph_signatures,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation


def _ok(args: list[str]) -> tuple[int, str]:
    return 0, f"{args[-1]}: digests signatures OK\n"


def _nokey(args: list[str]) -> tuple[int, str]:
    return 1, f"{args[-1]}: digests SIGNATURES NOKEY\n"


def _bad(args: list[str]) -> tuple[int, str]:
    return 1, f"{args[-1]}: digests SIGNATURES NOT OK\n"


def test_parse_checksig_statuses() -> None:
    assert parse_checksig(0, "x.rpm: digests signatures OK") == "verified"
    assert parse_checksig(1, "x.rpm: digests SIGNATURES NOKEY") == "nokey"
    assert parse_checksig(1, "x.rpm: NOT OK") == "failed"


def test_checksig_bytes_with_runner() -> None:
    assert checksig_bytes("x.rpm", b"rpm", runner=_ok).status == "verified"
    assert checksig_bytes("x.rpm", b"rpm", runner=_nokey).status == "nokey"
    assert checksig_bytes("x.rpm", b"rpm", runner=_bad).status == "failed"


def test_checksig_unavailable_when_rpmkeys_missing(monkeypatch: Any) -> None:
    monkeypatch.setattr(rpmsig, "rpmkeys_available", lambda: False)
    assert checksig_bytes("x.rpm", b"rpm").status == "unavailable"


def _graph() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:nginx-core",
            NodeType.BINARY_RPM,
            "nginx-core-1-1.el9.x86_64.rpm",
            {"filename": "nginx-core-1-1.el9.x86_64.rpm", "name": "nginx-core", "arch": "x86_64"},
        )
    )
    graph.add_node(Node("sig:1", NodeType.SIGNATURE, "sign task 1", {"externally_verified": False}))
    graph.add_edge("rpm:nginx-core", "sig:1", Relation.SIGNED_AS)
    return graph


def test_verify_graph_signatures_flips_flags_on_success() -> None:
    graph = _graph()
    report = verify_graph_signatures(
        graph,
        fetch_full=lambda _url: b"rpm-bytes",
        url_resolver=lambda _filename: ["http://example/nginx-core.rpm"],
        runner=_ok,
    )

    assert report.requested is True
    assert report.available is True
    assert report.verified == 1
    assert graph.nodes["rpm:nginx-core"].metadata["signature_verified"] is True
    assert graph.nodes["sig:1"].metadata["externally_verified"] is True


def test_verify_graph_signatures_nokey_keeps_unverified() -> None:
    graph = _graph()
    report = verify_graph_signatures(
        graph,
        fetch_full=lambda _url: b"rpm-bytes",
        url_resolver=lambda _filename: ["http://example/nginx-core.rpm"],
        runner=_nokey,
    )

    assert report.nokey == 1
    assert report.verified == 0
    assert graph.nodes["rpm:nginx-core"].metadata["signature_verified"] is False
    assert graph.nodes["sig:1"].metadata["externally_verified"] is False


def test_verify_graph_signatures_unavailable_does_not_break(monkeypatch: Any) -> None:
    monkeypatch.setattr(rpmsig, "rpmkeys_available", lambda: False)
    graph = _graph()
    report = verify_graph_signatures(graph)  # no runner, rpmkeys absent

    assert report.requested is True
    assert report.available is False
    assert report.unavailable == report.binaries == 1
    assert "signature_verified" not in graph.nodes["rpm:nginx-core"].metadata

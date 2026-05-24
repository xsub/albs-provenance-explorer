from typing import Any

from albs_graph.adapters import cas
from albs_graph.adapters.cas import verify_graph_cas, verify_hash
from albs_graph.fixtures import build_synthetic_fixture_graph
from albs_graph.model import NodeType


def _ok(_args: list[str]) -> tuple[int, str]:
    return 0, "verified"


def _fail(_args: list[str]) -> tuple[int, str]:
    return 1, "not notarized"


def _cas_nodes(graph: Any) -> list[Any]:
    return [
        node
        for node in graph.find_by_type(NodeType.CAS_ATTESTATION)
        if node.metadata.get("cas_hash")
    ]


def test_verify_hash_with_injected_runner() -> None:
    assert verify_hash("abc", runner=_ok).status == "verified"
    assert verify_hash("abc", runner=_fail).status == "failed"


def test_verify_hash_unavailable_when_cas_missing(monkeypatch: Any) -> None:
    monkeypatch.setattr(cas, "cas_available", lambda: False)
    result = verify_hash("abc")  # no runner -> uses real cas, which is absent
    assert result.status == "unavailable"


def test_use_cas_false_changes_nothing() -> None:
    graph = build_synthetic_fixture_graph()
    report = verify_graph_cas(graph, use_cas=False)

    assert report.requested is False
    assert report.attestations == len(_cas_nodes(graph))
    assert all(node.metadata.get("externally_verified") is False for node in _cas_nodes(graph))


def test_use_cas_verified_flips_external_verification() -> None:
    graph = build_synthetic_fixture_graph()
    report = verify_graph_cas(graph, use_cas=True, runner=_ok)

    assert report.requested is True
    assert report.available is True
    assert report.verified == report.attestations
    assert all(node.metadata.get("externally_verified") is True for node in _cas_nodes(graph))


def test_use_cas_failed_keeps_unverified() -> None:
    graph = build_synthetic_fixture_graph()
    report = verify_graph_cas(graph, use_cas=True, runner=_fail)

    assert report.failed == report.attestations
    assert report.verified == 0
    assert all(node.metadata.get("externally_verified") is False for node in _cas_nodes(graph))


def test_use_cas_unavailable_does_not_break(monkeypatch: Any) -> None:
    monkeypatch.setattr(cas, "cas_available", lambda: False)
    graph = build_synthetic_fixture_graph()
    report = verify_graph_cas(graph, use_cas=True)  # no runner, cas absent

    assert report.requested is True
    assert report.available is False
    assert report.unavailable == report.attestations
    assert report.verified == 0
    assert all(node.metadata.get("externally_verified") is False for node in _cas_nodes(graph))

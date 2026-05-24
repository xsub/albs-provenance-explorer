import gzip

import pytest

from albs_graph.adapters.rpm_payload import (
    PayloadError,
    analyze_rpm_payload,
    decompress_payload,
    enrich_graph_with_rpm_payloads,
    iter_cpio,
    payload_contents,
    payload_dependency_claims,
)
from albs_graph.dependency import Linkage
from albs_graph.model import Node, NodeType, ProvenanceGraph
from synthetic_binaries import build_elf, build_rpm

_FILENAME = "demo-1.0-1.el9.x86_64.rpm"


def _demo_rpm() -> bytes:
    return build_rpm(
        {
            "./usr/lib64/mylib.so.1": build_elf(),
            "./usr/share/doc/demo/README": b"just text, not elf\n",
        }
    )


def test_decompress_payload_gzip_and_unknown() -> None:
    assert decompress_payload(gzip.compress(b"hello"), "gzip") == b"hello"
    with pytest.raises(PayloadError):
        decompress_payload(b"\x00\x00", "lzip")


def test_iter_cpio_yields_regular_files() -> None:
    rpm = _demo_rpm()
    # The payload starts after the header; analyze_rpm_payload handles that,
    # but exercise iter_cpio directly on a decompressed archive too.
    from albs_graph.adapters.rpm_header import parse_rpm_header

    header = parse_rpm_header(rpm)
    raw = decompress_payload(rpm[header.payload_offset :], header.payload_compressor)
    names = {name for name, _ in iter_cpio(raw)}
    assert "./usr/lib64/mylib.so.1" in names
    assert "./usr/share/doc/demo/README" in names


def test_analyze_rpm_payload_finds_only_elf_objects() -> None:
    elfs = analyze_rpm_payload(_demo_rpm())

    assert len(elfs) == 1
    path, info = elfs[0]
    assert path == "./usr/lib64/mylib.so.1"
    assert set(info.needed) == {"libc.so.6", "libssl.so.3"}
    assert info.dlopen is True


def test_payload_contents_returns_all_files_and_elfs() -> None:
    elfs, files = payload_contents(_demo_rpm())

    assert len(elfs) == 1  # only the ELF object
    assert set(files) == {"./usr/lib64/mylib.so.1", "./usr/share/doc/demo/README"}


def test_payload_dependency_claims_are_dynamic_needed() -> None:
    claims = payload_dependency_claims("rpm:demo", analyze_rpm_payload(_demo_rpm()))

    assert {claim.spec.identity.name for claim in claims} == {"libc.so.6", "libssl.so.3"}
    assert all(claim.spec.linkage == Linkage.DYNAMIC for claim in claims)
    assert all(claim.evidence == "elf_dt_needed" for claim in claims)


def test_enrich_graph_records_elf_analysis_and_claims() -> None:
    graph = ProvenanceGraph()
    graph.add_node(Node("rpm:demo", NodeType.BINARY_RPM, _FILENAME, {"filename": _FILENAME}))

    result = enrich_graph_with_rpm_payloads(
        graph,
        fetch_full=lambda _url: _demo_rpm(),
        url_resolver=lambda _filename: ["http://example/demo.rpm"],
    )

    assert result.payloads_read == 1
    assert result.elf_objects == 1
    assert result.soname_claims == 2
    analysis = graph.nodes["rpm:demo"].metadata["elf_analysis"]
    assert analysis["runpath"] == ["/opt/lib", "/usr/lib"]
    assert analysis["dlopen"] == ["./usr/lib64/mylib.so.1"]
    assert len(graph.find_by_type(NodeType.DEPENDENCY_CLAIM)) == 2
    # Full file list is recorded, including the non-ELF doc file.
    assert "./usr/share/doc/demo/README" in graph.nodes["rpm:demo"].metadata["files"]

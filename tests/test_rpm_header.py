from typing import Callable

from albs_graph.adapters.rpm_header import (
    RpmHeaderError,
    classify_capability,
    parse_rpm_header,
    required_header_length,
)
from albs_graph.adapters.rpm_remote import (
    enrich_graph_with_rpm_headers,
    fetch_rpm_header,
    header_dependency_claims,
    vault_candidate_urls,
)
from albs_graph.dependency import Linkage
from albs_graph.model import Node, NodeType, ProvenanceGraph

# RPM header data types.
_STRING = 6
_INT32 = 4
_STRING_ARRAY = 8

_REQUIRES = [
    "libc.so.6()(64bit)",
    "libssl.so.3",
    "rpmlib(CompressedFileNames) <= 3.0.4-1",
    "bash",
    "/bin/sh",
    "(nginx if systemd)",
]


def _section(entries: list[tuple[int, int, object]]) -> bytes:
    store = bytearray()
    index: list[tuple[int, int, int, int]] = []
    for tag, dtype, value in entries:
        offset = len(store)
        if dtype == _STRING and isinstance(value, str):
            store += value.encode() + b"\x00"
            count = 1
        elif dtype == _STRING_ARRAY and isinstance(value, list):
            for item in value:
                store += str(item).encode() + b"\x00"
            count = len(value)
        elif dtype == _INT32 and isinstance(value, list):
            for number in value:
                store += int(number).to_bytes(4, "big")
            count = len(value)
        else:  # pragma: no cover - test data only
            raise AssertionError(f"unsupported test tag type {dtype}")
        index.append((tag, dtype, offset, count))
    out = bytearray(b"\x8e\xad\xe8\x01" + b"\x00" * 4)
    out += len(index).to_bytes(4, "big") + len(store).to_bytes(4, "big")
    for tag, dtype, offset, count in index:
        out += tag.to_bytes(4, "big") + dtype.to_bytes(4, "big")
        out += offset.to_bytes(4, "big") + count.to_bytes(4, "big")
    out += store
    return bytes(out)


def _build_rpm(
    *,
    name: str = "nginx-core",
    version: str = "1.20.1",
    release: str = "16.el9_4.1",
    arch: str = "x86_64",
    requires: list[str] | None = None,
) -> bytes:
    reqs = requires if requires is not None else _REQUIRES
    lead = b"\xed\xab\xee\xdb" + b"\x00" * 92  # 96-byte lead
    # Signature header with one short string tag, forcing 8-byte padding.
    sig = _section([(62, _STRING, "sig")])
    sig += b"\x00" * ((8 - (len(sig) % 8)) % 8)
    main = _section(
        [
            (1000, _STRING, name),
            (1001, _STRING, version),
            (1002, _STRING, release),
            (1022, _STRING, arch),
            (1049, _STRING_ARRAY, reqs),
            (1048, _INT32, [0] * len(reqs)),
        ]
    )
    payload = b"\x1f\x8b" + b"\x00" * 64  # token "compressed payload"
    return lead + sig + main + payload


def _range_fetcher(blob: bytes) -> Callable[[str, int, int], bytes]:
    def fetch(_url: str, start: int, end: int) -> bytes:
        return blob[start : end + 1]

    return fetch


def test_classify_capability_distinguishes_sonames() -> None:
    assert classify_capability("libssl.so.3()(64bit)") == ("soname", "libssl.so.3")
    assert classify_capability("bash") == ("package", None)
    assert classify_capability("/bin/sh") == ("file", None)
    assert classify_capability("rpmlib(Foo)") == ("rpmlib", None)
    assert classify_capability("(a if b)") == ("rich", None)


def test_parse_rpm_header_extracts_nevra_and_requires() -> None:
    header = parse_rpm_header(_build_rpm())

    assert header.name == "nginx-core"
    assert header.version == "1.20.1"
    assert header.arch == "x86_64"
    sonames = {dep.soname for dep in header.soname_requires}
    assert sonames == {"libc.so.6", "libssl.so.3"}
    # rpmlib/file/rich capabilities are present but not classified as sonames.
    assert len(header.requires) == len(_REQUIRES)


def test_required_header_length_grows_as_structure_becomes_readable() -> None:
    blob = _build_rpm()
    # With only the lead, we only know we need the signature intro.
    assert required_header_length(blob[:32]) == 96 + 16
    # With the whole file, the required length is bounded by the header, not payload.
    full = required_header_length(blob)
    assert full < len(blob)


def test_parse_rpm_header_rejects_non_rpm() -> None:
    try:
        parse_rpm_header(b"not an rpm" + b"\x00" * 200)
    except RpmHeaderError:
        return
    raise AssertionError("expected RpmHeaderError")


def test_fetch_rpm_header_drives_incremental_range_reads() -> None:
    blob = _build_rpm()
    header = fetch_rpm_header("http://example/test.rpm", _range_fetcher(blob))

    assert header.name == "nginx-core"
    claims = header_dependency_claims("rpm:test", header)
    assert {claim.spec.identity.name for claim in claims} == {"libc.so.6", "libssl.so.3"}
    assert all(claim.spec.linkage == Linkage.DYNAMIC for claim in claims)
    assert all(claim.evidence == "rpm_header_soname" for claim in claims)


def test_enrich_graph_adds_dynamic_linkage_claims() -> None:
    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:nginx-core",
            NodeType.BINARY_RPM,
            "nginx-core-1.20.1-16.el9_4.1.x86_64.rpm",
            {"name": "nginx-core", "filename": "nginx-core-1.20.1-16.el9_4.1.x86_64.rpm"},
        )
    )
    result = enrich_graph_with_rpm_headers(
        graph,
        fetch=_range_fetcher(_build_rpm()),
        url_resolver=lambda _filename: ["http://example/nginx-core.rpm"],
    )

    assert result.headers_fetched == 1
    assert result.claims_added == 2
    assert result.failures == ()
    claim_nodes = graph.find_by_type(NodeType.DEPENDENCY_CLAIM)
    assert len(claim_nodes) == 2
    assert all(node.metadata.get("linkage") == "dynamic" for node in claim_nodes)


def test_vault_candidate_urls_reconstructs_point_release_path() -> None:
    urls = vault_candidate_urls("nginx-core-1.20.1-16.el9_4.1.x86_64.rpm")

    assert (
        "https://repo.almalinux.org/vault/9.4/AppStream/x86_64/os/Packages/"
        "nginx-core-1.20.1-16.el9_4.1.x86_64.rpm" in urls
    )
    # A malformed filename yields no candidates rather than a bad guess.
    assert vault_candidate_urls("not-an-rpm") == []

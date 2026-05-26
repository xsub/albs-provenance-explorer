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
from albs_graph.provenance import reconcile_dependency_claims, resolution_details

# RPM header data types.
_STRING = 6
_INT32 = 4
_STRING_ARRAY = 8

# (capability, RPMSENSE flags, version): flags 8 = "=", 12 = ">=", 10 = "<=".
_REQUIRES = [
    ("libc.so.6()(64bit)", 0, ""),
    ("libssl.so.3", 0, ""),
    ("rpmlib(CompressedFileNames)", 10, "3.0.4-1"),
    ("bash", 0, ""),
    ("/bin/sh", 0, ""),
    ("(nginx if systemd)", 0, ""),
    ("openssl-libs", 12, "1:3.0.7"),  # versioned range require (>=)
    ("nginx-filesystem", 8, "1:1.20.1-16.el9_4.1"),  # exact-version require (=)
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
    license: str = "BSD-2-Clause",
    requires: list[tuple[str, int, str]] | None = None,
) -> bytes:
    reqs = requires if requires is not None else _REQUIRES
    names = [r[0] for r in reqs]
    flags = [r[1] for r in reqs]
    versions = [r[2] for r in reqs]
    lead = b"\xed\xab\xee\xdb" + b"\x00" * 92  # 96-byte lead
    # Signature header with one short string tag, forcing 8-byte padding.
    sig = _section([(62, _STRING, "sig")])
    sig += b"\x00" * ((8 - (len(sig) % 8)) % 8)
    main = _section(
        [
            (1000, _STRING, name),
            (1001, _STRING, version),
            (1002, _STRING, release),
            (1014, _STRING, license),  # RPMTAG_LICENSE
            (1022, _STRING, arch),
            (1049, _STRING_ARRAY, names),
            (1048, _INT32, flags),
            (1050, _STRING_ARRAY, versions),
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
    assert classify_capability("rtld(GNU_HASH)") == ("rpmlib", None)
    assert classify_capability("(a if b)") == ("rich", None)


def test_parse_rpm_header_extracts_nevra_and_requires() -> None:
    header = parse_rpm_header(_build_rpm())

    assert header.name == "nginx-core"
    assert header.version == "1.20.1"
    assert header.arch == "x86_64"
    assert header.license == "BSD-2-Clause"  # RPMTAG_LICENSE (1014)
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


def test_header_package_requires_carry_versions_and_constraints() -> None:
    header = fetch_rpm_header("http://example/test.rpm", _range_fetcher(_build_rpm()))
    claims = header_dependency_claims("rpm:test", header, include_packages=True)
    by_name = {claim.spec.identity.name: claim for claim in claims}

    # Sonames stay dynamic-linkage observations.
    assert by_name["libssl.so.3"].spec.linkage == Linkage.DYNAMIC
    assert by_name["libssl.so.3"].evidence == "rpm_header_soname"
    # Package requires become rpm_header_requires claims: "=" -> concrete version,
    # ">=" -> a requested constraint string, bare name -> neither.
    assert by_name["nginx-filesystem"].evidence == "rpm_header_requires"
    assert by_name["nginx-filesystem"].spec.identity.version == "1:1.20.1-16.el9_4.1"
    assert by_name["openssl-libs"].spec.requested == "openssl-libs >= 1:3.0.7"
    assert by_name["openssl-libs"].spec.identity.version is None
    assert by_name["bash"].spec.identity.version is None
    assert by_name["bash"].spec.requested is None
    # rpmlib / file / rich capabilities are not package requires.
    assert "/bin/sh" not in by_name


def test_versioned_package_require_reconciles_as_compatible() -> None:
    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:nginx-core",
            NodeType.BINARY_RPM,
            "nginx-core-1.20.1-16.el9_4.1.x86_64.rpm",
            {"name": "nginx-core", "filename": "nginx-core-1.20.1-16.el9_4.1.x86_64.rpm"},
        )
    )
    enrich_graph_with_rpm_headers(
        graph,
        fetch=_range_fetcher(_build_rpm()),
        url_resolver=lambda _filename: ["http://example/nginx-core.rpm"],
    )
    reconcile_dependency_claims(graph)

    # The exact-version package require resolves to a concrete version (COMPATIBLE),
    # so it counts toward the resolution axis instead of staying insufficient.
    nginx_fs = next(d for d in resolution_details(graph) if "nginx-filesystem" in d.coordinate)
    assert nginx_fs.agreement == "compatible"
    assert nginx_fs.versions == ("1:1.20.1-16.el9_4.1",)
    # The bare soname remains an unversioned observation.
    soname = next(d for d in resolution_details(graph) if d.coordinate.endswith("libssl.so.3"))
    assert soname.agreement == "insufficient_evidence"


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
    # 2 soname claims + 3 package requires (bash, openssl-libs, nginx-filesystem);
    # rpmlib / file / rich capabilities are not emitted as claims.
    assert result.claims_added == 5
    assert result.failures == ()
    claim_nodes = graph.find_by_type(NodeType.DEPENDENCY_CLAIM)
    assert len(claim_nodes) == 5
    # The two soname claims carry dynamic linkage; package requires carry unknown.
    soname_nodes = [n for n in claim_nodes if n.metadata.get("evidence") == "rpm_header_soname"]
    assert len(soname_nodes) == 2
    assert all(n.metadata.get("linkage") == "dynamic" for n in soname_nodes)


def test_enrich_graph_captures_header_license() -> None:
    # The header carries the real license (RPMTAG_LICENSE); reading it costs
    # nothing extra because the header is already on the wire for the sonames.
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
        fetch=_range_fetcher(_build_rpm(license="MIT AND BSD-2-Clause")),
        url_resolver=lambda _filename: ["http://example/nginx-core.rpm"],
    )

    assert result.licenses == {"nginx-core": "MIT AND BSD-2-Clause"}
    assert graph.nodes["rpm:nginx-core"].metadata.get("rpm_license") == "MIT AND BSD-2-Clause"


def test_vault_candidate_urls_reconstructs_point_release_path() -> None:
    urls = vault_candidate_urls("nginx-core-1.20.1-16.el9_4.1.x86_64.rpm")

    assert (
        "https://repo.almalinux.org/vault/9.4/AppStream/x86_64/os/Packages/"
        "nginx-core-1.20.1-16.el9_4.1.x86_64.rpm" in urls
    )
    # A malformed filename yields no candidates rather than a bad guess.
    assert vault_candidate_urls("not-an-rpm") == []


def test_candidate_urls_include_live_repo_for_current_builds() -> None:
    # Current (non-archived) point releases live under /almalinux/<ver>/, not the
    # vault, so both layouts must be offered (regression: el10 fetches 0 headers).
    urls = vault_candidate_urls("nginx-core-1.26.3-6.el10_2.3.x86_64.rpm")

    assert (
        "https://repo.almalinux.org/almalinux/10.2/AppStream/x86_64/os/Packages/"
        "nginx-core-1.26.3-6.el10_2.3.x86_64.rpm" in urls
    )
    assert any(u.startswith("https://repo.almalinux.org/vault/10.2/") for u in urls)
    # Live candidate is tried before vault for each repo.
    live = urls.index("https://repo.almalinux.org/almalinux/10.2/BaseOS/x86_64/os/Packages/"
                      "nginx-core-1.26.3-6.el10_2.3.x86_64.rpm")
    vault = urls.index("https://repo.almalinux.org/vault/10.2/BaseOS/x86_64/os/Packages/"
                       "nginx-core-1.26.3-6.el10_2.3.x86_64.rpm")
    assert live < vault

"""Rung 4: full RPM payload download + ELF analysis.

Where rung 3 (``rpm_remote``) range-reads only the header, rung 4 downloads the
whole RPM, decompresses the cpio payload, and parses each ELF object to recover
facts the header cannot carry: confirmed ``DT_NEEDED`` sonames, ``DT_RPATH`` /
``DT_RUNPATH`` search paths, dynamic-vs-static linkage, a best-effort ``dlopen``
flag, and the build toolchain of static binaries.

This deliberately crosses the "metadata-only" boundary the PoC started with: it
fetches and decompresses real artifact bytes. The confirmed sonames are emitted
as ``evidence="elf_dt_needed"`` claims, which *corroborate* the rung-3
``rpm_header_soname`` claims for the same library (reported vs. independently
verified). RPATH/RUNPATH/dlopen/static facts are recorded on the binary RPM node
under ``elf_analysis``.

zstd payloads (the el9 default) require the optional ``zstandard`` package; gzip,
xz and bzip2 are handled with the standard library, which is what the offline
tests use.
"""

from __future__ import annotations

import io
import stat
from dataclasses import dataclass, field
from typing import Callable, Iterator

from albs_graph.dependency import (
    DependencyScope,
    DependencySpec,
    Ecosystem,
    Linkage,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim

from .elf import ElfInfo, is_elf, parse_elf
from .rpm_header import parse_rpm_header
from .rpm_remote import vault_candidate_urls

FullFetcher = Callable[[str], bytes]
UrlResolver = Callable[[str], list[str]]
NodeSelector = Callable[[Node], bool]

_MAX_RPM_BYTES = 256 * 1024 * 1024


class PayloadError(RuntimeError):
    pass


@dataclass(frozen=True)
class PayloadEnrichmentResult:
    artifacts_seen: int
    payloads_read: int
    elf_objects: int
    soname_claims: int
    static_objects: int
    go_claims: int = 0
    failures: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "artifacts_seen": self.artifacts_seen,
            "payloads_read": self.payloads_read,
            "elf_objects": self.elf_objects,
            "soname_claims": self.soname_claims,
            "static_objects": self.static_objects,
            "go_claims": self.go_claims,
            "failures": list(self.failures),
        }


def payload_contents(rpm_bytes: bytes) -> tuple[list[tuple[str, ElfInfo]], list[str]]:
    """Decompress the payload once and return (ELF (path, info) pairs, all file paths)."""

    header = parse_rpm_header(rpm_bytes)
    payload = rpm_bytes[header.payload_offset :]
    raw = decompress_payload(payload, header.payload_compressor)
    elfs: list[tuple[str, ElfInfo]] = []
    files: list[str] = []
    for path, data in iter_cpio(raw):
        files.append(path)
        if is_elf(data):
            elfs.append((path, parse_elf(data)))
    return elfs, files


def analyze_rpm_payload(rpm_bytes: bytes) -> list[tuple[str, ElfInfo]]:
    """Parse an RPM's payload and return (path, ElfInfo) for every ELF object."""

    return payload_contents(rpm_bytes)[0]


def fetch_and_analyze(url: str, fetch_full: FullFetcher | None = None) -> list[tuple[str, ElfInfo]]:
    fetcher = fetch_full or _requests_full_get
    return analyze_rpm_payload(fetcher(url))


def fetch_and_contents(
    url: str, fetch_full: FullFetcher | None = None
) -> tuple[list[tuple[str, ElfInfo]], list[str]]:
    fetcher = fetch_full or _requests_full_get
    return payload_contents(fetcher(url))


def payload_dependency_claims(
    subject_id: str, elfs: list[tuple[str, ElfInfo]]
) -> list[DependencyClaim]:
    """One DYNAMIC-linkage claim per distinct soname actually needed by an ELF."""

    sonames: dict[str, list[str]] = {}
    for path, info in elfs:
        for need in info.needed:
            base = need.split("(", 1)[0]
            sonames.setdefault(base, []).append(path)
    claims: list[DependencyClaim] = []
    for soname, paths in sonames.items():
        spec = DependencySpec(
            identity=PackageIdentity(Ecosystem.RPM, soname),
            scope=DependencyScope.RUNTIME,
            linkage=Linkage.DYNAMIC,
            resolution_state=ResolutionState.OBSERVED,
            source="elf",
            raw={"capability": soname, "objects": sorted(set(paths))},
        )
        claims.append(DependencyClaim(subject_id=subject_id, spec=spec, evidence="elf_dt_needed"))
    return claims


def go_static_claims(subject_id: str, elfs: list[tuple[str, ElfInfo]]) -> list[DependencyClaim]:
    """Static dependency claims from Go binaries' embedded .go.buildinfo modules."""

    seen: set[tuple[str, str]] = set()
    claims: list[DependencyClaim] = []
    for path, info in elfs:
        for module, version in info.go_deps:
            key = (module, version)
            if key in seen:
                continue
            seen.add(key)
            spec = DependencySpec(
                identity=PackageIdentity(Ecosystem.GO, module, version=version),
                scope=DependencyScope.RUNTIME,
                linkage=Linkage.STATIC,
                resolution_state=ResolutionState.RESOLVED,
                source="go_buildinfo",
                raw={"object": path},
            )
            claims.append(DependencyClaim(subject_id=subject_id, spec=spec, evidence="go_buildinfo"))
    return claims


def elf_analysis_summary(elfs: list[tuple[str, ElfInfo]]) -> dict[str, object]:
    return {
        "elf_objects": len(elfs),
        "dynamic": sum(1 for _, info in elfs if info.linkage_kind() == "dynamic"),
        "static": sorted(path for path, info in elfs if info.linkage_kind() == "static"),
        "rpath": sorted({entry for _, info in elfs for entry in info.rpath}),
        "runpath": sorted({entry for _, info in elfs for entry in info.runpath}),
        "dlopen": sorted(path for path, info in elfs if info.dlopen),
        "toolchains": sorted({tool for _, info in elfs for tool in info.toolchains}),
    }


def enrich_graph_with_rpm_payloads(
    graph: ProvenanceGraph,
    *,
    fetch_full: FullFetcher | None = None,
    url_resolver: UrlResolver | None = None,
    limit: int | None = None,
    on_progress: Callable[[str], None] | None = None,
    node_selector: NodeSelector | None = None,
) -> PayloadEnrichmentResult:
    """For each binary RPM, download + analyze the payload and record ELF facts."""

    resolver = url_resolver or vault_candidate_urls
    seen = 0
    read = 0
    elf_total = 0
    claims_added = 0
    go_total = 0
    static_total = 0
    failures: list[str] = []

    for node in graph.find_by_type(NodeType.BINARY_RPM):
        filename = _artifact_filename(graph, node.id)
        if not filename or _is_debug_artifact(filename):
            continue
        if node_selector and not node_selector(node):
            continue
        if limit is not None and seen >= limit:
            break
        seen += 1
        contents = _try_candidates(filename, resolver(filename), fetch_full, on_progress)
        if contents is None:
            failures.append(filename)
            continue
        elfs, files = contents
        read += 1
        elf_total += len(elfs)
        summary = elf_analysis_summary(elfs)
        static_total += len(summary["static"]) if isinstance(summary["static"], list) else 0
        # Full file list (not just ELF), so `identify` can resolve any owned path
        # (configs, docs) offline from graph data.
        graph.update_metadata(node.id, {"elf_analysis": summary, "files": sorted(files)})
        for claim in payload_dependency_claims(node.id, elfs):
            add_dependency_claim(graph, claim)
            claims_added += 1
        for claim in go_static_claims(node.id, elfs):
            add_dependency_claim(graph, claim)
            go_total += 1
        if on_progress:
            on_progress(f"analyzed {len(elfs)} ELF objects in {filename}")
    return PayloadEnrichmentResult(
        artifacts_seen=seen,
        payloads_read=read,
        elf_objects=elf_total,
        soname_claims=claims_added,
        static_objects=static_total,
        go_claims=go_total,
        failures=tuple(failures),
    )


def decompress_payload(payload: bytes, compressor: str | None) -> bytes:
    name = (compressor or "gzip").lower()
    if name in ("gzip", "gz"):
        import gzip

        return gzip.decompress(payload)
    if name in ("xz", "lzma"):
        import lzma

        return lzma.decompress(payload)
    if name in ("bzip2", "bz2"):
        import bz2

        return bz2.decompress(payload)
    if name in ("zstd", "zstandard"):
        try:
            import zstandard
        except ImportError as exc:  # pragma: no cover - depends on optional dep
            raise PayloadError(
                "zstd-compressed payload requires the 'zstandard' package"
            ) from exc
        reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(payload))
        return bytes(reader.read())
    raise PayloadError(f"unsupported payload compressor: {compressor}")


def iter_cpio(blob: bytes) -> Iterator[tuple[str, bytes]]:
    """Yield (path, data) for regular files in a newc-format cpio archive."""

    pos = 0
    total = len(blob)
    while pos + 110 <= total:
        if blob[pos : pos + 6] != b"070701":
            break
        mode = _hex_field(blob, pos, 1)
        filesize = _hex_field(blob, pos, 6)
        namesize = _hex_field(blob, pos, 11)
        name_start = pos + 110
        name = blob[name_start : name_start + namesize - 1].decode("utf-8", "replace")
        data_start = pos + _align4(110 + namesize)
        if name == "TRAILER!!!":
            break
        data = blob[data_start : data_start + filesize]
        if stat.S_ISREG(mode):
            yield name, data
        pos = data_start + _align4(filesize)


def _try_candidates(
    filename: str,
    candidates: list[str],
    fetch_full: FullFetcher | None,
    on_progress: Callable[[str], None] | None,
) -> tuple[list[tuple[str, ElfInfo]], list[str]] | None:
    for url in candidates:
        try:
            if on_progress:
                on_progress(f"downloading payload for {filename} from {url}")
            return fetch_and_contents(url, fetch_full)
        except (PayloadError, OSError, ValueError):
            continue
    return None


def _hex_field(blob: bytes, header_pos: int, index: int) -> int:
    start = header_pos + 6 + index * 8
    return int(blob[start : start + 8], 16)


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _artifact_filename(graph: ProvenanceGraph, node_id: str) -> str | None:
    metadata = graph.nodes[node_id].metadata
    filename = metadata.get("filename") or metadata.get("artifact_name") or graph.nodes[node_id].label
    text = str(filename).strip()
    return text if text.endswith(".rpm") else None


def _is_debug_artifact(filename: str) -> bool:
    return "-debuginfo" in filename or "-debugsource" in filename


def _requests_full_get(url: str) -> bytes:
    import requests

    response = requests.get(url, timeout=120, allow_redirects=True, stream=True)
    if response.status_code not in (200, 206):
        raise PayloadError(f"HTTP {response.status_code} for {url}")
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=65536):
        chunks.append(chunk)
        size += len(chunk)
        if size > _MAX_RPM_BYTES:
            raise PayloadError(f"RPM exceeded {_MAX_RPM_BYTES} bytes for {url}")
    return b"".join(chunks)

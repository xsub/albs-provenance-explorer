"""Fetch RPM headers over HTTP Range and turn sonames into linkage claims.

This is rung 3 of the cost ladder: instead of downloading whole binary RPMs,
we pull only the bytes needed to cover the header (lead + signature + main
header, typically tens of KB) using HTTP Range requests, parse the dynamic
soname dependencies out of it, and feed them into the graph as dependency
claims with ``linkage=DYNAMIC``. AlmaLinux's public mirror/vault serves
``Accept-Ranges: bytes``, so this works against real published RPMs.

The claims are labelled ``rpm_header_soname`` -- they are RPM's recorded
dependency facts, not an independent ELF parse. RPATH/RUNPATH, dlopen sites and
static BOMs are *not* in the header; obtaining those is rung 4 (full payload)
and is intentionally out of scope here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

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

from .rpm_header import RpmHeader, RpmHeaderError, parse_rpm_header, required_header_length

# A range fetcher returns the bytes for an inclusive [start, end] byte range.
RangeFetcher = Callable[[str, int, int], bytes]
UrlResolver = Callable[[str], list[str]]
NodeSelector = Callable[[Node], bool]

_DEFAULT_VAULT_BASE = "https://repo.almalinux.org/vault"
_DEFAULT_REPOS = ("BaseOS", "AppStream", "CRB", "extras", "HighAvailability")
_MAX_FETCH_BYTES = 16 * 1024 * 1024


class RpmHeaderFetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class HeaderEnrichmentResult:
    artifacts_seen: int
    headers_fetched: int
    claims_added: int
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "artifacts_seen": self.artifacts_seen,
            "headers_fetched": self.headers_fetched,
            "claims_added": self.claims_added,
            "failures": list(self.failures),
        }


def fetch_rpm_header(
    url: str,
    fetch: RangeFetcher | None = None,
    *,
    max_bytes: int = _MAX_FETCH_BYTES,
) -> RpmHeader:
    """Pull just enough of an RPM via Range reads to parse its header."""

    fetcher = fetch or _requests_range_fetch
    buffer = b""
    needed = required_header_length(buffer)
    while len(buffer) < needed:
        chunk = fetcher(url, len(buffer), needed - 1)
        if not chunk:
            raise RpmHeaderFetchError(f"empty range response from {url}")
        buffer += chunk
        if len(buffer) > max_bytes:
            raise RpmHeaderFetchError(f"header exceeded {max_bytes} bytes for {url}")
        needed = required_header_length(buffer)
    return parse_rpm_header(buffer)


def header_dependency_claims(
    subject_id: str,
    header: RpmHeader,
    *,
    include_packages: bool = False,
) -> list[DependencyClaim]:
    """Convert header capabilities into dependency claims for one subject.

    Soname requires become DYNAMIC-linkage claims. Plain package requires are
    only emitted when ``include_packages`` is set (they duplicate what
    ``rpm -qp --requires`` already provides, minus the linkage signal).

    A package typically requires the same soname under several symbol versions
    (``libc.so.6(GLIBC_2.2.5)``, ``libc.so.6(GLIBC_2.34)`` ...). Those are one
    logical dynamic dependency on ``libc.so.6``, so they are collapsed into a
    single claim whose raw payload keeps every original expression.
    """

    groups: dict[tuple[str, str, Linkage], list[str]] = {}
    order: list[tuple[str, str, Linkage]] = []
    for dep in header.requires:
        if dep.kind == "soname" and dep.soname:
            key = (dep.soname, "rpm_header_soname", Linkage.DYNAMIC)
        elif include_packages and dep.kind == "package":
            key = (dep.name, "rpm_header_requires", Linkage.UNKNOWN)
        else:
            continue
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(dep.name)

    return [
        _claim(subject_id, name, linkage, evidence, groups[(name, evidence, linkage)])
        for name, evidence, linkage in order
    ]


def enrich_graph_with_rpm_headers(
    graph: ProvenanceGraph,
    *,
    fetch: RangeFetcher | None = None,
    url_resolver: UrlResolver | None = None,
    limit: int | None = None,
    on_progress: Callable[[str], None] | None = None,
    node_selector: NodeSelector | None = None,
) -> HeaderEnrichmentResult:
    """For each binary RPM node, range-fetch its header and add soname claims."""

    resolver = url_resolver or vault_candidate_urls
    artifacts = 0
    fetched = 0
    claims_added = 0
    failures: list[str] = []

    for node in graph.find_by_type(NodeType.BINARY_RPM):
        filename = _artifact_filename(graph, node.id)
        if not filename or _is_debug_artifact(filename):
            continue
        if node_selector and not node_selector(node):
            continue
        if limit is not None and artifacts >= limit:
            break
        artifacts += 1
        candidates = resolver(filename)
        header, used_url = _try_candidates(filename, candidates, fetch, on_progress)
        if header is None:
            failures.append(filename)
            continue
        fetched += 1
        if on_progress:
            on_progress(f"parsed header for {filename} from {used_url}")
        for claim in header_dependency_claims(node.id, header):
            add_dependency_claim(graph, claim)
            claims_added += 1
    return HeaderEnrichmentResult(artifacts, fetched, claims_added, tuple(failures))


def vault_candidate_urls(
    filename: str,
    *,
    base: str = _DEFAULT_VAULT_BASE,
    repos: tuple[str, ...] = _DEFAULT_REPOS,
) -> list[str]:
    """Best-effort public download URLs for an AlmaLinux RPM, by filename.

    The ALBS artifact ``href`` is a Pulp content path that does not resolve to
    a download without the distribution context, so we reconstruct vault URLs
    from the RPM's own NEVRA (the ``.elN_M`` release encodes the point release)
    and try each repository.
    """

    parsed = _parse_nevra(filename)
    arch = parsed.get("arch")
    release = parsed.get("release")
    if not arch or not release:
        return []
    version = _distro_version_from_release(release)
    if not version:
        return []
    return [f"{base}/{version}/{repo}/{arch}/os/Packages/{filename}" for repo in repos]


def _try_candidates(
    filename: str,
    candidates: list[str],
    fetch: RangeFetcher | None,
    on_progress: Callable[[str], None] | None,
) -> tuple[RpmHeader | None, str | None]:
    for url in candidates:
        try:
            if on_progress:
                on_progress(f"range-fetching header for {filename} from {url}")
            return fetch_rpm_header(url, fetch), url
        except (RpmHeaderFetchError, RpmHeaderError):
            continue
    return None, None


def _claim(
    subject_id: str, name: str, linkage: Linkage, evidence: str, expressions: list[str]
) -> DependencyClaim:
    spec = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, name),
        scope=DependencyScope.RUNTIME,
        linkage=linkage,
        resolution_state=ResolutionState.OBSERVED,
        source="rpm_header",
        raw={"capability": name, "expressions": expressions},
    )
    return DependencyClaim(subject_id=subject_id, spec=spec, evidence=evidence)


def _artifact_filename(graph: ProvenanceGraph, node_id: str) -> str | None:
    metadata = graph.nodes[node_id].metadata
    filename = metadata.get("filename") or metadata.get("artifact_name") or graph.nodes[node_id].label
    text = str(filename).strip()
    if not text.endswith(".rpm"):
        return None
    return text


def _is_debug_artifact(filename: str) -> bool:
    return "-debuginfo" in filename or "-debugsource" in filename


def _parse_nevra(filename: str) -> dict[str, str]:
    stem = filename.removesuffix(".rpm")
    parts = stem.rsplit(".", 1)
    if len(parts) != 2:
        return {}
    nevr, arch = parts
    name_version_release = nevr.rsplit("-", 2)
    if len(name_version_release) != 3:
        return {}
    name, version, release = name_version_release
    return {"name": name, "version": version, "release": release, "arch": arch}


def _distro_version_from_release(release: str) -> str | None:
    match = re.search(r"el(\d+)(?:_(\d+))?", release)
    if not match:
        return None
    major, minor = match.group(1), match.group(2)
    return f"{major}.{minor}" if minor else major


def _requests_range_fetch(url: str, start: int, end: int) -> bytes:
    import requests

    response = requests.get(
        url,
        headers={"Range": f"bytes={start}-{end}"},
        timeout=30,
        allow_redirects=True,
    )
    if response.status_code not in (200, 206):
        raise RpmHeaderFetchError(f"HTTP {response.status_code} for {url}")
    return response.content

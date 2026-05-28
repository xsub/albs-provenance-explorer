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

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from albs_graph.adapters._http_cache import HttpCache, cached_range_fetcher
from albs_graph.dependency import (
    DependencyScope,
    DependencySpec,
    Ecosystem,
    Linkage,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.nevra import RpmNevra
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim

from .rpm_header import (
    RpmDependency,
    RpmHeader,
    RpmHeaderError,
    parse_rpm_header,
    required_header_length,
)

# A range fetcher returns the bytes for an inclusive [start, end] byte range.
RangeFetcher = Callable[[str, int, int], bytes]
UrlResolver = Callable[[str], list[str]]
NodeSelector = Callable[[Node], bool]

_DEFAULT_VAULT_BASE = "https://repo.almalinux.org/vault"
_DEFAULT_LIVE_BASE = "https://repo.almalinux.org/almalinux"
_DEFAULT_REPOS = ("BaseOS", "AppStream", "CRB", "extras", "HighAvailability")
_MAX_FETCH_BYTES = 16 * 1024 * 1024

# RPMSENSE comparison bits (rpmlib): a require's flags encode the operator.
_RPMSENSE_LESS = 1 << 1
_RPMSENSE_GREATER = 1 << 2
_RPMSENSE_EQUAL = 1 << 3
_RPMSENSE_SENSE_MASK = _RPMSENSE_LESS | _RPMSENSE_GREATER | _RPMSENSE_EQUAL
_SENSE_OP = {
    _RPMSENSE_EQUAL: "=",
    _RPMSENSE_EQUAL | _RPMSENSE_GREATER: ">=",
    _RPMSENSE_EQUAL | _RPMSENSE_LESS: "<=",
    _RPMSENSE_GREATER: ">",
    _RPMSENSE_LESS: "<",
}


def _package_constraint(dep: RpmDependency) -> tuple[str | None, str | None]:
    """Translate a package require's flags+version into (exact_version, requested).

    An ``=`` dependency yields a concrete version (counts toward the resolution
    axis); a relational operator yields a ``requested`` constraint string (drives
    RANGE_VIOLATION); a bare name yields neither.
    """

    version = (dep.version or "").strip()
    if not version:
        return None, None
    operator = _SENSE_OP.get(dep.flags & _RPMSENSE_SENSE_MASK)
    if operator is None:
        return None, None
    if operator == "=":
        return version, None
    return None, f"{dep.name} {operator} {version}"


class RpmHeaderFetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class HeaderEnrichmentResult:
    artifacts_seen: int
    headers_fetched: int
    claims_added: int
    failures: tuple[str, ...]
    # Real per-package licenses read from RPMTAG_LICENSE (1014) in the headers we
    # fetched -- no extra cost, the header is already on the wire for the sonames.
    licenses: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "artifacts_seen": self.artifacts_seen,
            "headers_fetched": self.headers_fetched,
            "claims_added": self.claims_added,
            "failures": list(self.failures),
            "licenses": dict(self.licenses),
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

    soname_groups: dict[str, list[str]] = {}
    soname_order: list[str] = []
    package_claims: list[DependencyClaim] = []
    seen_packages: set[tuple[str, str | None, str | None]] = set()
    for dep in header.requires:
        if dep.kind == "soname" and dep.soname:
            if dep.soname not in soname_groups:
                soname_groups[dep.soname] = []
                soname_order.append(dep.soname)
            soname_groups[dep.soname].append(dep.name)
        elif include_packages and dep.kind == "package":
            version, requested = _package_constraint(dep)
            dedupe = (dep.name, version, requested)
            if dedupe in seen_packages:
                continue
            seen_packages.add(dedupe)
            package_claims.append(
                _claim(
                    subject_id,
                    dep.name,
                    Linkage.UNKNOWN,
                    "rpm_header_requires",
                    [dep.name],
                    version=version,
                    requested=requested,
                )
            )

    soname_claims = [
        _claim(subject_id, soname, Linkage.DYNAMIC, "rpm_header_soname", soname_groups[soname])
        for soname in soname_order
    ]
    return soname_claims + package_claims


def enrich_graph_with_rpm_headers(
    graph: ProvenanceGraph,
    *,
    fetch: RangeFetcher | None = None,
    url_resolver: UrlResolver | None = None,
    limit: int | None = None,
    on_progress: Callable[[str], None] | None = None,
    node_selector: NodeSelector | None = None,
    http_cache: bool = True,
    max_concurrency: int = 4,
) -> HeaderEnrichmentResult:
    """For each binary RPM node, range-fetch its header and add soname claims.

    The default fetcher is wrapped in an :class:`HttpCache` (see ``_http_cache``)
    so reruns serve from disk; pass ``http_cache=False`` to bypass. An injected
    ``fetch`` is honoured as-is (tests provide their own deterministic fetcher
    and bring no network at all). ``max_concurrency`` parallelises the per-RPM
    fetch + parse (workers); graph mutation stays single-threaded in this thread.
    """

    resolver = url_resolver or vault_candidate_urls
    # Default path wraps the real fetcher in a disk cache; an injected fetcher
    # (tests) is honoured verbatim so the cache never touches test data.
    if fetch is None:
        cache = HttpCache(enabled=http_cache)
        active_fetch: RangeFetcher = cached_range_fetcher(cache, _requests_range_fetch)
    else:
        active_fetch = fetch

    # Gather eligible nodes first so the worker pool sees a fixed work list (and
    # `limit` applies the same as before: it caps "what we attempt", not "what
    # succeeds").
    work: list[tuple[Node, str]] = []
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        filename = _artifact_filename(graph, node.id)
        if not filename or _is_debug_artifact(filename):
            continue
        if node_selector and not node_selector(node):
            continue
        if limit is not None and len(work) >= limit:
            break
        work.append((node, filename))

    def _process(item: tuple[Node, str]) -> tuple[Node, str, RpmHeader | None, str | None]:
        node, filename = item
        header, used_url = _try_candidates(
            filename, resolver(filename), active_fetch, on_progress
        )
        return node, filename, header, used_url

    if max_concurrency > 1 and len(work) > 1:
        with ThreadPoolExecutor(max_workers=max_concurrency) as pool:
            results = list(pool.map(_process, work))
    else:
        results = [_process(item) for item in work]

    # Merge sequentially in this thread -- ProvenanceGraph is not thread-safe.
    artifacts = len(work)
    fetched = 0
    claims_added = 0
    failures: list[str] = []
    licenses: dict[str, str] = {}
    for node, filename, header, used_url in results:
        if header is None:
            failures.append(filename)
            continue
        fetched += 1
        if on_progress:
            on_progress(f"parsed header for {filename} from {used_url}")
        if header.license:
            # The header carries the real license; record it as a fact (rung 3).
            graph.update_metadata(node.id, {"rpm_license": header.license})
            licenses[header.name or filename] = header.license
        for claim in header_dependency_claims(node.id, header, include_packages=True):
            add_dependency_claim(graph, claim)
            claims_added += 1
    return HeaderEnrichmentResult(artifacts, fetched, claims_added, tuple(failures), licenses)


def vault_candidate_urls(
    filename: str,
    *,
    base: str = _DEFAULT_VAULT_BASE,
    repos: tuple[str, ...] = _DEFAULT_REPOS,
    live_base: str = _DEFAULT_LIVE_BASE,
) -> list[str]:
    """Best-effort public download URLs for an AlmaLinux RPM, by filename.

    The ALBS artifact ``href`` is a Pulp content path that does not resolve to a
    download without the distribution context, so we reconstruct URLs from the
    RPM's own NEVRA (the ``.elN_M`` release encodes the point release). Where a
    package lives depends on whether its point release is current or archived,
    so both layouts are offered per repository:

    * live   ``.../almalinux/<ver>/<repo>/<arch>/os/Packages/<file>`` and
    * vault  ``.../vault/<ver>/<repo>/<arch>/os/Packages/<file>``.

    They are interleaved per repo (live then vault) so the reader reaches the
    right one in a couple of range reads whether the build is current or EOL.
    """

    nevra = RpmNevra.from_filename(filename)
    if nevra is None or not nevra.arch or not nevra.release:
        return []
    version = nevra.distro_version
    if not version:
        return []
    urls: list[str] = []
    for repo in repos:
        path = f"{repo}/{nevra.arch}/os/Packages/{filename}"
        urls.append(f"{live_base}/{version}/{path}")
        urls.append(f"{base}/{version}/{path}")
    return urls


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
    subject_id: str,
    name: str,
    linkage: Linkage,
    evidence: str,
    expressions: list[str],
    *,
    version: str | None = None,
    requested: str | None = None,
) -> DependencyClaim:
    spec = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, name, version=version),
        scope=DependencyScope.RUNTIME,
        linkage=linkage,
        resolution_state=ResolutionState.OBSERVED,
        requested=requested,
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

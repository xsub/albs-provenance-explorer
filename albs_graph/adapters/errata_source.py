"""Live errata sources behind one contract (D79): is this RPM in an advisory?

Errata is a *queryable* fact, not only a hand-supplied file (``errata.py``).
AlmaLinux publishes advisories two ways, and this module queries either behind
one ``ErrataSource`` protocol (the ``resolver_for`` pattern):

- ``HttpErrataSource`` -> the AlmaLinux errata feed JSON (``errata.almalinux.org``
  ``errata.full.json`` or a drop-in mirror), fetched through ``HttpCache`` +
  TTL exactly like the live CPE/CVE feeds (D76). Works anywhere, offline after
  the first fetch; tests inject the fetcher.
- ``DnfErrataSource`` -> ``dnf -q updateinfo list --all`` on an AlmaLinux host
  with the repos enabled, parsing the ``ADVISORY  TYPE  NEVRA`` columns. Like
  the other ``dnf.py`` adapters it degrades to "not consulted" when ``dnf`` is
  absent (e.g. on a Mac).

The point is the **three-state** answer the file-only path could never give:

* **advisory_present**  -- a source returned an advisory shipping this exact NEVRA.
* **confirmed_clean**   -- a source was consulted and returned no advisory for it.
* **not_checked**       -- no source was consulted (the historical default).

``confirmed_clean`` is a *positive* result for the security-context axis: a
package with no advisory is the normal, trustworthy state, not an
incompleteness. ``attach_errata_from_source`` records it as
``errata_status="confirmed_clean"`` node metadata, which the graph's
``trust_path_report`` reads to satisfy ``has_errata_link`` (mirroring the
``identity_established`` / ``identity_externally_verified`` split from D71).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

from albs_graph.adapters._http_cache import HttpCache, default_cache_root
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.nevra import RpmNevra

Progress = Callable[[str], None] | None
Fetcher = Callable[[str], bytes]
# A dnf runner takes argv and returns (returncode, stdout); injectable for tests.
Runner = Callable[[list[str]], tuple[int, str]]
NodeSelector = Callable[[Node], bool]

# The official AlmaLinux errata feed: one full JSON per distro major version.
# https://errata.almalinux.org/9/errata.full.json is the canonical "is this
# NEVRA in an advisory?" source the three-state errata check (D79) consults.
ALMALINUX_ERRATA_FEED_URL = "https://errata.almalinux.org/{version}/errata.full.json"
_EL_RELEASE = re.compile(r"\.el(\d+)")


def almalinux_errata_feed_url(version: str | int) -> str:
    """Canonical AlmaLinux ``errata.full.json`` URL for a distro major version."""

    return ALMALINUX_ERRATA_FEED_URL.format(version=version)


_ADVISORY_ID = re.compile(r"^AL([SBE]A)-(\d{4})[:-](\d+)$")


def almalinux_advisory_url(advisory_id: str, major_version: str | None) -> str | None:
    """The AlmaLinux errata HTML page for an ALSA/ALBA/ALEA advisory id, e.g.
    ``ALSA-2026:19158`` + major ``10`` -> ``https://errata.almalinux.org/10/
    ALSA-2026-19158.html``. The page path uses hyphens (the feed id uses a colon),
    so it needs the AlmaLinux major version; ``None`` when either is missing or
    the id is not an AlmaLinux advisory."""

    match = _ADVISORY_ID.match(advisory_id.strip())
    if not match or not major_version:
        return None
    page_id = f"AL{match.group(1)}-{match.group(2)}-{match.group(3)}"
    return f"https://errata.almalinux.org/{major_version}/{page_id}.html"


def redhat_advisory_id(advisory_id: str) -> str | None:
    """The upstream Red Hat advisory an AlmaLinux advisory mirrors. AlmaLinux
    rebuilds RHEL and keeps the same advisory number, so ``ALSA-2026:19158``
    corresponds to ``RHSA-2026:19158`` (``ALBA``->``RHBA``, ``ALEA``->``RHEA``);
    ``None`` for a non-AlmaLinux id."""

    match = _ADVISORY_ID.match(advisory_id.strip())
    if not match:
        return None
    return f"RH{match.group(1)}-{match.group(2)}:{match.group(3)}"


def redhat_advisory_url(advisory_id: str) -> str | None:
    """The Red Hat errata page for the upstream advisory (see ``redhat_advisory_id``)."""

    rhsa = redhat_advisory_id(advisory_id)
    return f"https://access.redhat.com/errata/{rhsa}" if rhsa else None


def almalinux_major_version(graph: ProvenanceGraph) -> str | None:
    """Infer the distro major version (``8`` / ``9`` / ``10``) from the build.

    Reads the ``.elN`` token out of the binary RPM release strings and returns
    the dominant one, so the right errata feed can be defaulted without the
    caller knowing which AlmaLinux release the build targets.
    """

    counts: Counter[str] = Counter()
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        match = _EL_RELEASE.search(str(node.metadata.get("release") or ""))
        if match:
            counts[match.group(1)] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


@dataclass(frozen=True)
class ErrataAdvisory:
    """One advisory shipping a package: id + classification + the CVEs it fixes."""

    id: str
    type: str | None = None       # security / bugfix / enhancement
    severity: str | None = None   # Critical / Important / Moderate / Low (security only)
    cves: tuple[str, ...] = ()


@runtime_checkable
class ErrataSource(Protocol):
    """Anything that can answer "which advisories ship this NEVRA?".

    ``consulted`` records whether the source was actually reachable -- the
    load-bearing distinction between "checked, none" and "never checked".
    """

    name: str

    @property
    def consulted(self) -> bool: ...

    def advisories_for(self, nevra: RpmNevra) -> list[ErrataAdvisory]: ...


@dataclass
class ErrataSourceResult:
    source: str
    consulted: bool
    queried: int = 0          # binary RPMs examined
    with_advisory: int = 0    # -> advisory_present
    clean: int = 0            # -> confirmed_clean
    advisories_added: int = 0  # FIXES edges created (an RPM may map to several)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "consulted": self.consulted,
            "queried": self.queried,
            "with_advisory": self.with_advisory,
            "clean": self.clean,
            "advisories_added": self.advisories_added,
        }


# --- HTTP feed source --------------------------------------------------------


class HttpErrataSource:
    name = "almalinux-errata-feed"

    def __init__(
        self,
        *,
        feed_file: str | Path | None = None,
        url: str | None = None,
        cache: HttpCache | None = None,
        ttl_seconds: float | None = 12 * 3600,
        fetcher: Fetcher | None = None,
        on_progress: Progress = None,
    ) -> None:
        # name -> list of (package NEVRA, advisory). Built once; queries are
        # then pure dict lookups.
        self._index: dict[str, list[tuple[RpmNevra, ErrataAdvisory]]] = {}
        self._consulted = False
        body = self._load(feed_file, url, cache, ttl_seconds, fetcher, on_progress)
        if body is not None:
            self._index = _index_feed(body)
            self._consulted = True

    @property
    def consulted(self) -> bool:
        return self._consulted

    def advisories_for(self, nevra: RpmNevra) -> list[ErrataAdvisory]:
        out: list[ErrataAdvisory] = []
        for pkg_nevra, advisory in self._index.get(nevra.name, []):
            if _nevra_matches(pkg_nevra, nevra):
                out.append(advisory)
        return out

    def _load(
        self,
        feed_file: str | Path | None,
        url: str | None,
        cache: HttpCache | None,
        ttl_seconds: float | None,
        fetcher: Fetcher | None,
        on_progress: Progress,
    ) -> bytes | None:
        if feed_file is not None:
            return Path(feed_file).read_bytes()
        if not url:
            return None
        # Reuse the live-feeds cache machinery (D76): content-addressed disk
        # cache with a TTL on top, graceful on network failure.
        from albs_graph.security.live_feeds import _cached_get

        try:
            return _cached_get(
                url,
                cache=cache or HttpCache(root=default_cache_root() / "feeds"),
                ttl_seconds=ttl_seconds,
                fetcher=fetcher,
                on_progress=on_progress,
            )
        except Exception as exc:  # noqa: BLE001 -- live fetch must never crash a run
            if on_progress:
                on_progress(f"live errata feed unavailable ({exc}); not consulted")
            return None


# --- dnf updateinfo source ---------------------------------------------------


# ``dnf -q updateinfo list --all`` prints ``ADVISORY  TYPE/SEV  NEVRA`` columns,
# e.g. ``ALSA-2024:1234 Important/Sec.  nginx-1:1.20.1-14.el9_2.x86_64``. The
# middle token is ``severity/type`` for security, or a plain ``bugfix`` /
# ``enhancement``.
_DNF_LINE = re.compile(
    r"^(?P<advisory>\S+)\s+(?P<class>\S+)\s+(?P<nevra>\S+)\s*$"
)


class DnfErrataSource:
    name = "dnf-updateinfo"

    def __init__(self, *, runner: Runner | None = None, on_progress: Progress = None) -> None:
        self._index: dict[str, list[tuple[RpmNevra, ErrataAdvisory]]] = {}
        self._consulted = False
        output = self._run(runner, on_progress)
        if output is not None:
            self._index = _index_dnf(output)
            self._consulted = True

    @property
    def consulted(self) -> bool:
        return self._consulted

    def advisories_for(self, nevra: RpmNevra) -> list[ErrataAdvisory]:
        out: list[ErrataAdvisory] = []
        for pkg_nevra, advisory in self._index.get(nevra.name, []):
            if _nevra_matches(pkg_nevra, nevra):
                out.append(advisory)
        return out

    def _run(self, runner: Runner | None, on_progress: Progress) -> str | None:
        if runner is None and shutil.which("dnf") is None:
            if on_progress:
                on_progress("dnf not found in PATH; errata source not consulted")
            return None
        args = ["dnf", "-q", "updateinfo", "list", "--all"]
        try:
            if runner is not None:
                returncode, output = runner(args)
            else:
                process = subprocess.run(args, check=False, text=True, capture_output=True)
                returncode, output = process.returncode, process.stdout or ""
        except FileNotFoundError:
            return None
        if returncode != 0:
            if on_progress:
                on_progress(f"dnf updateinfo failed (exit {returncode}); not consulted")
            return None
        return output


# --- factory + attach --------------------------------------------------------


def errata_source_for(
    kind: str | None,
    *,
    feed_file: str | Path | None = None,
    url: str | None = None,
    runner: Runner | None = None,
    fetcher: Fetcher | None = None,
    cache: HttpCache | None = None,
    ttl_seconds: float | None = 12 * 3600,
    on_progress: Progress = None,
) -> ErrataSource | None:
    """Build the requested errata source, or ``None`` when ``kind`` is unset.

    ``kind`` is ``"http"`` (feed file or URL) or ``"dnf"`` (host updateinfo).
    A ``feed_file`` implies ``http`` even if ``kind`` is omitted, so a supplied
    offline feed "just works".
    """

    if kind is None and feed_file is not None:
        kind = "http"
    if kind == "http":
        return HttpErrataSource(
            feed_file=feed_file,
            url=url,
            cache=cache,
            ttl_seconds=ttl_seconds,
            fetcher=fetcher,
            on_progress=on_progress,
        )
    if kind == "dnf":
        return DnfErrataSource(runner=runner, on_progress=on_progress)
    return None


def attach_errata_from_source(
    graph: ProvenanceGraph,
    source: ErrataSource,
    *,
    node_selector: NodeSelector | None = None,
) -> ErrataSourceResult:
    """Query ``source`` for every binary RPM; record the three-state outcome.

    advisory found -> ERRATA node + ``FIXES`` edge (+ CVE nodes), exactly like
    ``attach_errata_file``; consulted-but-none -> ``errata_status=confirmed_clean``
    node metadata; source not consulted -> nothing recorded (stays not_checked).
    """

    result = ErrataSourceResult(source=source.name, consulted=source.consulted)
    if not source.consulted:
        return result  # nothing reachable -> leave every node not_checked
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        result.queried += 1
        advisories = source.advisories_for(_node_nevra(node))
        if advisories:
            result.with_advisory += 1
            for advisory in advisories:
                _attach_advisory(graph, node.id, advisory, (source.name,))
                result.advisories_added += 1
        else:
            result.clean += 1
            graph.update_metadata(
                node.id, {"errata_status": "confirmed_clean", "errata_source": source.name}
            )
    return result


@dataclass
class ErrataCrossCheckResult:
    """Outcome of cross-checking errata across several sources (web feed + dnf)."""

    sources: list[str]
    consulted: bool
    queried: int = 0           # binary RPMs examined
    with_advisory: int = 0     # RPMs carrying >= 1 advisory
    clean: int = 0             # RPMs all sources agree are advisory-free
    advisories_added: int = 0  # (RPM, advisory) attachments
    corroborated: int = 0      # (RPM, advisory) confirmed by >= 2 sources
    single_source: int = 0     # (RPM, advisory) reported by only one source

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": list(self.sources),
            "consulted": self.consulted,
            "queried": self.queried,
            "with_advisory": self.with_advisory,
            "clean": self.clean,
            "advisories_added": self.advisories_added,
            "corroborated": self.corroborated,
            "single_source": self.single_source,
        }


def attach_errata_cross_checked(
    graph: ProvenanceGraph,
    sources: list[ErrataSource],
    *,
    node_selector: NodeSelector | None = None,
) -> ErrataCrossCheckResult:
    """Consult several errata sources and mark each advisory they agree on.

    For every (selected) binary RPM each source is asked which advisories ship
    it. An advisory reported by >= 2 sources is **cross-checked** (``True`` on
    both the ERRATA node and the per-RPM ``FIXES`` edge); one reported by a
    single source is flagged as a discrepancy (``cross_checked=False``). An RPM
    that every consulted source agrees is advisory-free is ``confirmed_clean``
    with ``errata_cross_checked=True`` (both agree it is clean). Only sources
    that were actually reachable count, so this degrades to the single-source
    answer when one source is unavailable (e.g. dnf off an AlmaLinux box).
    """

    consulted = [source for source in sources if source.consulted]
    result = ErrataCrossCheckResult(
        sources=[source.name for source in consulted], consulted=bool(consulted)
    )
    if not consulted:
        return result
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        result.queried += 1
        nevra = _node_nevra(node)
        # advisory id -> (advisory, set of reporting source names)
        reported: dict[str, tuple[ErrataAdvisory, set[str]]] = {}
        for source in consulted:
            for advisory in source.advisories_for(nevra):
                entry = reported.setdefault(advisory.id, (advisory, set()))
                entry[1].add(source.name)
        if reported:
            result.with_advisory += 1
            for advisory, reporters in reported.values():
                corroborated = len(reporters) >= 2
                _attach_advisory(
                    graph, node.id, advisory, tuple(sorted(reporters)), cross_checked=corroborated
                )
                result.advisories_added += 1
                result.corroborated += int(corroborated)
                result.single_source += int(not corroborated)
            graph.update_metadata(
                node.id,
                {
                    "errata_sources": [source.name for source in consulted],
                    "errata_cross_checked": all(
                        len(reporters) >= 2 for _, reporters in reported.values()
                    ),
                },
            )
        else:
            result.clean += 1
            graph.update_metadata(
                node.id,
                {
                    "errata_status": "confirmed_clean",
                    "errata_source": "+".join(source.name for source in consulted),
                    "errata_sources": [source.name for source in consulted],
                    "errata_cross_checked": len(consulted) >= 2,  # both agree it is clean
                },
            )
    return result


def _attach_advisory(
    graph: ProvenanceGraph,
    rpm_node_id: str,
    advisory: ErrataAdvisory,
    sources: tuple[str, ...],
    *,
    cross_checked: bool | None = None,
) -> None:
    """Attach an advisory to a binary RPM: ERRATA node + ``FIXES`` edge + CVEs.

    ``sources`` is the set of errata sources that reported this advisory for the
    RPM. ``cross_checked`` -- set only by the cross-check path -- records whether
    >= 2 sources agreed, on both the ERRATA node and the per-RPM ``FIXES`` edge
    (the "mark when correct"). The single-source path passes one name and leaves
    ``cross_checked`` unset so existing behaviour is unchanged.
    """

    errata_id = f"errata:{advisory.id}"
    source_label = "+".join(sources)
    if errata_id not in graph.nodes:
        meta: dict[str, Any] = {
            "type": advisory.type,
            "severity": advisory.severity,
            "source": source_label,
        }
        if cross_checked is not None:
            meta["sources"] = list(sources)
            meta["cross_checked"] = cross_checked
        graph.add_node(Node(errata_id, NodeType.ERRATA, advisory.id, meta))
    elif cross_checked is not None:
        existing = graph.nodes[errata_id]
        merged = sorted(set(existing.metadata.get("sources") or []) | set(sources))
        graph.update_metadata(
            errata_id,
            {
                "sources": merged,
                "source": "+".join(merged),
                "cross_checked": bool(existing.metadata.get("cross_checked")) or cross_checked,
            },
        )
    edge_meta: dict[str, Any] = {}
    if cross_checked is not None:
        edge_meta = {"sources": list(sources), "cross_checked": cross_checked}
    if not _has_fixes_edge(graph, rpm_node_id, errata_id):
        graph.add_edge(rpm_node_id, errata_id, Relation.FIXES, **edge_meta)
    for cve in advisory.cves:
        cve_id = f"cve:{cve}"
        if cve_id not in graph.nodes:
            graph.add_node(Node(cve_id, NodeType.CVE, cve, {"source": "errata"}))
        # The advisory->CVE edge is a property of the advisory, not of each RPM
        # it ships. Add it once, or a CVE fixed by an advisory covering N RPMs
        # accrues N identical "fixes" edges.
        if not _has_fixes_edge(graph, errata_id, cve_id):
            graph.add_edge(errata_id, cve_id, Relation.FIXES)


def _has_fixes_edge(graph: ProvenanceGraph, source_id: str, target_id: str) -> bool:
    return any(
        edge.target == target_id and edge.relation == Relation.FIXES
        for edge in graph.outgoing(source_id)
    )


# --- parsing helpers ---------------------------------------------------------


def _index_feed(body: bytes) -> dict[str, list[tuple[RpmNevra, ErrataAdvisory]]]:
    """Index an AlmaLinux errata feed JSON: package name -> [(NEVRA, advisory)].

    Tolerant of the shape (top-level list, ``{"data": [...]}`` or
    ``{"errata": [...]}``), missing fields, and either a ``references`` list of
    ``{"id","type"}`` or a flat ``cves`` list for the CVE ids.
    """

    data: Any = json.loads(body.decode("utf-8"))
    entries = data
    if isinstance(data, dict):
        entries = data.get("data") or data.get("errata") or []
    index: dict[str, list[tuple[RpmNevra, ErrataAdvisory]]] = {}
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        advisory_id = str(entry.get("id") or entry.get("updateinfo_id") or "").strip()
        if not advisory_id:
            continue
        advisory = ErrataAdvisory(
            id=advisory_id,
            type=_opt_str(entry.get("type")),
            severity=_opt_str(entry.get("severity")),
            cves=_extract_cves(entry),
        )
        for pkg in _iter_packages(entry):
            name = _opt_str(pkg.get("name"))
            if not name:
                continue
            pkg_nevra = RpmNevra(
                name=name,
                epoch=_opt_str(pkg.get("epoch")),
                version=_opt_str(pkg.get("version")),
                release=_opt_str(pkg.get("release")),
                arch=_opt_str(pkg.get("arch")),
            )
            index.setdefault(name, []).append((pkg_nevra, advisory))
    return index


def _index_dnf(output: str) -> dict[str, list[tuple[RpmNevra, ErrataAdvisory]]]:
    index: dict[str, list[tuple[RpmNevra, ErrataAdvisory]]] = {}
    for line in output.splitlines():
        match = _DNF_LINE.match(line)
        if not match:
            continue
        advisory_type, severity = _split_dnf_class(match.group("class"))
        nevra = RpmNevra.from_token(match.group("nevra"))
        if not nevra.name:
            continue
        advisory = ErrataAdvisory(
            id=match.group("advisory"), type=advisory_type, severity=severity
        )
        index.setdefault(nevra.name, []).append((nevra, advisory))
    return index


def _split_dnf_class(token: str) -> tuple[str | None, str | None]:
    """``Important/Sec.`` -> (type=security, severity=Important); ``bugfix`` -> (bugfix, None)."""

    if "/" in token:
        severity, kind = token.split("/", 1)
        advisory_type = "security" if kind.lower().startswith("sec") else kind.rstrip(".").lower()
        return advisory_type, severity or None
    return token.rstrip(".").lower() or None, None


def _iter_packages(entry: dict[str, Any]) -> list[dict[str, Any]]:
    packages = entry.get("packages")
    if isinstance(packages, list):
        return [pkg for pkg in packages if isinstance(pkg, dict)]
    return []


def _extract_cves(entry: dict[str, Any]) -> tuple[str, ...]:
    cves: list[str] = []
    references = entry.get("references")
    if isinstance(references, list):
        for ref in references:
            if isinstance(ref, dict) and str(ref.get("type", "")).lower() == "cve":
                cve = _opt_str(ref.get("id"))
                if cve:
                    cves.append(cve)
    flat = entry.get("cves")
    if isinstance(flat, list):
        cves.extend(str(cve) for cve in flat if cve)
    # de-dupe preserving order
    seen: list[str] = []
    for cve in cves:
        if cve not in seen:
            seen.append(cve)
    return tuple(seen)


def _node_nevra(node: Node) -> RpmNevra:
    """Best NEVRA for a binary RPM node: prefer structured metadata, else the label."""

    meta = node.metadata
    name = _opt_str(meta.get("name"))
    version = _opt_str(meta.get("version"))
    release = _opt_str(meta.get("release"))
    arch = _opt_str(meta.get("arch"))
    if name and (version or release):
        return RpmNevra(name=name, version=version, release=release, arch=arch)
    return RpmNevra.from_filename(node.label) or RpmNevra.from_token(node.label)


def _nevra_matches(advisory_pkg: RpmNevra, query: RpmNevra) -> bool:
    """Name must match; version/release/arch must match when present on both sides.

    The AlmaLinux feed carries full version-release-arch, so this is exact-build
    matching (the RPM *is* the advisory's shipped package). A query that only
    knows the name still matches a name-only advisory entry.
    """

    if advisory_pkg.name != query.name:
        return False
    if advisory_pkg.version and query.version and advisory_pkg.version != query.version:
        return False
    if advisory_pkg.release and query.release and advisory_pkg.release != query.release:
        return False
    if advisory_pkg.arch and query.arch and advisory_pkg.arch != query.arch:
        return False
    return True


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

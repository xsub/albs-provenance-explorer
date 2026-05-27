"""Deep RPM/DNF extraction via ``dnf repoquery``.

``dnf repoquery`` is the richest native source on an AlmaLinux host. Unlike the
RPM header (rung 3) or ``repograph`` (package-name edges), it can *resolve*
requirements to concrete provider NEVRAs and expose the full relation set:

- ``--requires --resolve`` -> versioned RUNTIME dependencies (real resolution),
- ``--recommends`` / ``--suggests`` -> weak dependencies (scope OPTIONAL),
- ``--conflicts`` / ``--obsoletes`` -> recorded as node facts,
- ``--whatprovides <capability>`` -> the soname -> providing-package mapping.

Everything shells out through an injectable runner, so the parsing is tested
offline with canned ``dnf`` output. When ``dnf`` is absent the orchestrator
returns ``available=False`` and changes nothing - it never crashes.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
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
from albs_graph.nevra import RpmNevra
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim

Runner = Callable[[list[str]], tuple[int, str]]
NodeSelector = Callable[[Node], bool]

# repoquery relations that we resolve to versioned provider packages.
_RESOLVE_RELATIONS: tuple[tuple[str, DependencyScope], ...] = (
    ("requires", DependencyScope.RUNTIME),
    ("recommends", DependencyScope.OPTIONAL),
    ("suggests", DependencyScope.OPTIONAL),
)
# relations recorded as facts on the node (not "depends on" edges).
_RECORD_RELATIONS = ("conflicts", "obsoletes")
_NOISE = re.compile(r"^(Last metadata|Repository|Importing|Updating|Failed)")


class DnfUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class DnfEnrichmentResult:
    available: bool
    packages_seen: int
    packages_queried: int
    resolved_claims: int
    weak_claims: int
    relations_recorded: int
    failures: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "packages_seen": self.packages_seen,
            "packages_queried": self.packages_queried,
            "resolved_claims": self.resolved_claims,
            "weak_claims": self.weak_claims,
            "relations_recorded": self.relations_recorded,
            "failures": list(self.failures),
        }


def dnf_available() -> bool:
    return shutil.which("dnf") is not None


def repoquery(
    package: str,
    *,
    relation: str,
    resolve: bool = False,
    repo: str | None = None,
    arch: str | None = None,
    runner: Runner | None = None,
) -> list[str]:
    """Run ``dnf repoquery --<relation> [--resolve] <package>[.<arch>]`` -> lines.

    Passing ``arch`` scopes the query to that architecture's build of the package
    (``name.arch``), so a multi-arch graph resolves each node against its own arch
    instead of every arch inheriting the host arch's dependencies. ``src`` is not
    a queryable binary arch and is ignored.
    """

    args = ["dnf", "repoquery", "--quiet", f"--{relation}"]
    if resolve:
        args.append("--resolve")
    if repo:
        args += ["--repo", repo]
    args.append(f"{package}.{arch}" if arch and arch != "src" else package)
    return _lines(_run(args, runner))


def whatprovides(capability: str, *, runner: Runner | None = None) -> list[str]:
    """Resolve a capability (e.g. ``libssl.so.3()(64bit)``) to providing NEVRAs."""

    return _lines(_run(["dnf", "repoquery", "--quiet", "--whatprovides", capability], runner))


def package_licenses(
    names: list[str],
    *,
    repo: str | None = None,
    runner: Runner | None = None,
) -> dict[str, str]:
    """Map package names to their license string via ``dnf repoquery``.

    Uses ``--qf '%{name}\\t%{license}'`` -- license strings carry spaces (e.g.
    ``LGPL-2.1-or-later AND ...``) but never tabs, so a tab separator is safe.
    Repos may carry several builds of one name; the first license seen wins
    (license rarely changes across rebuilds of the same NEVR family).
    """

    if not names:
        return {}
    args = ["dnf", "repoquery", "--quiet", "--qf", "%{name}\t%{license}"]
    if repo:
        args += ["--repo", repo]
    args += names
    licenses: dict[str, str] = {}
    for line in _lines(_run(args, runner)):
        if "\t" not in line:
            continue
        name, lic = line.split("\t", 1)
        name, lic = name.strip(), lic.strip()
        if name and lic and name not in licenses:
            licenses[name] = lic
    return licenses


def parse_nevra(token: str) -> tuple[str, str | None]:
    """Split a NEVRA / capability token into (name, version|None)."""

    nevra = RpmNevra.from_token(token)
    return nevra.name, nevra.evr


def enrich_graph_with_dnf(
    graph: ProvenanceGraph,
    *,
    runner: Runner | None = None,
    node_selector: NodeSelector | None = None,
    include_weak: bool = True,
    repo: str | None = None,
    limit: int | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> DnfEnrichmentResult:
    """Enrich each selected binary RPM with resolved dnf repoquery dependencies."""

    if runner is None and not dnf_available():
        seen = sum(
            1
            for node in graph.find_by_type(NodeType.BINARY_RPM)
            if not node_selector or node_selector(node)
        )
        return DnfEnrichmentResult(False, seen, 0, 0, 0, 0, ())

    seen = queried = resolved = weak = recorded = 0
    failures: list[str] = []
    relations = _RESOLVE_RELATIONS if include_weak else _RESOLVE_RELATIONS[:1]

    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        name = str(node.metadata.get("name") or parse_nevra(node.label)[0])
        arch = node.metadata.get("arch") or node.metadata.get("build_arch")
        arch_str = str(arch) if arch else None
        if limit is not None and seen >= limit:
            break
        seen += 1
        seen_keys: set[tuple[str, str, str]] = set()
        try:
            for relation, scope in relations:
                for nevra in repoquery(
                    name, relation=relation, resolve=True, repo=repo, arch=arch_str, runner=runner
                ):
                    dep_name, dep_version = parse_nevra(nevra)
                    key = (dep_name, dep_version or "", relation)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    _add_claim(graph, node.id, dep_name, dep_version, scope, relation)
                    if scope == DependencyScope.RUNTIME:
                        resolved += 1
                    else:
                        weak += 1
            recorded += _record_relations(graph, node, name, repo, arch_str, runner)
            queried += 1
            if on_progress:
                on_progress(f"dnf repoquery resolved dependencies for {name}")
        except DnfUnavailable as exc:
            failures.append(f"{name}: {exc}")
    return DnfEnrichmentResult(True, seen, queried, resolved, weak, recorded, tuple(failures))


@dataclass(frozen=True)
class SonameResolutionResult:
    sonames: int
    resolved: int
    claims_added: int

    def to_dict(self) -> dict[str, int]:
        return {
            "sonames": self.sonames,
            "resolved": self.resolved,
            "claims_added": self.claims_added,
        }


def collect_soname_names(graph: ProvenanceGraph) -> list[str]:
    """Distinct soname capabilities present as dependency claims (libz.so.1 ...)."""

    names: set[str] = set()
    for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM):
        name = str(node.metadata.get("name", ""))
        if ".so" in name:
            names.add(name)
    return sorted(names)


def build_soname_index(
    sonames: list[str], *, runner: Runner | None = None
) -> dict[str, str]:
    """Map each soname to a providing package NEVRA via ``dnf --whatprovides``.

    Queries the explicit RPM capability form first (``libz.so.1()(64bit)``) then
    the bare soname. Degrades to an empty map when dnf is absent.
    """

    if runner is None and not dnf_available():
        return {}
    index: dict[str, str] = {}
    for soname in sonames:
        for capability in (f"{soname}()(64bit)", soname):
            try:
                providers = whatprovides(capability, runner=runner)
            except DnfUnavailable:
                return index
            if providers:
                index[soname] = providers[0]
                break
    return index


def resolve_soname_claims(
    graph: ProvenanceGraph, index: dict[str, str]
) -> SonameResolutionResult:
    """Bridge sonames to packages: add a package claim for each resolved soname.

    A header/ELF soname claim (``libz.so.1``) is rewritten into a package-level
    ``soname_provider`` claim (``zlib@...``) on the same subject, so it reconciles
    against SBOM / dnf / repograph package claims instead of sitting in its own
    coordinate space.
    """

    sonames: set[str] = set()
    resolved_sonames: set[str] = set()
    added = 0
    seen: set[tuple[str, str, str]] = set()
    for node in graph.find_by_type(NodeType.DEPENDENCY_CLAIM):
        name = str(node.metadata.get("name", ""))
        if ".so" not in name:
            continue
        sonames.add(name)
        provider = index.get(name)
        if not provider:
            continue
        resolved_sonames.add(name)  # count unique sonames, not per-claim occurrences
        subject = str(node.metadata.get("subject", ""))
        pkg_name, pkg_version = parse_nevra(provider)
        key = (subject, pkg_name, pkg_version or "")
        if key in seen:
            continue
        seen.add(key)
        spec = DependencySpec(
            identity=PackageIdentity(
                Ecosystem.RPM, pkg_name, namespace="almalinux", version=pkg_version
            ),
            scope=DependencyScope.RUNTIME,
            linkage=Linkage.DYNAMIC,
            resolution_state=ResolutionState.RESOLVED,
            source="dnf whatprovides",
            raw={"soname": name, "provider": provider},
        )
        add_dependency_claim(graph, DependencyClaim(subject, spec, evidence="soname_provider"))
        added += 1
    return SonameResolutionResult(len(sonames), len(resolved_sonames), added)


def _add_claim(
    graph: ProvenanceGraph,
    subject_id: str,
    name: str,
    version: str | None,
    scope: DependencyScope,
    relation: str,
) -> None:
    spec = DependencySpec(
        identity=PackageIdentity(Ecosystem.RPM, name, namespace="almalinux", version=version),
        scope=scope,
        resolution_state=ResolutionState.RESOLVED,
        source="dnf repoquery",
        raw={"relation": relation},
    )
    add_dependency_claim(graph, DependencyClaim(subject_id, spec, evidence=f"dnf:{relation}"))


def _record_relations(
    graph: ProvenanceGraph,
    node: Node,
    name: str,
    repo: str | None,
    arch: str | None,
    runner: Runner | None,
) -> int:
    recorded = 0
    relations: dict[str, list[str]] = {}
    for relation in _RECORD_RELATIONS:
        values = repoquery(name, relation=relation, repo=repo, arch=arch, runner=runner)
        if values:
            relations[relation] = values
            recorded += len(values)
    if relations:
        existing = node.metadata.get("dnf_relations")
        merged = {**existing, **relations} if isinstance(existing, dict) else relations
        graph.update_metadata(node.id, {"dnf_relations": merged})
    return recorded


def _run(args: list[str], runner: Runner | None) -> str:
    if runner is not None:
        returncode, output = runner(args)
    else:
        if shutil.which(args[0]) is None:
            raise DnfUnavailable(f"{args[0]} not found in PATH")
        try:
            process = subprocess.run(args, check=False, text=True, capture_output=True)
        except FileNotFoundError as exc:  # pragma: no cover - race with which()
            raise DnfUnavailable(f"{args[0]} not found") from exc
        returncode, output = process.returncode, process.stdout
    if returncode != 0:
        raise DnfUnavailable(f"{' '.join(args)} failed (exit {returncode})")
    return output


def _lines(output: str) -> list[str]:
    return [
        line.strip()
        for line in output.splitlines()
        if line.strip() and not _NOISE.match(line.strip())
    ]

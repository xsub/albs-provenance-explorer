"""AlmaLinux-native dependency resolution via ``dnf repograph`` / ``rpmgraph``.

These tools ship on AlmaLinux (dnf-plugins-core and rpm) and emit a package
dependency graph in Graphviz dot. That is a *real* RPM resolution (libsolv /
rpm's own dependency logic) — rung 5 for the RPM ecosystem, using the
authoritative tooling rather than a reimplemented solver.

This adapter parses dot edges and turns them into resolved dependency claims
(``evidence="repograph"`` / ``"rpmgraph"``) anchored on the matching binary RPM
nodes in the graph. The dot text can be produced live on an AlmaLinux host
(``run_repograph`` / ``run_rpmgraph``) or fed from a pre-generated file, so the
parser is fully testable offline. Tools are optional: if absent, the run helpers
raise ``RpmgraphUnavailable`` (callers treat it as "skipped"), never crashing.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable

from albs_graph.dependency import (
    DependencyScope,
    DependencySpec,
    Ecosystem,
    PackageIdentity,
    ResolutionState,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim

Runner = Callable[[list[str]], tuple[int, str]]
NodeSelector = Callable[[Node], bool]

_ARCH_SUFFIXES = ("x86_64", "aarch64", "ppc64le", "s390x", "i686", "noarch", "src")
_EDGE = re.compile(r'(?:"([^"]+)"|(\S+))\s*->\s*(?:"([^"]+)"|([^"\s;\[]+))')


class RpmgraphUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class RpmgraphEnrichmentResult:
    edges: int
    matched_edges: int
    claims_added: int

    def to_dict(self) -> dict[str, int]:
        return {
            "edges": self.edges,
            "matched_edges": self.matched_edges,
            "claims_added": self.claims_added,
        }


def repograph_available() -> bool:
    return shutil.which("dnf") is not None


def rpmgraph_available() -> bool:
    return shutil.which("rpmgraph") is not None


def run_repograph(repo: str | None = None, *, runner: Runner | None = None) -> str:
    args = ["dnf", "repograph"]
    if repo:
        args.append(repo)
    return _run(args, runner)


def run_rpmgraph(paths: list[str], *, runner: Runner | None = None) -> str:
    return _run(["rpmgraph", *paths], runner)


def parse_dot_edges(dot_text: str) -> list[tuple[str, str]]:
    """Extract directed ``A -> B`` edges from Graphviz dot text."""

    edges: list[tuple[str, str]] = []
    for line in dot_text.splitlines():
        match = _EDGE.search(line)
        if not match:
            continue
        src = (match.group(1) or match.group(2) or "").strip().rstrip(";")
        dst = (match.group(3) or match.group(4) or "").strip().rstrip(";")
        if src and dst and src != "->" and dst != "->":
            edges.append((src, dst))
    return edges


def enrich_graph_with_rpmgraph(
    graph: ProvenanceGraph,
    dot_text: str,
    *,
    evidence: str = "repograph",
    node_selector: NodeSelector | None = None,
) -> RpmgraphEnrichmentResult:
    """Add resolved RPM dependency claims from a repograph/rpmgraph dot graph."""

    name_to_node: dict[str, str] = {}
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        name = str(node.metadata.get("name") or _parse_node_token(node.label)[0])
        name_to_node.setdefault(name, node.id)

    edges = parse_dot_edges(dot_text)
    matched = 0
    added = 0
    seen: set[tuple[str, str, str]] = set()
    for src, dst in edges:
        src_name, _ = _parse_node_token(src)
        node_id = name_to_node.get(src_name)
        if node_id is None:
            continue
        matched += 1
        dep_name, dep_version = _parse_node_token(dst)
        key = (node_id, dep_name, dep_version or "")
        if key in seen:
            continue
        seen.add(key)
        spec = DependencySpec(
            identity=PackageIdentity(
                Ecosystem.RPM, dep_name, namespace="almalinux", version=dep_version
            ),
            scope=DependencyScope.RUNTIME,
            resolution_state=ResolutionState.RESOLVED,
            source=f"dnf {evidence}" if evidence == "repograph" else evidence,
            raw={"edge": [src, dst]},
        )
        add_dependency_claim(graph, DependencyClaim(subject_id=node_id, spec=spec, evidence=evidence))
        added += 1
    return RpmgraphEnrichmentResult(edges=len(edges), matched_edges=matched, claims_added=added)


def _parse_node_token(token: str) -> tuple[str, str | None]:
    """Split an RPM node label into (name, version) — handles NEVRA or bare name."""

    base = token
    for arch in _ARCH_SUFFIXES:
        if base.endswith("." + arch):
            base = base[: -(len(arch) + 1)]
            break
    parts = base.rsplit("-", 2)
    if len(parts) == 3 and any(char.isdigit() for char in parts[1]):
        return parts[0], f"{parts[1]}-{parts[2]}"
    return token, None


def _run(args: list[str], runner: Runner | None) -> str:
    if runner is not None:
        returncode, output = runner(args)
    else:
        if shutil.which(args[0]) is None:
            raise RpmgraphUnavailable(f"{args[0]} not found in PATH")
        try:
            process = subprocess.run(args, check=False, text=True, capture_output=True)
        except FileNotFoundError as exc:  # pragma: no cover - race with which()
            raise RpmgraphUnavailable(f"{args[0]} not found") from exc
        returncode, output = process.returncode, process.stdout
    if returncode != 0:
        raise RpmgraphUnavailable(f"{' '.join(args)} failed (exit {returncode})")
    return output

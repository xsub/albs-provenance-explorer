"""AlmaLinux-native dependency resolution via ``dnf repograph`` / ``rpmgraph``.

These tools ship on AlmaLinux (dnf-plugins-core and rpm) and emit a package
dependency graph in Graphviz dot. That is a *real* RPM resolution (libsolv /
rpm's own dependency logic) - rung 5 for the RPM ecosystem, using the
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
from albs_graph.nevra import RpmNevra
from albs_graph.provenance.reconcile import DependencyClaim, add_dependency_claim

Runner = Callable[[list[str]], tuple[int, str]]
NodeSelector = Callable[[Node], bool]

# A dot node: quoted ("foo bar") or a bare token that never starts with a brace.
_NODE = r'(?:"([^"]+)"|([A-Za-z0-9_./+][^\s{}\[\];,]*))'
# Block form (dnf repograph): `SRC -> { "A" "B" ... }`, possibly spanning lines.
_BLOCK_EDGE = re.compile(_NODE + r"\s*->\s*\{([^}]*)\}", re.DOTALL)
# Simple form (rpmgraph / older dnf): `SRC -> DST`. The dst node cannot be a "{",
# so this never mis-captures a block opener.
_SIMPLE_EDGE = re.compile(_NODE + r"\s*->\s*" + _NODE)
_NODE_TOKEN = re.compile(_NODE)


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
    # dnf repograph selects a repo with the global --repo flag, not a positional
    # argument ("dnf repograph appstream" is rejected as unrecognized).
    args = ["dnf", "repograph"]
    if repo:
        args += ["--repo", repo]
    return _run(args, runner)


def run_rpmgraph(paths: list[str], *, runner: Runner | None = None) -> str:
    return _run(["rpmgraph", *paths], runner)


def parse_dot_edges(dot_text: str) -> list[tuple[str, str]]:
    """Extract directed ``A -> B`` edges from Graphviz dot text.

    Handles both forms ``dnf``/``rpmgraph`` emit:

    * simple ``"A" -> "B";`` (one or many per line), and
    * block ``"A" -> { "B" "C" ... }`` spanning lines, which modern
      ``dnf repograph`` uses -- each token in the block is an edge ``A -> token``.

    The two passes are disjoint: a simple edge's destination can never be ``{``.
    """

    edges: list[tuple[str, str]] = []
    for match in _BLOCK_EDGE.finditer(dot_text):
        src = (match.group(1) or match.group(2) or "").strip()
        if not src:
            continue
        for token in _NODE_TOKEN.finditer(match.group(3)):
            dst = (token.group(1) or token.group(2) or "").strip()
            if dst:
                edges.append((src, dst))
    for match in _SIMPLE_EDGE.finditer(dot_text):
        src = (match.group(1) or match.group(2) or "").strip().rstrip(";")
        dst = (match.group(3) or match.group(4) or "").strip().rstrip(";")
        if src and dst:
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

    # A repograph dot is package-name level (no arch), so a name maps to every
    # arch variant of that package in the graph. Index name -> all node ids and
    # attach the dependency to each (the previous setdefault kept only the first
    # arch, dropping the claim for the rest under --all-archs / a repo union).
    name_to_nodes: dict[str, list[str]] = {}
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        name = str(node.metadata.get("name") or _parse_node_token(node.label)[0])
        name_to_nodes.setdefault(name, []).append(node.id)

    edges = parse_dot_edges(dot_text)
    matched = 0
    added = 0
    seen: set[tuple[str, str, str]] = set()
    for src, dst in edges:
        src_name, _ = _parse_node_token(src)
        node_ids = name_to_nodes.get(src_name)
        if not node_ids:
            continue
        matched += 1
        dep_name, dep_version = _parse_node_token(dst)
        for node_id in node_ids:  # every arch variant of the source package
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
            add_dependency_claim(
                graph, DependencyClaim(subject_id=node_id, spec=spec, evidence=evidence)
            )
            added += 1
    return RpmgraphEnrichmentResult(edges=len(edges), matched_edges=matched, claims_added=added)


def _parse_node_token(token: str) -> tuple[str, str | None]:
    """Split an RPM node label into (name, version) - handles NEVRA or bare name."""

    nevra = RpmNevra.from_token(token)
    return nevra.name, nevra.evr


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

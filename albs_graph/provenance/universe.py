"""The dependency "universe" - a traversable graph across many packages.

Two ways to build it:

- ``universe_from_dot`` takes a ``dnf repograph`` / ``rpmgraph`` dot (the whole
  repo) and builds one node per package with ``requires`` edges between them.
  This is the "graph universe for all packages": ``libc`` ends up with an
  incoming edge from every package that links it, and you can traverse from any
  element back to ``libc`` and onward to anything else.
- ``build_universe`` collapses an enriched provenance graph's per-subject
  dependency *claims* into shared capability nodes, so a single ``libc.so.6``
  node is shared by every artifact that needs it (carrying linkage + evidence).

Either way the result is a ``ProvenanceGraph`` you can render (dot/svg/json) and
traverse with the helpers here: ``dependencies_of``, ``dependents_of``,
``reachable_dependencies`` and ``dependency_paths``.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from typing import Callable

from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation

from .trust import make_binary_rpm_selector

NodeSelector = Callable[[Node], bool]
# "X requires Y" edges - used for dependents/dependencies (direction matters).
_REQUIRES_RELATIONS = (Relation.REQUIRES_RUNTIME, Relation.DECLARES_DEPENDENCY)
# Traversal also follows PROVIDES so a soname capability bridges to its provider
# package (cap:zlib -PROVIDES-> cap:libz.so.1) when walking chains.
_TRAVERSE_RELATIONS = (Relation.REQUIRES_RUNTIME, Relation.DECLARES_DEPENDENCY, Relation.PROVIDES)


def universe_from_dot(dot_text: str, *, arch: str | None = None) -> ProvenanceGraph:
    """Build a repo-wide dependency universe from a repograph/rpmgraph dot graph."""

    # Lazy import keeps the provenance package free of a top-level adapters
    # dependency (adapters import provenance.reconcile).
    from albs_graph.adapters.dnf import parse_nevra
    from albs_graph.adapters.rpmgraph import parse_dot_edges

    universe = ProvenanceGraph()

    def ensure(token: str) -> str:
        name, version = parse_nevra(token)
        node_id = f"pkg:{name}"
        if node_id not in universe.nodes:
            universe.add_node(
                Node(node_id, NodeType.BINARY_RPM, name, {"name": name, "version": version})
            )
        return node_id

    seen: set[tuple[str, str]] = set()
    for src, dst in parse_dot_edges(dot_text):
        if arch and not _arch_ok(src, arch):
            continue
        src_id = ensure(src)
        dst_id = ensure(dst)
        key = (src_id, dst_id)
        if key in seen or src_id == dst_id:
            continue
        seen.add(key)
        universe.add_edge(src_id, dst_id, Relation.REQUIRES_RUNTIME)
    return universe


def build_universe(graph: ProvenanceGraph, *, node_selector: NodeSelector | None = None) -> ProvenanceGraph:
    """Collapse per-subject dependency claims into shared capability nodes.

    Packages are re-keyed to canonical ``pkg:<name>`` ids (keeping the original
    RPM node id in ``rpm_node_id``) so that universes built from different
    sources align when merged (see :func:`build_arch_universe`).
    """

    universe = ProvenanceGraph()
    subjects: dict[str, str] = {}  # original RPM node id -> canonical pkg:<name>
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        name = str(node.metadata.get("name") or node.label)
        pkg_id = f"pkg:{name}"
        if pkg_id not in universe.nodes:
            universe.add_node(
                Node(
                    pkg_id,
                    NodeType.BINARY_RPM,
                    name,
                    {
                        "name": name,
                        "arch": node.metadata.get("arch"),
                        "rpm_node_id": node.id,
                        "package": True,
                    },
                )
            )
        subjects[node.id] = pkg_id

    seen_edges: set[tuple[str, str, str]] = set()
    for claim in graph.find_by_type(NodeType.DEPENDENCY_CLAIM):
        subject = subjects.get(str(claim.metadata.get("subject", "")))
        if subject is None:
            continue
        coordinate, name, kind = _capability(claim.metadata)
        cap_id = f"cap:{coordinate}"
        if cap_id not in universe.nodes:
            universe.add_node(
                Node(
                    cap_id,
                    NodeType.EXTERNAL_PACKAGE,
                    name,
                    {"name": name, "coordinate": coordinate, "kind": kind, "capability": True},
                )
            )
        _add_edge_once(
            universe,
            seen_edges,
            subject,
            cap_id,
            Relation.REQUIRES_RUNTIME,
            linkage=claim.metadata.get("linkage"),
            evidence=claim.metadata.get("evidence"),
            scope=claim.metadata.get("scope"),
        )
        _maybe_link_provider(universe, seen_edges, claim, cap_id)
    return universe


def merge_graphs(graphs: Iterable[ProvenanceGraph]) -> ProvenanceGraph:
    """Union several graphs into one, de-duplicating nodes by id and edges by
    (source, target, relation). The first definition of a node id wins."""

    merged = ProvenanceGraph()
    graph_list = list(graphs)
    for graph in graph_list:
        for node in graph.nodes.values():
            if node.id not in merged.nodes:
                merged.add_node(node)
    seen: set[tuple[str, str, str]] = set()
    for graph in graph_list:
        for edge in graph.edges:
            key = (edge.source, edge.target, str(edge.relation))
            if key in seen:
                continue
            if edge.source in merged.nodes and edge.target in merged.nodes:
                seen.add(key)
                merged.add_edge(edge.source, edge.target, edge.relation, **edge.metadata)
    return merged


def build_arch_universe(
    *,
    dots: Iterable[str] = (),
    graphs: Iterable[ProvenanceGraph] = (),
    arch: str | None = None,
) -> ProvenanceGraph:
    """Merge many sources into one arch-wide universe.

    ``dots`` are ``dnf repograph`` / ``rpmgraph`` outputs (e.g. one per repo:
    baseos + appstream + crb); ``graphs`` are enriched provenance graphs whose
    dependency claims add linkage/soname/resolution detail. With canonical
    ``pkg:<name>`` ids, a package appearing in several sources is one node, so
    cross-repo edges (appstream's nginx-core -> baseos's glibc) connect.
    """

    components: list[ProvenanceGraph] = [universe_from_dot(dot, arch=arch) for dot in dots]
    graph_list = list(graphs)
    if graph_list:
        selector = make_binary_rpm_selector(arch=arch, all_archs=arch is None)
        components.extend(build_universe(graph, node_selector=selector) for graph in graph_list)
    return merge_graphs(components)


def dependencies_of(graph: ProvenanceGraph, node_id: str) -> list[str]:
    """Direct dependencies (capabilities/packages) the node requires."""

    if node_id not in graph.nodes:
        return []
    return sorted(
        {
            graph.nodes[edge.target].label
            for relation in _REQUIRES_RELATIONS
            for edge in graph.outgoing(node_id, relation)
        }
    )


def dependents_of(graph: ProvenanceGraph, capability: str) -> list[str]:
    """Everything that requires the given capability/package (who links libc)."""

    targets = _match_nodes(graph, capability)
    dependents: set[str] = set()
    for target in targets:
        for relation in _REQUIRES_RELATIONS:
            for edge in graph.incoming(target, relation):
                dependents.add(graph.nodes[edge.source].label)
    return sorted(dependents)


def reachable_dependencies(graph: ProvenanceGraph, start_id: str) -> set[str]:
    """Transitive closure of dependencies reachable from a node."""

    if start_id not in graph.nodes:
        return set()
    seen: set[str] = set()
    queue: deque[str] = deque([start_id])
    while queue:
        current = queue.popleft()
        for relation in _TRAVERSE_RELATIONS:
            for edge in graph.outgoing(current, relation):
                if edge.target not in seen:
                    seen.add(edge.target)
                    queue.append(edge.target)
    return seen


def dependency_paths(
    graph: ProvenanceGraph,
    start_id: str,
    target: str,
    *,
    max_depth: int = 8,
    max_paths: int = 25,
) -> list[list[str]]:
    """Paths from a start node to any node matching ``target`` over dep edges."""

    if start_id not in graph.nodes:
        return []
    target_ids = set(_match_nodes(graph, target))
    paths: list[list[str]] = []
    queue: deque[list[str]] = deque([[start_id]])
    while queue and len(paths) < max_paths:
        path = queue.popleft()
        if len(path) > max_depth:
            continue
        tail = path[-1]
        if tail in target_ids and len(path) > 1:
            paths.append(path)
            continue
        for relation in _TRAVERSE_RELATIONS:
            for edge in graph.outgoing(tail, relation):
                if edge.target not in path:
                    queue.append(path + [edge.target])
    return paths


def path_subgraph(graph: ProvenanceGraph, paths: list[list[str]]) -> ProvenanceGraph:
    """Induced subgraph over all nodes appearing in the given traversal paths."""

    node_ids: set[str] = set()
    for path in paths:
        node_ids.update(path)
    return graph.subgraph(node_ids)


def neighborhood_subgraph(
    graph: ProvenanceGraph, target: str, *, incoming: bool
) -> ProvenanceGraph:
    """Subgraph of a capability/package plus its direct dependents or dependencies.

    ``incoming=True`` keeps the things that require ``target`` (its dependents);
    ``incoming=False`` keeps what ``target`` requires (its dependencies).
    """

    centers = _match_nodes(graph, target)
    node_ids: set[str] = set(centers)
    for center in centers:
        for relation in _REQUIRES_RELATIONS:
            edges = graph.incoming(center, relation) if incoming else graph.outgoing(center, relation)
            for edge in edges:
                node_ids.add(edge.source if incoming else edge.target)
    return graph.subgraph(node_ids)


def _capability(metadata: dict[str, object]) -> tuple[str, str, str]:
    ecosystem = str(metadata.get("ecosystem", "generic"))
    namespace = metadata.get("namespace")
    name = str(metadata.get("name", "?"))
    prefix = f"{namespace}/" if namespace else ""
    coordinate = f"{ecosystem}:{prefix}{name}"
    kind = "soname" if ".so" in name else "package"
    return coordinate, name, kind


def _maybe_link_provider(
    universe: ProvenanceGraph,
    seen_edges: set[tuple[str, str, str]],
    claim: Node,
    cap_id: str,
) -> None:
    if claim.metadata.get("evidence") != "soname_provider":
        return
    dependency = claim.metadata.get("dependency")
    raw = dependency.get("raw", {}) if isinstance(dependency, dict) else {}
    soname = raw.get("soname") if isinstance(raw, dict) else None
    if not soname:
        return
    soname_coord = f"rpm:{soname}"
    soname_cap = f"cap:{soname_coord}"
    if soname_cap not in universe.nodes:
        universe.add_node(
            Node(
                soname_cap,
                NodeType.EXTERNAL_PACKAGE,
                str(soname),
                {"name": str(soname), "coordinate": soname_coord, "kind": "soname", "capability": True},
            )
        )
    _add_edge_once(universe, seen_edges, cap_id, soname_cap, Relation.PROVIDES, via="soname_provider")


def _add_edge_once(
    universe: ProvenanceGraph,
    seen_edges: set[tuple[str, str, str]],
    source: str,
    target: str,
    relation: Relation,
    **metadata: object,
) -> None:
    key = (source, target, str(relation))
    if key in seen_edges:
        return
    seen_edges.add(key)
    universe.add_edge(source, target, relation, **{k: v for k, v in metadata.items() if v is not None})


def _match_nodes(graph: ProvenanceGraph, needle: str) -> list[str]:
    matches: list[str] = []
    for node in graph.nodes.values():
        name = str(node.metadata.get("name") or "")
        coordinate = str(node.metadata.get("coordinate") or "")
        if needle == name or needle in node.id or needle == coordinate or needle in coordinate:
            matches.append(node.id)
    return matches


def _arch_ok(token: str, arch: str) -> bool:
    return token.endswith(f".{arch}") or token.endswith(".noarch") or "." not in token

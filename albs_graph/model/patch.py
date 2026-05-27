"""Evidence patches: a recorded, replayable set of graph mutations.

Adapters enrich the graph by mutating it in place. That is convenient but hard
to test, diff, cache or dry-run: there is no first-class "this is what the dnf
adapter would add" object. An :class:`EvidencePatch` is exactly that -- the
nodes, edges, metadata updates and warnings an adapter produced -- and a
:class:`RecordingGraph` captures one transparently while an adapter runs, with
no change to the adapter's code.

Two ways to get a patch:

* wrap a graph in a :class:`RecordingGraph` and run the adapter against it -- the
  writes are applied to the underlying graph (normal behaviour) *and* recorded;
* call :func:`capture_patch` with ``apply=False`` for a dry run -- the adapter
  runs against a throwaway copy, so the original graph is untouched and you get
  back just the patch ("what would this change?").

The patch then composes (:meth:`EvidencePatch.merge`), summarises, and re-applies
to any graph (:meth:`EvidencePatch.apply`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .edges import Relation
from .graph import ProvenanceGraph
from .nodes import Node


@dataclass(frozen=True)
class EdgeSpec:
    """A recorded edge: the arguments an ``add_edge`` call was made with."""

    source: str
    target: str
    relation: Relation | str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidencePatch:
    """The nodes, edges and metadata updates an adapter produced."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[EdgeSpec] = field(default_factory=list)
    metadata_updates: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.nodes or self.edges or self.metadata_updates or self.warnings)

    def summary(self) -> dict[str, int]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "metadata_updates": len(self.metadata_updates),
            "warnings": len(self.warnings),
        }

    def merge(self, other: EvidencePatch) -> EvidencePatch:
        """Compose two patches (this one first), without mutating either."""

        return EvidencePatch(
            nodes=self.nodes + other.nodes,
            edges=self.edges + other.edges,
            metadata_updates=self.metadata_updates + other.metadata_updates,
            warnings=self.warnings + other.warnings,
        )

    def apply(self, graph: ProvenanceGraph) -> None:
        """Replay the patch onto ``graph`` (nodes first, then edges, then updates)."""

        for node in self.nodes:
            graph.add_node(node)
        for spec in self.edges:
            graph.add_edge(spec.source, spec.target, spec.relation, **spec.metadata)
        for node_id, updates in self.metadata_updates:
            graph.update_metadata(node_id, updates)


class RecordingGraph(ProvenanceGraph):
    """A graph that records every mutation into an :class:`EvidencePatch`.

    It *shares* the wrapped graph's state (nodes, edges and indexes are the same
    objects), so reads see the live graph and writes mutate it exactly as before
    -- an adapter cannot tell the difference. The override of each write path also
    appends to :attr:`patch`, so after running an adapter ``recorder.patch`` is a
    first-class record of what it did. For a non-mutating dry run, wrap a copy
    (see :func:`capture_patch`).
    """

    def __init__(self, target: ProvenanceGraph) -> None:
        # Share the target's state rather than re-init fresh state, so the
        # recorder is a faithful live view that also captures writes.
        self.nodes = target.nodes
        self.edges = target.edges
        self._outgoing = target._outgoing
        self._incoming = target._incoming
        self._nodes_by_type = target._nodes_by_type
        self.patch = EvidencePatch()

    def add_node(self, node: Node) -> None:
        super().add_node(node)
        self.patch.nodes.append(node)

    def add_edge(self, source: str, target: str, relation: Relation | str, **metadata: Any) -> None:
        super().add_edge(source, target, relation, **metadata)
        self.patch.edges.append(
            EdgeSpec(source, target, Relation.canonical(relation), dict(metadata))
        )

    def update_metadata(self, node_id: str, updates: dict[str, Any]) -> None:
        super().update_metadata(node_id, updates)
        self.patch.metadata_updates.append((node_id, dict(updates)))

    def warn(self, message: str) -> None:
        """Record a warning into the patch (e.g. a skipped or ambiguous input)."""

        self.patch.warnings.append(message)


def capture_patch(
    graph: ProvenanceGraph,
    mutate: Callable[[ProvenanceGraph], Any],
    *,
    apply: bool = True,
) -> EvidencePatch:
    """Run ``mutate`` against a recorder and return the resulting patch.

    With ``apply=True`` (default) the writes land on ``graph`` as usual and are
    also recorded. With ``apply=False`` the run targets a throwaway copy, so
    ``graph`` is left untouched -- a dry run answering "what would this change?".
    """

    target = graph if apply else graph.copy()
    recorder = RecordingGraph(target)
    mutate(recorder)
    return recorder.patch

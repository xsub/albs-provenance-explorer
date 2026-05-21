from __future__ import annotations

import json
from pathlib import Path

from albs_graph.model import ProvenanceGraph


def graph_to_json(graph: ProvenanceGraph, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(graph.to_dict(), indent=2, sort_keys=True)
    return json.dumps(graph.to_dict(), separators=(",", ":"), sort_keys=True)


def write_json(graph: ProvenanceGraph, path: str | Path) -> None:
    Path(path).write_text(graph_to_json(graph), encoding="utf-8")

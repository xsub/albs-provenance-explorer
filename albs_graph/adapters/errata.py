from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation


def attach_errata_file(graph: ProvenanceGraph, rpm_node_id: str, errata_path: str | Path) -> str:
    path = Path(errata_path)
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    errata_id = f"errata:{data.get('id', path.stem)}"
    graph.add_node(
        Node(
            errata_id,
            NodeType.ERRATA,
            str(data.get("id", path.stem)),
            {
                "type": data.get("type"),
                "severity": data.get("severity"),
                "issued": data.get("issued"),
                "backported": data.get("backported", False),
                "source_path": str(path),
            },
        )
    )
    graph.add_edge(rpm_node_id, errata_id, Relation.FIXES)

    for cve in data.get("cves", []):
        cve_id = f"cve:{cve}"
        graph.add_node(Node(cve_id, NodeType.CVE, cve, {"source": "errata"}))
        graph.add_edge(errata_id, cve_id, Relation.FIXES)
    return errata_id

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from albs_graph.model import Node, ProvenanceGraph
from albs_graph.provenance.inventory import (
    rpm_artifact_inventory,
    summarize_artifacts_by_build_arch,
)


def test_live_build_artifact_inventory_preserves_multi_package_arch_matrix() -> None:
    graph = _graph_from_export(
        json.loads(Path("examples/live-build-17812/build-17812.json").read_text())
    )

    inventory = rpm_artifact_inventory(graph)
    summaries = {
        summary.build_arch: summary
        for summary in summarize_artifacts_by_build_arch(inventory)
    }

    assert set(summaries) == {"x86_64", "aarch64", "ppc64le", "s390x", "i686", "src"}
    assert summaries["x86_64"].total_artifacts == 19
    assert summaries["x86_64"].artifact_arches == {"x86_64": 16, "noarch": 2, "src": 1}
    assert "nginx-core" in summaries["x86_64"].packages
    assert "nginx-mod-http-xslt-filter" in summaries["x86_64"].packages
    assert "nginx-core-debuginfo" in summaries["x86_64"].packages
    assert summaries["src"].artifact_arches == {"src": 1}


def test_artifact_inventory_summary_exposes_complete_package_list() -> None:
    graph = _graph_from_export(
        json.loads(Path("examples/live-build-17812/build-17812.json").read_text())
    )

    inventory = rpm_artifact_inventory(graph)
    x86_64_summary = next(
        summary
        for summary in summarize_artifacts_by_build_arch(inventory)
        if summary.build_arch == "x86_64"
    )

    assert len(x86_64_summary.packages) == 18
    assert x86_64_summary.packages[-1] == "nginx-mod-stream-debuginfo"


def test_artifact_inventory_rows_keep_artifact_identity_evidence() -> None:
    graph = _graph_from_export(
        json.loads(Path("examples/live-build-17812/build-17812.json").read_text())
    )

    inventory = rpm_artifact_inventory(graph)
    nginx_core = next(
        item
        for item in inventory
        if item.build_arch == "x86_64"
        and item.package_name == "nginx-core"
        and item.artifact_arch == "x86_64"
    )

    assert nginx_core.artifact_id == "3237140"
    assert nginx_core.kind == "binary"
    assert nginx_core.purl == (
        "pkg:rpm/almalinux/nginx-core@1.20.1-16.el9_4.1?arch=x86_64&distro=almalinux-9"
    )
    assert nginx_core.cas_hash == "e81b769bd3647a3310fff0d364f19980d1fe39f01a444feffdfed9430a68f4c3"


def _graph_from_export(data: dict[str, Any]) -> ProvenanceGraph:
    graph = ProvenanceGraph()
    for node in data["nodes"]:
        graph.add_node(Node(node["id"], node["type"], node["label"], node["metadata"]))
    for edge in data["edges"]:
        graph.add_edge(edge["source"], edge["target"], edge["relation"], **edge["metadata"])
    return graph

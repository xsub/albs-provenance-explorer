from __future__ import annotations

import re
import shutil

import pytest

from albs_graph.fixtures import build_synthetic_fixture_graph
from albs_graph.gui.render import workbench_graph_rendering, workbench_graph_to_dot


@pytest.mark.skipif(shutil.which("dot") is None, reason="graphviz 'dot' not installed")
def test_cmapx_regions_share_the_svg_coordinate_space() -> None:
    # Regression: the clickable image map (cmapx) defaulted to ~96 dpi while the
    # SVG is in 72-dpi points, so the hit regions were ~1.3x too large and clicks
    # only ever landed near the top-left ("barely reacts"). Every region
    # coordinate must lie within the SVG viewBox.
    rendering = workbench_graph_rendering(build_synthetic_fixture_graph(), dark=False)
    regions = rendering.node_regions + rendering.edge_regions
    assert regions  # graphviz produced a real image map
    match = re.search(r'viewBox="[\d.]+ [\d.]+ ([\d.]+) ([\d.]+)"', rendering.svg)
    assert match is not None
    width, height = float(match.group(1)), float(match.group(2))
    xs = [c for region in regions for c in region.coords[0::2]]
    ys = [c for region in regions for c in region.coords[1::2]]
    assert max(xs) <= width * 1.02 and min(xs) >= -2  # a few px of node margin
    assert max(ys) <= height * 1.02 and min(ys) >= -2


def test_workbench_dot_uses_dark_theme() -> None:
    dot = workbench_graph_to_dot(build_synthetic_fixture_graph(), dark=True)

    assert 'bgcolor="#171A1F"' in dot
    assert 'fontcolor="#F0F3F7"' in dot
    assert "Inter" not in dot
    assert "Helvetica" not in dot


def test_workbench_dot_wraps_long_rpm_labels() -> None:
    dot = workbench_graph_to_dot(build_synthetic_fixture_graph())

    assert "binary rpm\\nsynthetic-core" in dot
    assert ".x86_64.rpm" not in dot


def test_workbench_dot_marks_nodes_clickable_and_highlights_selection() -> None:
    graph = build_synthetic_fixture_graph()
    selected = next(iter(graph.nodes))

    dot = workbench_graph_to_dot(graph, selected_node_id=selected)

    assert 'URL="node:' in dot
    assert 'color="#2F6FED", penwidth=3.0' in dot


def test_workbench_dot_marks_edges_clickable_and_highlights_selection() -> None:
    graph = build_synthetic_fixture_graph()

    dot = workbench_graph_to_dot(graph, selected_edge_index=0)

    assert 'URL="edge:0"' in dot
    assert 'color="#2F6FED", penwidth=3.2' in dot


def test_graph_background_matches_the_theme() -> None:
    # The GUI paints the graph's frame this exact colour so there is no seam (D135).
    from albs_graph.gui.render import graph_background

    assert graph_background(True) == "#171A1F"
    assert graph_background(False) == "#FFFFFF"

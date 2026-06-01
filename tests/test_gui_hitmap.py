from __future__ import annotations

from albs_graph.gui.hitmap import (
    EdgeRegion,
    NodeRegion,
    edge_at,
    graph_regions_from_cmap,
    node_at,
    node_regions_from_cmap,
)


def test_node_regions_from_cmap_decodes_graphviz_node_urls() -> None:
    cmapx = """
    <map id="albs_workbench" name="albs_workbench">
      <area shape="poly" href="node:rpm%3A1" coords="0,0,20,0,20,20,0,20"/>
    </map>
    """

    regions = node_regions_from_cmap(cmapx)

    assert regions == (
        NodeRegion("rpm:1", "poly", (0.0, 0.0, 20.0, 0.0, 20.0, 20.0, 0.0, 20.0)),
    )
    assert node_at(regions, 10, 10) == "rpm:1"
    assert node_at(regions, 30, 10) is None


def test_graph_regions_from_cmap_decodes_edge_urls() -> None:
    cmapx = """
    <map id="albs_workbench" name="albs_workbench">
      <area shape="poly" href="edge:7" coords="0,0,20,0,20,20,0,20"/>
    </map>
    """

    regions = graph_regions_from_cmap(cmapx)

    assert regions.nodes == ()
    assert regions.edges == (
        EdgeRegion(7, "poly", (0.0, 0.0, 20.0, 0.0, 20.0, 20.0, 0.0, 20.0)),
    )
    assert edge_at(regions.edges, 10, 10) == 7
    assert edge_at(regions.edges, 30, 10) is None


def test_node_region_supports_rect_circle_and_polygon_hits() -> None:
    regions = (
        NodeRegion("rect", "rect", (2, 4, 12, 14)),
        NodeRegion("circle", "circle", (30, 30, 5)),
        NodeRegion("poly", "poly", (50, 50, 70, 50, 70, 70, 50, 70)),
    )

    assert node_at(regions, 4, 6) == "rect"
    assert node_at(regions, 31, 31) == "circle"
    assert node_at(regions, 60, 60) == "poly"
    assert node_at(regions, 45, 45) is None


def test_node_region_center_for_scrolling() -> None:
    # The bbox/circle centre in SVG coords, used to scroll the graph to a node
    # (D129).
    assert NodeRegion("r", "rect", (2, 4, 12, 14)).center() == (7.0, 9.0)
    assert NodeRegion("c", "circle", (30, 40, 5)).center() == (30.0, 40.0)
    assert NodeRegion("p", "poly", (50, 50, 70, 50, 70, 70, 50, 70)).center() == (60.0, 60.0)

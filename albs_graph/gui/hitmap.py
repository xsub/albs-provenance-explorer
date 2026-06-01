from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import unquote


@dataclass(frozen=True)
class NodeRegion:
    node_id: str
    shape: str
    coords: tuple[float, ...]

    def contains(self, x: float, y: float) -> bool:
        return _contains(self.shape, self.coords, x, y)

    def center(self) -> tuple[float, float]:
        """The region's centre in SVG coordinates (for scrolling to it, D129)."""

        if self.shape == "circle" and len(self.coords) >= 2:
            return self.coords[0], self.coords[1]
        xs = self.coords[0::2]
        ys = self.coords[1::2]
        if not xs or not ys:
            return 0.0, 0.0
        return (min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2


@dataclass(frozen=True)
class EdgeRegion:
    edge_index: int
    shape: str
    coords: tuple[float, ...]

    def contains(self, x: float, y: float) -> bool:
        return _contains(self.shape, self.coords, x, y)


@dataclass(frozen=True)
class GraphRegions:
    nodes: tuple[NodeRegion, ...]
    edges: tuple[EdgeRegion, ...]


def node_regions_from_cmap(cmapx: str) -> tuple[NodeRegion, ...]:
    return graph_regions_from_cmap(cmapx).nodes


def graph_regions_from_cmap(cmapx: str) -> GraphRegions:
    parser = _CMapParser()
    parser.feed(cmapx)
    return GraphRegions(nodes=tuple(parser.node_regions), edges=tuple(parser.edge_regions))


def node_at(regions: tuple[NodeRegion, ...], x: float, y: float) -> str | None:
    for region in reversed(regions):
        if region.contains(x, y):
            return region.node_id
    return None


def edge_at(regions: tuple[EdgeRegion, ...], x: float, y: float) -> int | None:
    for region in reversed(regions):
        if region.contains(x, y):
            return region.edge_index
    return None


class _CMapParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.node_regions: list[NodeRegion] = []
        self.edge_regions: list[EdgeRegion] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "area":
            return
        values = {key: value for key, value in attrs if value is not None}
        href = unquote(values.get("href", ""))
        coords = _parse_coords(values.get("coords", ""))
        if not coords:
            return
        shape = values.get("shape", "").lower()
        if href.startswith("node:"):
            self.node_regions.append(
                NodeRegion(
                    node_id=href.removeprefix("node:"),
                    shape=shape,
                    coords=coords,
                )
            )
        elif href.startswith("edge:"):
            try:
                edge_index = int(href.removeprefix("edge:"))
            except ValueError:
                return
            self.edge_regions.append(EdgeRegion(edge_index=edge_index, shape=shape, coords=coords))


def _parse_coords(value: str) -> tuple[float, ...]:
    coords: list[float] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            coords.append(float(item))
        except ValueError:
            return ()
    return tuple(coords)


def _point_in_polygon(x: float, y: float, coords: tuple[float, ...]) -> bool:
    points = list(zip(coords[0::2], coords[1::2]))
    inside = False
    previous_x, previous_y = points[-1]
    for current_x, current_y in points:
        intersects = (current_y > y) != (previous_y > y)
        if intersects:
            x_intersection = (previous_x - current_x) * (y - current_y) / (
                previous_y - current_y
            ) + current_x
            if x < x_intersection:
                inside = not inside
        previous_x, previous_y = current_x, current_y
    return inside


def _contains(shape: str, coords: tuple[float, ...], x: float, y: float) -> bool:
    if shape == "rect" and len(coords) >= 4:
        left, top, right, bottom = coords[:4]
        return left <= x <= right and top <= y <= bottom
    if shape == "circle" and len(coords) >= 3:
        cx, cy, radius = coords[:3]
        return (x - cx) ** 2 + (y - cy) ** 2 <= radius**2
    if shape in {"poly", "polygon"} and len(coords) >= 6:
        return _point_in_polygon(x, y, coords)
    return False

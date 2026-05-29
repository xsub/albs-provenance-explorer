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
        if self.shape == "rect" and len(self.coords) >= 4:
            left, top, right, bottom = self.coords[:4]
            return left <= x <= right and top <= y <= bottom
        if self.shape == "circle" and len(self.coords) >= 3:
            cx, cy, radius = self.coords[:3]
            return (x - cx) ** 2 + (y - cy) ** 2 <= radius**2
        if self.shape in {"poly", "polygon"} and len(self.coords) >= 6:
            return _point_in_polygon(x, y, self.coords)
        return False


def node_regions_from_cmap(cmapx: str) -> tuple[NodeRegion, ...]:
    parser = _CMapParser()
    parser.feed(cmapx)
    return tuple(parser.regions)


def node_at(regions: tuple[NodeRegion, ...], x: float, y: float) -> str | None:
    for region in reversed(regions):
        if region.contains(x, y):
            return region.node_id
    return None


class _CMapParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.regions: list[NodeRegion] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "area":
            return
        values = {key: value for key, value in attrs if value is not None}
        href = unquote(values.get("href", ""))
        if not href.startswith("node:"):
            return
        coords = _parse_coords(values.get("coords", ""))
        if not coords:
            return
        self.regions.append(
            NodeRegion(
                node_id=href.removeprefix("node:"),
                shape=values.get("shape", "").lower(),
                coords=coords,
            )
        )


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

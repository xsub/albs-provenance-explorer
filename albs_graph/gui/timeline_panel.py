"""The build-task timeline panel, extracted as a typed widget (god-object #4).

Fourth cut of the splitting started in D102. Bundles the two timeline views --
the tree (a ``QTreeWidget``) and the Gantt cascade (a custom ``QGraphicsView``)
behind a Tree/Gantt switch -- plus the Gantt drawing code and its helpers that
previously lived at module scope in ``qt_app.py``. The host drives it with
``populate(graph, build_analysis, *, dark)`` and injects one ``navigate``
callback; both views emit it on activation. Type-checks under mypy strict.
"""

from __future__ import annotations

import math
from typing import Callable

from PyQt5 import QtCore, QtGui, QtWidgets

from albs_graph.model import ProvenanceGraph
from albs_graph.provenance.build_analysis import BuildAnalysis
from albs_graph.services import (
    TimelineGanttRow,
    TimelineTreeItem,
    timeline_gantt_rows,
    timeline_tree,
)

NavigateFn = Callable[[str], None]

GANTT_MIN_HEIGHT = 48
_HEADERS = ["Stage", "Status", "Duration", "Started", "Finished", "Graph node", "Detail"]

# Gantt layout, in scene coordinates. The bars are a *duration* cascade: every
# row starts at the same baseline and its width is its own duration, so the eye
# compares how long each step took. The time scale is fitted to the bulk of the
# (short) tasks -- a high percentile of the durations -- so a few very long tasks
# cannot squash everything else into invisible slivers; those long bars are
# clipped to the full width, flagged with a "…", and their real duration is shown
# past the end. The name/status columns left of the bars are elided so a long
# stage name can never overwrite the status column. The timeline width tracks the
# viewport so the chart fills the window instead of a fixed canvas.
_NAME_X = 10
_DETAIL_X = 252
_BARS_LEFT = 356
_NAME_BUDGET = _DETAIL_X - _NAME_X - 18  # px the stage name may use before status
_DETAIL_BUDGET = _BARS_LEFT - _DETAIL_X - 16  # px the status may use before bars
_RIGHT_MARGIN = 100  # room for the duration label past a (clipped) bar
_MIN_TIMELINE_WIDTH = 240
_TOP = 64  # axis baseline; the band above holds the clip note (top) + tick labels
_ROW_HEIGHT = 28
_BAR_HEIGHT = 16
_SCALE_PERCENTILE = 0.90


class TimelineGanttView(QtWidgets.QGraphicsView):
    """A Gantt cascade of the build-task timeline; emits ``nodeActivated``."""

    nodeActivated = QtCore.pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self._scene = QtWidgets.QGraphicsScene(self)
        self.setScene(self._scene)
        # node id -> its row label item, and a pending "scroll to this node" that
        # is (re)applied on show/resize so it lands even when the Gantt was the
        # hidden sub-view at click time (D127).
        self._node_items: dict[str, QtWidgets.QGraphicsItem] = {}
        self._pending_node: str | None = None
        # The rows + theme are kept so the chart can re-lay-out itself when the
        # viewport is resized (the timeline width tracks the window).
        self._rows: list[TimelineGanttRow] = []
        self._dark = True
        self._last_layout_width = 0
        self.setRenderHint(QtGui.QPainter.Antialiasing, True)
        self.setDragMode(QtWidgets.QGraphicsView.ScrollHandDrag)
        self.setMinimumHeight(GANTT_MIN_HEIGHT)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Ignored)

    def set_events(
        self, graph: ProvenanceGraph, build_analysis: BuildAnalysis | None, *, dark: bool
    ) -> None:
        self._rows = timeline_gantt_rows(graph, build_analysis)
        self._dark = dark
        self._pending_node = None
        self._relayout()

    def _viewport_width(self) -> int:
        viewport = self.viewport()
        return viewport.width() if viewport is not None else 0

    def _timeline_width(self) -> int:
        available = self._viewport_width() - _BARS_LEFT - _RIGHT_MARGIN
        return max(_MIN_TIMELINE_WIDTH, available)

    def _relayout(self) -> None:
        self._scene.clear()
        self._node_items = {}
        self._last_layout_width = self._viewport_width()
        rows = self._rows
        if not rows:
            self._scene.addText("No timeline data")
            return
        palette = _gantt_palette(self._dark)
        timeline_width = self._timeline_width()
        display_cap, actual_max, clipped = _duration_scale(rows)
        scale = timeline_width / display_cap
        self._draw_gantt_axis(
            palette, timeline_width, display_cap, scale, actual_max=actual_max, clipped=clipped
        )
        for index, row in enumerate(rows):
            y = _TOP + 22 + index * _ROW_HEIGHT
            self._draw_gantt_row(palette, row, y, timeline_width, scale)
        height = _TOP + 48 + len(rows) * _ROW_HEIGHT
        self._scene.setSceneRect(0, 0, _BARS_LEFT + timeline_width + _RIGHT_MARGIN, height)
        self._apply_pending_scroll()

    def _relayout_if_resized(self) -> None:
        if not self._rows:
            return
        if abs(self._viewport_width() - self._last_layout_width) > 8:
            self._relayout()

    def mousePressEvent(self, event: QtGui.QMouseEvent | None) -> None:
        self._pending_node = None  # the user is navigating; stop auto-recentring
        if event is None:
            super().mousePressEvent(event)
            return
        item = self.itemAt(event.pos())
        while item is not None:
            node_id = item.data(0)
            if node_id:
                self.nodeActivated.emit(str(node_id))
                return
            item = item.parentItem()
        super().mousePressEvent(event)

    def find_node(self, node_id: str) -> bool:
        return node_id in self._node_items

    def scroll_to_node(self, node_id: str) -> bool:
        """Bring ``node_id``'s row into view (D124/D127). Records it as pending so
        the scroll re-applies on show/resize -- it lands even when the Gantt was
        the hidden sub-view (size 0) at click time. Returns whether it was found."""

        if node_id not in self._node_items:
            return False
        self._pending_node = node_id
        self._apply_pending_scroll()
        return True

    def _apply_pending_scroll(self) -> None:
        if self._pending_node is None:
            return
        item = self._node_items.get(self._pending_node)
        if item is not None:
            self.ensureVisible(item, 80, 40)

    def showEvent(self, event: QtGui.QShowEvent | None) -> None:
        super().showEvent(event)
        self._relayout_if_resized()
        self._apply_pending_scroll()

    def resizeEvent(self, event: QtGui.QResizeEvent | None) -> None:
        super().resizeEvent(event)
        self._relayout_if_resized()
        self._apply_pending_scroll()

    def _draw_gantt_axis(
        self,
        palette: dict[str, QtGui.QColor],
        width: int,
        span: float,
        scale: float,
        *,
        actual_max: float,
        clipped: int,
    ) -> None:
        pen = QtGui.QPen(palette["grid"])
        self._scene.addLine(_BARS_LEFT, _TOP, _BARS_LEFT + width, _TOP, pen)
        bottom = _TOP + 48 + len(self._rows) * _ROW_HEIGHT
        tick_count = 5
        for index in range(tick_count + 1):
            seconds = span * index / tick_count
            x = _BARS_LEFT + seconds * scale
            self._scene.addLine(x, _TOP - 5, x, bottom, pen)
            text = _format_seconds(seconds)
            if index == tick_count and clipped:
                text += "+"  # the scale is capped; bars beyond it are clipped
            label = _scene_text(self._scene, text)
            label.setDefaultTextColor(palette["muted"])
            label.setPos(x - 18, 34)  # just above the axis line, below the note
        if clipped:
            note = _scene_text(
                self._scene,
                f"scale fitted to {_format_seconds(span)} · "
                f"{clipped} longer task(s) clipped (max {_format_seconds(actual_max)})",
            )
            note.setDefaultTextColor(palette["muted"])
            note.setPos(_NAME_X, 2)  # own line at the very top, clear of the ticks

    def _draw_gantt_row(
        self,
        palette: dict[str, QtGui.QColor],
        row: TimelineGanttRow,
        y: float,
        timeline_width: int,
        scale: float,
    ) -> None:
        tip = _row_tooltip(row)
        name = "  " * row.depth + row.label
        name_item = _elided_text_item(self._scene, name, _NAME_BUDGET)
        name_item.setDefaultTextColor(palette["text"])
        name_item.setPos(_NAME_X, y - 7)
        name_item.setToolTip(tip)
        if row.node_id:
            name_item.setData(0, row.node_id)
            self._node_items[row.node_id] = name_item  # for scroll_to_node (D127)
        detail_item = _elided_text_item(self._scene, row.status or row.kind, _DETAIL_BUDGET)
        detail_item.setDefaultTextColor(palette["muted"])
        detail_item.setPos(_DETAIL_X, y - 7)
        # The bar is the row's duration from a shared baseline; a bar longer than
        # the fitted scale clips to the full width and is flagged "…" so the short
        # majority stays readable.
        raw_width = row.duration_seconds * scale if row.duration_seconds else 0.0
        is_clipped = raw_width > timeline_width
        if is_clipped:
            drawn_width = float(timeline_width)
        elif row.duration_seconds:
            drawn_width = max(raw_width, 5.0)
        else:
            drawn_width = 7.0
        rect = QtCore.QRectF(_BARS_LEFT, y - 7, drawn_width, _BAR_HEIGHT)
        fill = palette.get(row.kind, palette["bar"])
        path = QtGui.QPainterPath()
        path.addRoundedRect(rect, 4, 4)
        item = self._scene.addPath(path, QtGui.QPen(palette["bar_border"]), QtGui.QBrush(fill))
        if item is not None and row.node_id:
            item.setData(0, row.node_id)
            item.setToolTip(tip)
        if is_clipped:
            marker = _scene_text(self._scene, "…")
            marker.setDefaultTextColor(palette["bar_border"])
            marker.setPos(_BARS_LEFT + timeline_width - 24, y - 10)
        duration = _format_seconds(row.duration_seconds)
        if duration:
            duration_item = _elided_text_item(self._scene, duration, _RIGHT_MARGIN - 12)
            duration_item.setDefaultTextColor(palette["muted"])
            duration_item.setPos(_BARS_LEFT + drawn_width + 6, y - 7)
        self._scene.addLine(
            0,
            y + _ROW_HEIGHT / 2 - 1,
            _BARS_LEFT + timeline_width,
            y + _ROW_HEIGHT / 2 - 1,
            QtGui.QPen(palette["row"]),
        )


class TimelinePanel(QtWidgets.QWidget):
    """Tree + Gantt views of the build-task timeline behind a view switch."""

    def __init__(self, *, navigate: NavigateFn, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._navigate = navigate

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(_HEADERS)
        self.tree.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tree.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tree.setAlternatingRowColors(True)
        # The "Stage" labels (e.g. build_done_stats.logs_processing) are long and
        # were overflowing into "Status". Auto-fit column 0 to its content and
        # elide anything that still does not fit, so columns never overlap.
        self.tree.setTextElideMode(QtCore.Qt.TextElideMode.ElideRight)
        tree_header = self.tree.header()
        if tree_header is not None:
            tree_header.setSectionResizeMode(
                0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
            )
            tree_header.setStretchLastSection(True)
        self.view_combo = QtWidgets.QComboBox()
        self.view_combo.addItems(["Tree", "Gantt"])
        # Without a minimum the combo gets squeezed to "Ga…" in a narrow dock.
        self.view_combo.setMinimumWidth(96)
        self.view_combo.setSizeAdjustPolicy(
            QtWidgets.QComboBox.SizeAdjustPolicy.AdjustToContents
        )
        self.gantt = TimelineGanttView()
        self.stack = QtWidgets.QStackedWidget()
        self.stack.addWidget(self.tree)
        self.stack.addWidget(self.gantt)
        self.stack.setMinimumHeight(0)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        header = QtWidgets.QHBoxLayout()
        header.setContentsMargins(6, 4, 6, 4)
        header.addStretch(1)
        header.addWidget(self.view_combo)
        layout.addLayout(header)
        layout.addWidget(self.stack)

        self.tree.itemActivated.connect(self._tree_activated)
        self.tree.itemDoubleClicked.connect(self._tree_activated)
        self.gantt.nodeActivated.connect(self._navigate)
        self.view_combo.currentIndexChanged.connect(self.stack.setCurrentIndex)
        # The Gantt is the more useful default (the graph<->timeline jump lands
        # on it); selecting it here also switches the stacked view via the signal
        # above. Tree stays one click away for exact per-step start/finish times.
        gantt_index = self.view_combo.findText("Gantt")
        if gantt_index >= 0:
            self.view_combo.setCurrentIndex(gantt_index)

    def populate(
        self, graph: ProvenanceGraph, build_analysis: BuildAnalysis | None, *, dark: bool
    ) -> None:
        self.tree.clear()
        for event in timeline_tree(graph, build_analysis):
            self.tree.addTopLevelItem(self._tree_item(event))
        self.gantt.set_events(graph, build_analysis, dark=dark)
        self.tree.expandToDepth(1)
        # Column 0 auto-fits via ResizeToContents; size the rest to their content.
        for column in range(1, self.tree.columnCount()):
            self.tree.resizeColumnToContents(column)

    def _tree_item(self, event: TimelineTreeItem) -> QtWidgets.QTreeWidgetItem:
        item = QtWidgets.QTreeWidgetItem(
            [
                event.label,
                event.status,
                _format_seconds(event.duration_seconds),
                event.started_at or "",
                event.finished_at or "",
                event.node_id,
                event.detail,
            ]
        )
        item.setData(0, QtCore.Qt.ItemDataRole.UserRole, event.node_id)
        for child in event.children:
            item.addChild(self._tree_item(child))
        return item

    def _tree_activated(self, item: QtWidgets.QTreeWidgetItem, _column: int = 0) -> None:
        node_id = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
        if node_id:
            self._navigate(str(node_id))

    def reveal_node(self, node_id: str) -> bool:
        """Reveal ``node_id`` in the timeline (D124/D127): select + scroll the
        tree, and -- when the Gantt has the row -- switch to the Gantt sub-view
        and scroll it to the row (the scroll re-applies on show so it lands even
        if the Gantt was hidden). Returns whether the node was found."""

        if not node_id:
            return False
        item = self._find_tree_item(node_id)
        if item is not None:
            self.tree.setCurrentItem(item)
            self.tree.scrollToItem(
                item, QtWidgets.QAbstractItemView.ScrollHint.PositionAtCenter
            )
        found_in_gantt = self.gantt.find_node(node_id)
        if found_in_gantt:
            gantt_index = self.stack.indexOf(self.gantt)
            if gantt_index >= 0:
                self.view_combo.setCurrentIndex(gantt_index)  # show the Gantt sub-view
            self.gantt.scroll_to_node(node_id)
        return item is not None or found_in_gantt

    def _find_tree_item(self, node_id: str) -> QtWidgets.QTreeWidgetItem | None:
        iterator = QtWidgets.QTreeWidgetItemIterator(self.tree)
        while True:
            item = iterator.value()
            if item is None:
                return None
            if str(item.data(0, QtCore.Qt.ItemDataRole.UserRole) or "") == node_id:
                return item
            iterator += 1


def _scene_text(scene: QtWidgets.QGraphicsScene, text: str) -> QtWidgets.QGraphicsTextItem:
    # QGraphicsScene.addText is typed as Optional in the PyQt5 stubs but never
    # returns None in practice; assert it so the panel stays ignore-free.
    item = scene.addText(text)
    assert item is not None
    return item


def _elided_text_item(
    scene: QtWidgets.QGraphicsScene, text: str, max_px: int
) -> QtWidgets.QGraphicsTextItem:
    """A scene text item whose visible text is right-elided to ``max_px`` so a
    long stage name can never overwrite the next column. The caller exposes the
    full text via a tooltip."""

    item = _scene_text(scene, text)
    metrics = QtGui.QFontMetrics(item.font())
    elided = metrics.elidedText(text, QtCore.Qt.TextElideMode.ElideRight, max(0, max_px))
    if elided != text:
        item.setPlainText(elided)
    return item


def _duration_scale(rows: list[TimelineGanttRow]) -> tuple[float, float, int]:
    """Pick the Gantt time scale: a high percentile of the row durations, so the
    bulk of the (short) tasks fill the scale and only the long tail clips. Returns
    ``(display_cap, actual_max, clipped_count)``."""

    durations = sorted(row.duration_seconds for row in rows if row.duration_seconds > 0)
    actual_max = max((row.duration_seconds for row in rows), default=0.0)
    actual_max = max(actual_max, 1.0)
    if durations:
        index = min(len(durations) - 1, max(0, math.ceil(_SCALE_PERCENTILE * len(durations)) - 1))
        cap = durations[index]
    else:
        cap = actual_max
    cap = min(max(cap, 1.0), actual_max)
    clipped = sum(1 for row in rows if row.duration_seconds > cap * 1.0001)
    return cap, actual_max, clipped


def _row_tooltip(row: TimelineGanttRow) -> str:
    parts = [row.label]
    if row.status:
        parts.append(f"status: {row.status}")
    parts.append(f"duration: {_format_seconds(row.duration_seconds) or '0.00s'}")
    if row.started_at:
        parts.append(f"started: {row.started_at}")
    if row.finished_at:
        parts.append(f"finished: {row.finished_at}")
    if row.node_id:
        parts.append(row.node_id)
    return "\n".join(parts)


def _format_seconds(value: float | None) -> str:
    if value is None:
        return ""
    if value < 60:
        return f"{value:.2f}s"
    minutes, seconds = divmod(value, 60)
    if minutes < 60:
        return f"{int(minutes)}m {seconds:.1f}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m {seconds:.0f}s"


def _gantt_palette(dark: bool) -> dict[str, QtGui.QColor]:
    if dark:
        return {
            "text": QtGui.QColor("#EEF2F6"),
            "muted": QtGui.QColor("#AAB5C2"),
            "grid": QtGui.QColor("#3C4652"),
            "row": QtGui.QColor("#252B33"),
            "bar": QtGui.QColor("#2F6FED"),
            "bar_border": QtGui.QColor("#8AB4FF"),
            "build_task": QtGui.QColor("#5A3B66"),
            "build_step": QtGui.QColor("#2F6FED"),
            "test_tasks": QtGui.QColor("#35546B"),
            "test_step": QtGui.QColor("#4B7190"),
            "artifacts": QtGui.QColor("#4B4F5C"),
            "artifact_group": QtGui.QColor("#6B5B38"),
            "sign_task": QtGui.QColor("#6B4C2F"),
            "sign_step": QtGui.QColor("#8A633F"),
        }
    return {
        "text": QtGui.QColor("#17212B"),
        "muted": QtGui.QColor("#52616F"),
        "grid": QtGui.QColor("#D8DDE6"),
        "row": QtGui.QColor("#EEF2F6"),
        "bar": QtGui.QColor("#2F6FED"),
        "bar_border": QtGui.QColor("#174EA6"),
        "build_task": QtGui.QColor("#DCC8E8"),
        "build_step": QtGui.QColor("#8EB7FF"),
        "test_tasks": QtGui.QColor("#BFD7EA"),
        "test_step": QtGui.QColor("#9AC2E0"),
        "artifacts": QtGui.QColor("#DDD7C8"),
        "artifact_group": QtGui.QColor("#E6D5A9"),
        "sign_task": QtGui.QColor("#E8C9A5"),
        "sign_step": QtGui.QColor("#D9AA76"),
    }

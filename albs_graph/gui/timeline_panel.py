"""The build-task timeline panel, extracted as a typed widget (god-object #4).

Fourth cut of the splitting started in D102. Bundles the two timeline views --
the tree (a ``QTreeWidget``) and the Gantt cascade (a custom ``QGraphicsView``)
behind a Tree/Gantt switch -- plus the Gantt drawing code and its helpers that
previously lived at module scope in ``qt_app.py``. The host drives it with
``populate(graph, build_analysis, *, dark)`` and injects one ``navigate``
callback; both views emit it on activation. Type-checks under mypy strict.
"""

from __future__ import annotations

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


class TimelineGanttView(QtWidgets.QGraphicsView):
    """A Gantt cascade of the build-task timeline; emits ``nodeActivated``."""

    nodeActivated = QtCore.pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self._scene = QtWidgets.QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QtGui.QPainter.Antialiasing, True)
        self.setDragMode(QtWidgets.QGraphicsView.ScrollHandDrag)
        self.setMinimumHeight(GANTT_MIN_HEIGHT)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Ignored)

    def set_events(
        self, graph: ProvenanceGraph, build_analysis: BuildAnalysis | None, *, dark: bool
    ) -> None:
        rows = timeline_gantt_rows(graph, build_analysis)
        self._scene.clear()
        if not rows:
            self._scene.addText("No timeline data")
            return
        palette = _gantt_palette(dark)
        label_width = 330
        left = label_width + 36
        top = 42
        row_height = 28
        timeline_width = 920
        span = max((row.offset_seconds + row.duration_seconds for row in rows), default=1.0)
        span = max(span, 1.0)
        scale = timeline_width / span
        self._draw_gantt_axis(palette, left, top, timeline_width, span, scale)
        for index, row in enumerate(rows):
            y = top + 22 + index * row_height
            self._draw_gantt_row(palette, row, y, left, label_width, scale, row_height)
        self._scene.setSceneRect(0, 0, left + timeline_width + 180, top + 48 + len(rows) * row_height)

    def mousePressEvent(self, event: QtGui.QMouseEvent | None) -> None:
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

    def _draw_gantt_axis(
        self,
        palette: dict[str, QtGui.QColor],
        left: int,
        top: int,
        width: int,
        span: float,
        scale: float,
    ) -> None:
        pen = QtGui.QPen(palette["grid"])
        self._scene.addLine(left, top, left + width, top, pen)
        tick_count = 5
        for index in range(tick_count + 1):
            seconds = span * index / tick_count
            x = left + seconds * scale
            self._scene.addLine(x, top - 5, x, top + 9000, pen)
            label = _scene_text(self._scene, _format_seconds(seconds))
            label.setDefaultTextColor(palette["muted"])
            label.setPos(x - 18, 12)

    def _draw_gantt_row(
        self,
        palette: dict[str, QtGui.QColor],
        row: TimelineGanttRow,
        y: float,
        left: int,
        label_width: int,
        scale: float,
        row_height: int,
    ) -> None:
        text = "  " * row.depth + row.label
        label = _scene_text(self._scene, text)
        label.setDefaultTextColor(palette["text"])
        label.setPos(8, y - 7)
        if row.node_id:
            label.setData(0, row.node_id)
        detail = _scene_text(self._scene, row.status or row.kind)
        detail.setDefaultTextColor(palette["muted"])
        detail.setPos(label_width - 120, y - 7)
        x = left + row.offset_seconds * scale
        width = max(5.0, row.duration_seconds * scale) if row.duration_seconds else 7.0
        rect = QtCore.QRectF(x, y - 7, width, 16)
        fill = palette.get(row.kind, palette["bar"])
        path = QtGui.QPainterPath()
        path.addRoundedRect(rect, 4, 4)
        item = self._scene.addPath(path, QtGui.QPen(palette["bar_border"]), QtGui.QBrush(fill))
        if item is not None and row.node_id:
            item.setData(0, row.node_id)
            item.setToolTip(row.node_id)
        duration = _format_seconds(row.duration_seconds)
        if duration:
            duration_text = _scene_text(self._scene, duration)
            duration_text.setDefaultTextColor(palette["muted"])
            duration_text.setPos(x + width + 6, y - 7)
        self._scene.addLine(
            0, y + row_height / 2 - 1, left + 920, y + row_height / 2 - 1, QtGui.QPen(palette["row"])
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

    def populate(
        self, graph: ProvenanceGraph, build_analysis: BuildAnalysis | None, *, dark: bool
    ) -> None:
        self.tree.clear()
        for event in timeline_tree(graph, build_analysis):
            self.tree.addTopLevelItem(self._tree_item(event))
        self.gantt.set_events(graph, build_analysis, dark=dark)
        self.tree.expandToDepth(1)
        for column in range(self.tree.columnCount()):
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


def _scene_text(scene: QtWidgets.QGraphicsScene, text: str) -> QtWidgets.QGraphicsTextItem:
    # QGraphicsScene.addText is typed as Optional in the PyQt5 stubs but never
    # returns None in practice; assert it so the panel stays ignore-free.
    item = scene.addText(text)
    assert item is not None
    return item


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

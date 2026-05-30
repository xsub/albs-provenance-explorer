# mypy: ignore-errors
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import sys

from PyQt5 import QtCore, QtGui, QtSvg, QtWidgets

from albs_graph.adapters.sbom import discover_build_sbom
from albs_graph.gui.inspect import (
    InspectorEdge,
    edge_inspector_view,
    inspector_view,
    raw_json,
)
from albs_graph.pipeline import RunSpec
from albs_graph.security.cve_feed import CveFeed
from albs_graph.security.live_feeds import fetch_cve_feed_or_none
from albs_graph.gui.hitmap import EdgeRegion, NodeRegion, edge_at, node_at
from albs_graph.gui.render import workbench_graph_rendering
from albs_graph.services import (
    AnalysisResult,
    AnalysisService,
    evidence_report_html,
    evidence_report_markdown,
    GraphLoadSpec,
    GraphQueries,
    GraphSlice,
    GraphSlices,
    WorkbenchSession,
    compare_builds,
    coverage_rows,
    dependency_rows,
    evidence_bundle,
    evidence_matrix_rows,
    filter_graph_layers,
    finding_drilldown_rows,
    findings_for_analysis,
    graph_layers,
    graph_query_presets,
    investigation_recipes,
    run_graph_query,
    security_rows,
    source_evidence_rows,
    timeline_gantt_rows,
    timeline_tree,
)
from albs_graph.services.universe import UniversePathRow, UniverseStore


RECIPE_COMBO_WIDTH = 136
RECIPE_POPUP_MIN_WIDTH = 460
BOTTOM_DOCK_MIN_HEIGHT = 96
BOTTOM_PAGE_MIN_HEIGHT = 0
GANTT_MIN_HEIGHT = 48
CLASSIC_ROOT_ENV = "ALBS_EXPLORER_CLASSIC_ROOT"
CLASSIC_TMP_ROOT = Path("/private/tmp/albs-provenance-workbench")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _build_id_from_path(path: Path) -> str | None:
    match = re.search(r"build[-_](\d+)", path.name)
    return match.group(1) if match else None


def _prepend_env_path(path: Path, existing: str) -> str:
    prefix = str(path)
    return f"{prefix}{os.pathsep}{existing}" if existing else prefix


class AnalysisSignals(QtCore.QObject):
    progress = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(object)
    failed = QtCore.pyqtSignal(str)


class AnalysisWorker(QtCore.QRunnable):
    def __init__(self, load_spec: GraphLoadSpec, run_spec: RunSpec) -> None:
        super().__init__()
        self.load_spec = load_spec
        self.run_spec = run_spec
        self.signals = AnalysisSignals()

    @QtCore.pyqtSlot()
    def run(self) -> None:
        try:
            result = AnalysisService().analyze(
                self.load_spec,
                self.run_spec,
                on_progress=self.signals.progress.emit,
            )
        except Exception as exc:
            self.signals.failed.emit(str(exc))
            return
        self.signals.finished.emit(result)


class GraphSvgWidget(QtSvg.QSvgWidget):
    nodeClicked = QtCore.pyqtSignal(str)
    edgeClicked = QtCore.pyqtSignal(int)

    def __init__(self) -> None:
        super().__init__()
        self._node_regions: tuple[NodeRegion, ...] = ()
        self._edge_regions: tuple[EdgeRegion, ...] = ()
        self.setMouseTracking(True)

    def set_regions(
        self, node_regions: tuple[NodeRegion, ...], edge_regions: tuple[EdgeRegion, ...]
    ) -> None:
        self._node_regions = node_regions
        self._edge_regions = edge_regions

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
        if event.button() == QtCore.Qt.LeftButton:
            node_id = self._node_id_at(event.pos())
            if node_id is not None:
                self.nodeClicked.emit(node_id)
                event.accept()
                return
            edge_index = self._edge_index_at(event.pos())
            if edge_index is not None:
                self.edgeClicked.emit(edge_index)
                event.accept()
                return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QtGui.QMouseEvent) -> None:
        cursor = (
            QtCore.Qt.PointingHandCursor
            if self._node_id_at(event.pos()) is not None
            or self._edge_index_at(event.pos()) is not None
            else QtCore.Qt.ArrowCursor
        )
        self.setCursor(cursor)
        super().mouseMoveEvent(event)

    def leaveEvent(self, event: QtCore.QEvent) -> None:
        self.unsetCursor()
        super().leaveEvent(event)

    def _node_id_at(self, point: QtCore.QPoint) -> str | None:
        if not self._node_regions:
            return None
        size = self.renderer().defaultSize()
        if not size.isValid() or self.width() <= 0 or self.height() <= 0:
            return None
        x = point.x() * size.width() / self.width()
        y = point.y() * size.height() / self.height()
        return node_at(self._node_regions, x, y)

    def _edge_index_at(self, point: QtCore.QPoint) -> int | None:
        if not self._edge_regions:
            return None
        size = self.renderer().defaultSize()
        if not size.isValid() or self.width() <= 0 or self.height() <= 0:
            return None
        x = point.x() * size.width() / self.width()
        y = point.y() * size.height() / self.height()
        return edge_at(self._edge_regions, x, y)


class TimelineGanttView(QtWidgets.QGraphicsView):
    nodeActivated = QtCore.pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self._scene = QtWidgets.QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QtGui.QPainter.Antialiasing, True)
        self.setDragMode(QtWidgets.QGraphicsView.ScrollHandDrag)
        self.setMinimumHeight(GANTT_MIN_HEIGHT)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Ignored)

    def set_events(self, graph, build_analysis, *, dark: bool) -> None:
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

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
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
            label = self._scene.addText(_format_seconds(seconds))
            label.setDefaultTextColor(palette["muted"])
            label.setPos(x - 18, 12)

    def _draw_gantt_row(
        self,
        palette: dict[str, QtGui.QColor],
        row,
        y: float,
        left: int,
        label_width: int,
        scale: float,
        row_height: int,
    ) -> None:
        text = "  " * row.depth + row.label
        label = self._scene.addText(text)
        label.setDefaultTextColor(palette["text"])
        label.setPos(8, y - 7)
        if row.node_id:
            label.setData(0, row.node_id)
        detail = self._scene.addText(row.status or row.kind)
        detail.setDefaultTextColor(palette["muted"])
        detail.setPos(label_width - 120, y - 7)
        x = left + row.offset_seconds * scale
        width = max(5.0, row.duration_seconds * scale) if row.duration_seconds else 7.0
        rect = QtCore.QRectF(x, y - 7, width, 16)
        fill = palette.get(row.kind, palette["bar"])
        path = QtGui.QPainterPath()
        path.addRoundedRect(rect, 4, 4)
        item = self._scene.addPath(
            path,
            QtGui.QPen(palette["bar_border"]),
            QtGui.QBrush(fill),
        )
        if row.node_id:
            item.setData(0, row.node_id)
            item.setToolTip(row.node_id)
        duration = _format_seconds(row.duration_seconds)
        if duration:
            duration_text = self._scene.addText(duration)
            duration_text.setDefaultTextColor(palette["muted"])
            duration_text.setPos(x + width + 6, y - 7)
        self._scene.addLine(0, y + row_height / 2 - 1, left + 920, y + row_height / 2 - 1, QtGui.QPen(palette["row"]))


class ConsoleProcessDialog(QtWidgets.QDialog):
    def __init__(
        self,
        *,
        title: str,
        program: str,
        arguments: list[str],
        cwd: Path,
        environment: QtCore.QProcessEnvironment,
        intro: str,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(1120, 720)
        self.exit_code: int | None = None
        self.exit_status: QtCore.QProcess.ExitStatus | None = None

        self.output = QtWidgets.QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.output.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard
        )

        self.ok_button = QtWidgets.QPushButton("OK")
        self.ok_button.setEnabled(False)
        self.ok_button.clicked.connect(self.accept)
        self.stop_button = QtWidgets.QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_process)

        buttons = QtWidgets.QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.stop_button)
        buttons.addWidget(self.ok_button)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.output)
        layout.addLayout(buttons)

        self.process = QtCore.QProcess(self)
        self.process.setWorkingDirectory(str(cwd))
        self.process.setProcessEnvironment(environment)
        self.process.setProcessChannelMode(QtCore.QProcess.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._read_output)
        self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(self._failed)

        self._append(intro.rstrip() + "\n\n")
        self.process.start(program, arguments)

    def stop_process(self) -> None:
        if self.process.state() == QtCore.QProcess.NotRunning:
            return
        self._append("\n[workbench] stopping subprocess...\n")
        self.process.terminate()
        if not self.process.waitForFinished(3000):
            self.process.kill()

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if self.process.state() != QtCore.QProcess.NotRunning:
            self.stop_process()
        event.accept()

    def _read_output(self) -> None:
        data = bytes(self.process.readAllStandardOutput()).decode(errors="replace")
        if data:
            self._append(data)

    def _failed(self, error: QtCore.QProcess.ProcessError) -> None:
        self._append(f"\n[workbench] subprocess error: {error}\n")
        self.stop_button.setEnabled(False)
        self.ok_button.setEnabled(True)

    def _finished(self, exit_code: int, exit_status: QtCore.QProcess.ExitStatus) -> None:
        self.exit_code = exit_code
        self.exit_status = exit_status
        status = "ok" if exit_code == 0 and exit_status == QtCore.QProcess.NormalExit else "failed"
        self._append(f"\n[workbench] subprocess finished: {status} (exit code {exit_code})\n")
        self.stop_button.setEnabled(False)
        self.ok_button.setEnabled(True)

    def _append(self, text: str) -> None:
        cursor = self.output.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()


class WorkbenchWindow(QtWidgets.QMainWindow):
    def __init__(
        self,
        *,
        initial_source: Path | None = None,
        initial_build_id: int | None = None,
        initial_build_sbom: Path | None = None,
        base_url: str = "https://build.almalinux.org",
    ) -> None:
        super().__init__()
        self.setWindowTitle("ALBS Provenance Investigation Workbench")
        self.resize(1500, 930)

        self.thread_pool = QtCore.QThreadPool.globalInstance()
        self._active_worker: AnalysisWorker | None = None
        self.universe_store: UniverseStore | None = None
        self.universe_focus: str | None = None
        self.universe_favourites: list[dict[str, str]] = []
        # M3: a report-time CVE feed for the Security panel's Potential CVEs
        # column, cached by the source string it was loaded from.
        self.cve_feed: CveFeed | None = None
        self._cve_feed_source: str | None = None
        self.result: AnalysisResult | None = None
        self.current_slice: GraphSlice | None = None
        self.findings = []
        self.pending_session: WorkbenchSession | None = None
        self.selected_node_id: str | None = None
        self.selected_edge_index: int | None = None
        self.current_svg = ""
        self.dark_mode = False
        self.base_url = base_url
        self.graph_scale = 1.0
        self.graph_fit_to_view = False
        self.svg_default_size = QtCore.QSize(900, 560)

        self.source_edit = QtWidgets.QLineEdit(str(initial_source or ""))
        self.build_id_edit = QtWidgets.QLineEdit(str(initial_build_id or ""))
        self.build_id_edit.setPlaceholderText("Enter build id")
        self.build_sbom_edit = QtWidgets.QLineEdit(str(initial_build_sbom or ""))
        self.build_sbom_edit.setPlaceholderText("Build SBOM")
        self.build_sbom_edit.setClearButtonEnabled(True)
        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(
            ["Trust Path", "Dependency Evidence", "Security Context", "Node Neighborhood"]
        )
        # Live errata source (D79/M3): off / http feed / host dnf. The combo's
        # userData is the RunSpec.errata_source value (""/"http"/"dnf").
        self.errata_combo = QtWidgets.QComboBox()
        self.errata_combo.addItem("Errata off", "")
        self.errata_combo.addItem("Errata: http", "http")
        self.errata_combo.addItem("Errata: dnf", "dnf")
        self.errata_feed_edit = QtWidgets.QLineEdit()
        self.errata_feed_edit.setPlaceholderText("errata feed file / URL")
        self.errata_feed_edit.setClearButtonEnabled(True)
        self.errata_feed_edit.setFixedWidth(180)
        # M3: CPE dictionary (verify candidates -> official CPE) feeds RunSpec;
        # the CVE feed is a report-time input to the Security panel.
        self.cpe_dict_edit = QtWidgets.QLineEdit()
        self.cpe_dict_edit.setPlaceholderText("CPE dict (verify)")
        self.cpe_dict_edit.setClearButtonEnabled(True)
        self.cpe_dict_edit.setFixedWidth(150)
        self.cve_feed_edit = QtWidgets.QLineEdit()
        self.cve_feed_edit.setPlaceholderText("CVE feed")
        self.cve_feed_edit.setClearButtonEnabled(True)
        self.cve_feed_edit.setFixedWidth(150)
        self.recipe_combo = QtWidgets.QComboBox()
        self.recipe_combo.addItem("Recipes")
        self.recipe_combo.setFixedWidth(RECIPE_COMBO_WIDTH)
        self.recipe_combo.setSizePolicy(
            QtWidgets.QSizePolicy.Fixed,
            QtWidgets.QSizePolicy.Fixed,
        )
        self.recipe_combo.view().setTextElideMode(QtCore.Qt.ElideNone)
        self.recipe_combo.view().setMinimumWidth(RECIPE_POPUP_MIN_WIDTH)
        self.layer_button = QtWidgets.QToolButton()
        self.layer_button.setText("Layers")
        self.layer_button.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        self.layer_menu = QtWidgets.QMenu(self.layer_button)
        self.layer_actions: dict[str, QtWidgets.QAction] = {}
        for layer in graph_layers():
            action = self.layer_menu.addAction(layer.label)
            action.setCheckable(True)
            action.setChecked(True)
            self.layer_actions[layer.code] = action
        self.layer_button.setMenu(self.layer_menu)
        self.graph_search_edit = QtWidgets.QLineEdit()
        self.graph_search_edit.setPlaceholderText("Search graph")
        self.graph_search_edit.setFixedWidth(160)
        self.include_tests = QtWidgets.QCheckBox("Tests")
        self.coverage_label = QtWidgets.QLabel("No graph loaded")
        self.progress_label = QtWidgets.QLabel("")

        self.artifact_header = QtWidgets.QLabel("Artifacts")
        self.artifact_filter = QtWidgets.QLineEdit()
        self.artifact_filter.setPlaceholderText("Filter artifacts")
        self.artifact_list = QtWidgets.QListWidget()
        self.artifact_list.setSpacing(2)
        self.slice_nodes = QtWidgets.QTableWidget(0, 3)
        self.slice_nodes.setHorizontalHeaderLabels(["Type", "Label", "Node id"])
        self.slice_nodes.horizontalHeader().setStretchLastSection(True)
        self.slice_nodes.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.slice_nodes.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.svg_widget = GraphSvgWidget()
        self.svg_widget.setMinimumSize(720, 520)
        self.svg_scroll = QtWidgets.QScrollArea()
        self.svg_scroll.setWidget(self.svg_widget)
        self.svg_scroll.setWidgetResizable(False)

        self.graph_title = QtWidgets.QLabel("No artifact selected")
        self.graph_title.setObjectName("GraphTitle")
        self.graph_meta = QtWidgets.QLabel("")
        self.graph_meta.setObjectName("GraphMeta")

        self.inspector_tabs = QtWidgets.QTabWidget()
        self.summary_table = QtWidgets.QTableWidget(0, 2)
        self.summary_table.setHorizontalHeaderLabels(["Field", "Value"])
        self.metadata_table = QtWidgets.QTableWidget(0, 2)
        self.metadata_table.setHorizontalHeaderLabels(["Key", "Value"])
        self.edges_table = QtWidgets.QTableWidget(0, 5)
        self.edges_table.setHorizontalHeaderLabels(["Dir", "Relation", "Other node", "Label", "Index"])
        self.raw_inspector = QtWidgets.QPlainTextEdit()
        self.raw_inspector.setReadOnly(True)
        for table in (self.summary_table, self.metadata_table, self.edges_table):
            table.horizontalHeader().setStretchLastSection(True)
            table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            table.setAlternatingRowColors(True)
        self.inspector_tabs.addTab(self.summary_table, "Summary")
        self.inspector_tabs.addTab(self.metadata_table, "Metadata")
        self.inspector_tabs.addTab(self.edges_table, "Edges")
        self.inspector_tabs.addTab(self.raw_inspector, "Raw")

        self.findings_table = QtWidgets.QTableWidget(0, 4)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Code", "Subject", "Detail"])
        self.findings_table.horizontalHeader().setStretchLastSection(True)
        self.findings_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.findings_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.coverage_table = QtWidgets.QTableWidget(0, 5)
        self.coverage_table.setHorizontalHeaderLabels(["Axis", "Covered", "Total", "Ratio", "Status"])
        self.coverage_table.horizontalHeader().setStretchLastSection(True)
        self.coverage_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.evidence_table = QtWidgets.QTableWidget(0, 15)
        self.evidence_table.setHorizontalHeaderLabels(
            [
                "Package",
                "Arch",
                "Version",
                "Release",
                "Provenance",
                "Security",
                "Build",
                "Source CAS",
                "Artifact CAS",
                "Signature",
                "Release",
                "SBOM",
                "Errata",
                "Tests",
                "Missing",
            ]
        )
        self.evidence_table.horizontalHeader().setStretchLastSection(True)
        self.evidence_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.evidence_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.evidence_table.setAlternatingRowColors(True)
        self.security_table = QtWidgets.QTableWidget(0, 9)
        self.security_table.setHorizontalHeaderLabels(
            [
                "Package",
                "Arch",
                "Identity",
                "CPE",
                "Candidates",
                "Errata",
                "Addressed CVEs",
                "Potential CVEs",
                "Caveats",
            ]
        )
        self.security_table.horizontalHeader().setStretchLastSection(True)
        self.security_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.security_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.security_table.setAlternatingRowColors(True)
        self.dependency_table = QtWidgets.QTableWidget(0, 11)
        self.dependency_table.setHorizontalHeaderLabels(
            [
                "Subject",
                "Coordinate",
                "Ecosystem",
                "Scope",
                "Linkage",
                "State",
                "Verdict",
                "Conflict",
                "Context",
                "Versions",
                "Evidence",
            ]
        )
        self.dependency_table.horizontalHeader().setStretchLastSection(True)
        self.dependency_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.dependency_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.dependency_table.setAlternatingRowColors(True)
        self.dep_scope_combo = QtWidgets.QComboBox()
        for label, facet in (
            ("All scopes", ""),
            ("Runtime", "runtime"),
            ("Build", "build"),
            ("Static", "static"),
            ("Test", "test"),
        ):
            self.dep_scope_combo.addItem(label, facet)
        self.dep_only_conflicts = QtWidgets.QCheckBox("Only conflicts")
        self.dep_only_unresolved = QtWidgets.QCheckBox("Only unresolved")
        self.dependency_panel = QtWidgets.QWidget()
        dependency_layout = QtWidgets.QVBoxLayout(self.dependency_panel)
        dependency_layout.setContentsMargins(0, 0, 0, 0)
        dependency_header = QtWidgets.QHBoxLayout()
        dependency_header.setContentsMargins(6, 4, 6, 4)
        dependency_header.addWidget(QtWidgets.QLabel("Scope"))
        dependency_header.addWidget(self.dep_scope_combo)
        dependency_header.addWidget(self.dep_only_conflicts)
        dependency_header.addWidget(self.dep_only_unresolved)
        dependency_header.addStretch(1)
        dependency_layout.addLayout(dependency_header)
        dependency_layout.addWidget(self.dependency_table)
        self.source_table = QtWidgets.QTableWidget(0, 4)
        self.source_table.setHorizontalHeaderLabels(["Category", "Label", "Node id", "Detail"])
        self.source_table.horizontalHeader().setStretchLastSection(True)
        self.source_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.source_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.source_table.setAlternatingRowColors(True)
        self.query_combo = QtWidgets.QComboBox()
        for preset in graph_query_presets():
            self.query_combo.addItem(preset.title, preset.code)
        self.query_run_button = QtWidgets.QPushButton("Run")
        self.query_table = QtWidgets.QTableWidget(0, 4)
        self.query_table.setHorizontalHeaderLabels(["Kind", "Label", "Node id", "Detail"])
        self.query_table.horizontalHeader().setStretchLastSection(True)
        self.query_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.query_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.query_table.setAlternatingRowColors(True)
        self.query_panel = QtWidgets.QWidget()
        query_layout = QtWidgets.QVBoxLayout(self.query_panel)
        query_layout.setContentsMargins(0, 0, 0, 0)
        query_header = QtWidgets.QHBoxLayout()
        query_header.setContentsMargins(6, 4, 6, 4)
        query_header.addWidget(self.query_combo, 1)
        query_header.addWidget(self.query_run_button)
        query_layout.addLayout(query_header)
        query_layout.addWidget(self.query_table)
        self.finding_detail_table = QtWidgets.QTableWidget(0, 4)
        self.finding_detail_table.setHorizontalHeaderLabels(["Kind", "Label", "Node id", "Detail"])
        self.finding_detail_table.horizontalHeader().setStretchLastSection(True)
        self.finding_detail_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.finding_detail_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.finding_detail_table.setAlternatingRowColors(True)
        self.timeline_table = QtWidgets.QTreeWidget()
        self.timeline_table.setHeaderLabels(
            ["Stage", "Status", "Duration", "Started", "Finished", "Graph node", "Detail"]
        )
        self.timeline_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.timeline_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.timeline_table.setAlternatingRowColors(True)
        self.timeline_view_combo = QtWidgets.QComboBox()
        self.timeline_view_combo.addItems(["Tree", "Gantt"])
        self.timeline_gantt = TimelineGanttView()
        self.timeline_stack = QtWidgets.QStackedWidget()
        self.timeline_stack.addWidget(self.timeline_table)
        self.timeline_stack.addWidget(self.timeline_gantt)
        self.timeline_panel = QtWidgets.QWidget()
        timeline_layout = QtWidgets.QVBoxLayout(self.timeline_panel)
        timeline_layout.setContentsMargins(0, 0, 0, 0)
        timeline_header = QtWidgets.QHBoxLayout()
        timeline_header.setContentsMargins(6, 4, 6, 4)
        timeline_header.addStretch(1)
        timeline_header.addWidget(self.timeline_view_combo)
        timeline_layout.addLayout(timeline_header)
        timeline_layout.addWidget(self.timeline_stack)
        self.compare_table = QtWidgets.QTableWidget(0, 6)
        self.compare_table.setHorizontalHeaderLabels(["Area", "Change", "Key", "Left", "Right", "Detail"])
        self.compare_table.horizontalHeader().setStretchLastSection(True)
        self.compare_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.compare_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(500)

        self.universe_panel = self._create_universe_panel()

        self._build_ui()
        self._connect_signals()
        self._apply_style()
        self._update_input_tooltips()

        if initial_build_id is not None or (initial_source is not None and initial_source.exists()):
            QtCore.QTimer.singleShot(50, self.run_analysis)

    def _build_ui(self) -> None:
        toolbar = QtWidgets.QToolBar("Workbench")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        open_action = QtWidgets.QAction(
            self.style().standardIcon(QtWidgets.QStyle.SP_DialogOpenButton),
            "Open",
            self,
        )
        open_action.triggered.connect(self.open_source)
        run_action = QtWidgets.QAction(
            self.style().standardIcon(QtWidgets.QStyle.SP_MediaPlay),
            "Analyze",
            self,
        )
        run_action.triggered.connect(self.run_analysis)
        export_action = QtWidgets.QAction(
            self.style().standardIcon(QtWidgets.QStyle.SP_DialogSaveButton),
            "Export SVG",
            self,
        )
        export_action.triggered.connect(self.export_svg)
        export_bundle_action = QtWidgets.QAction(
            self.style().standardIcon(QtWidgets.QStyle.SP_DriveFDIcon),
            "Export Bundle",
            self,
        )
        export_bundle_action.triggered.connect(self.export_bundle)
        export_html_action = QtWidgets.QAction("Export HTML", self)
        export_html_action.triggered.connect(self.export_html_report)
        export_markdown_action = QtWidgets.QAction("Export Markdown", self)
        export_markdown_action.triggered.connect(self.export_markdown_report)
        export_png_action = QtWidgets.QAction("Export PNG", self)
        export_png_action.triggered.connect(self.export_png)
        compare_action = QtWidgets.QAction("Compare", self)
        compare_action.triggered.connect(self.compare_with_source)
        build_sbom_action = QtWidgets.QAction("SBOM", self)
        build_sbom_action.setToolTip("Choose a build CycloneDX SBOM")
        build_sbom_action.triggered.connect(self.open_build_sbom)
        save_session_action = QtWidgets.QAction("Save Session", self)
        save_session_action.triggered.connect(self.save_session)
        load_session_action = QtWidgets.QAction("Load Session", self)
        load_session_action.triggered.connect(self.load_session)
        reload_program_action = QtWidgets.QAction("Reload Program", self)
        reload_program_action.triggered.connect(self.reload_program)
        exit_action = QtWidgets.QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        zoom_in_action = QtWidgets.QAction("Zoom In", self)
        zoom_in_action.triggered.connect(self.zoom_in_graph)
        zoom_out_action = QtWidgets.QAction("Zoom Out", self)
        zoom_out_action.triggered.connect(self.zoom_out_graph)
        fit_action = QtWidgets.QAction("Fit", self)
        fit_action.triggered.connect(self.fit_graph)
        reset_action = QtWidgets.QAction("Reset", self)
        reset_action.triggered.connect(self.reset_graph_zoom)

        self._configure_actions(
            open_action=open_action,
            run_action=run_action,
            save_session_action=save_session_action,
            load_session_action=load_session_action,
            reload_program_action=reload_program_action,
            exit_action=exit_action,
            zoom_in_action=zoom_in_action,
            zoom_out_action=zoom_out_action,
            fit_action=fit_action,
            reset_action=reset_action,
        )
        self._build_menu_bar(
            open_action=open_action,
            run_action=run_action,
            build_sbom_action=build_sbom_action,
            export_action=export_action,
            export_bundle_action=export_bundle_action,
            export_html_action=export_html_action,
            export_markdown_action=export_markdown_action,
            export_png_action=export_png_action,
            compare_action=compare_action,
            save_session_action=save_session_action,
            load_session_action=load_session_action,
            reload_program_action=reload_program_action,
            exit_action=exit_action,
            zoom_in_action=zoom_in_action,
            zoom_out_action=zoom_out_action,
            fit_action=fit_action,
            reset_action=reset_action,
        )

        toolbar.addWidget(QtWidgets.QLabel("Source"))
        self.source_edit.setFixedWidth(320)
        toolbar.addWidget(self.source_edit)
        toolbar.addAction(build_sbom_action)
        self.build_sbom_edit.setFixedWidth(240)
        toolbar.addWidget(self.build_sbom_edit)
        toolbar.addSeparator()
        toolbar.addWidget(QtWidgets.QLabel("Build id"))
        self.build_id_edit.setFixedWidth(100)
        toolbar.addWidget(self.build_id_edit)
        toolbar.addSeparator()
        toolbar.addWidget(QtWidgets.QLabel("Mode"))
        toolbar.addWidget(self.mode_combo)
        toolbar.addWidget(self.recipe_combo)
        toolbar.addWidget(self.layer_button)
        toolbar.addWidget(self.graph_search_edit)
        toolbar.addWidget(self.include_tests)
        toolbar.addSeparator()
        toolbar.addWidget(self.errata_combo)
        toolbar.addWidget(self.errata_feed_edit)
        toolbar.addWidget(self.cpe_dict_edit)
        toolbar.addWidget(self.cve_feed_edit)

        left = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.addWidget(self.artifact_header)
        left_layout.addWidget(self.artifact_filter)
        left_layout.addWidget(self.artifact_list)
        left_layout.addWidget(self.coverage_label)

        center = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        graph_panel = QtWidgets.QWidget()
        graph_layout = QtWidgets.QVBoxLayout(graph_panel)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        header = QtWidgets.QWidget()
        header_layout = QtWidgets.QHBoxLayout(header)
        header_layout.setContentsMargins(8, 6, 8, 6)
        header_layout.addWidget(self.graph_title, 1)
        header_layout.addWidget(self.graph_meta)
        graph_layout.addWidget(header)
        graph_layout.addWidget(self.svg_scroll)
        center.addWidget(graph_panel)
        center.addWidget(self.slice_nodes)
        center.setStretchFactor(0, 4)
        center.setStretchFactor(1, 1)

        right = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.setContentsMargins(8, 8, 8, 8)
        right_layout.addWidget(QtWidgets.QLabel("Inspector"))
        right_layout.addWidget(self.inspector_tabs)

        split = QtWidgets.QSplitter()
        split.addWidget(left)
        split.addWidget(center)
        split.addWidget(right)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 4)
        split.setStretchFactor(2, 2)
        self.setCentralWidget(split)

        bottom = QtWidgets.QTabWidget()
        bottom.setMinimumHeight(BOTTOM_DOCK_MIN_HEIGHT)
        bottom.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Ignored)
        bottom.addTab(self.findings_table, "Findings")
        bottom.addTab(self.coverage_table, "Coverage")
        bottom.addTab(self.evidence_table, "Evidence")
        bottom.addTab(self.security_table, "Security")
        bottom.addTab(self.dependency_panel, "Dependencies")
        bottom.addTab(self.source_table, "Source")
        bottom.addTab(self.query_panel, "Queries")
        bottom.addTab(self.finding_detail_table, "Finding Detail")
        bottom.addTab(self.timeline_panel, "Timeline")
        bottom.addTab(self.compare_table, "Compare")
        bottom.addTab(self.universe_panel, "Universe")
        bottom.addTab(self.log, "Log")
        self._relax_bottom_panel_minimums(bottom)
        dock = QtWidgets.QDockWidget("Investigation Output")
        dock.setMinimumHeight(BOTTOM_DOCK_MIN_HEIGHT)
        dock.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Ignored)
        dock.setWidget(bottom)
        dock.setAllowedAreas(QtCore.Qt.BottomDockWidgetArea)
        self.output_tabs = bottom
        self.output_dock = dock
        self.addDockWidget(QtCore.Qt.BottomDockWidgetArea, dock)
        self.statusBar().addWidget(self.progress_label)

    def _configure_actions(
        self,
        *,
        open_action: QtWidgets.QAction,
        run_action: QtWidgets.QAction,
        save_session_action: QtWidgets.QAction,
        load_session_action: QtWidgets.QAction,
        reload_program_action: QtWidgets.QAction,
        exit_action: QtWidgets.QAction,
        zoom_in_action: QtWidgets.QAction,
        zoom_out_action: QtWidgets.QAction,
        fit_action: QtWidgets.QAction,
        reset_action: QtWidgets.QAction,
    ) -> None:
        open_action.setShortcut(QtGui.QKeySequence.Open)
        run_action.setShortcut(QtGui.QKeySequence("Ctrl+R"))
        save_session_action.setShortcut(QtGui.QKeySequence.Save)
        load_session_action.setShortcut(QtGui.QKeySequence("Ctrl+L"))
        reload_program_action.setShortcut(QtGui.QKeySequence("Ctrl+Shift+R"))
        exit_action.setShortcut(QtGui.QKeySequence.Quit)
        zoom_in_action.setShortcut(QtGui.QKeySequence.ZoomIn)
        zoom_out_action.setShortcut(QtGui.QKeySequence.ZoomOut)
        fit_action.setShortcut(QtGui.QKeySequence("Ctrl+0"))
        reset_action.setShortcut(QtGui.QKeySequence("Ctrl+1"))

    def _build_menu_bar(
        self,
        *,
        open_action: QtWidgets.QAction,
        run_action: QtWidgets.QAction,
        build_sbom_action: QtWidgets.QAction,
        export_action: QtWidgets.QAction,
        export_bundle_action: QtWidgets.QAction,
        export_html_action: QtWidgets.QAction,
        export_markdown_action: QtWidgets.QAction,
        export_png_action: QtWidgets.QAction,
        compare_action: QtWidgets.QAction,
        save_session_action: QtWidgets.QAction,
        load_session_action: QtWidgets.QAction,
        reload_program_action: QtWidgets.QAction,
        exit_action: QtWidgets.QAction,
        zoom_in_action: QtWidgets.QAction,
        zoom_out_action: QtWidgets.QAction,
        fit_action: QtWidgets.QAction,
        reset_action: QtWidgets.QAction,
    ) -> None:
        file_menu = self.menuBar().addMenu("File")
        file_menu.addAction(open_action)
        file_menu.addAction(build_sbom_action)
        file_menu.addSeparator()
        file_menu.addAction(save_session_action)
        file_menu.addAction(load_session_action)
        export_menu = file_menu.addMenu("Export")
        export_menu.addAction(export_action)
        export_menu.addAction(export_png_action)
        export_menu.addAction(export_bundle_action)
        export_menu.addAction(export_html_action)
        export_menu.addAction(export_markdown_action)
        file_menu.addSeparator()
        file_menu.addAction(reload_program_action)
        file_menu.addAction(exit_action)

        run_menu = self.menuBar().addMenu("Run")
        run_menu.addAction(run_action)
        run_menu.addAction(compare_action)

        view_menu = self.menuBar().addMenu("View")
        view_menu.addAction(zoom_in_action)
        view_menu.addAction(zoom_out_action)
        view_menu.addAction(fit_action)
        view_menu.addAction(reset_action)

    def _relax_bottom_panel_minimums(self, bottom: QtWidgets.QTabWidget) -> None:
        for index in range(bottom.count()):
            page = bottom.widget(index)
            page.setMinimumHeight(BOTTOM_PAGE_MIN_HEIGHT)
            page.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Ignored)
        self.timeline_stack.setMinimumHeight(BOTTOM_PAGE_MIN_HEIGHT)
        self.timeline_panel.setMinimumHeight(BOTTOM_PAGE_MIN_HEIGHT)

    def _connect_signals(self) -> None:
        self.source_edit.textChanged.connect(lambda _text: self._update_input_tooltips())
        self.build_sbom_edit.textChanged.connect(lambda _text: self._update_input_tooltips())
        self.build_id_edit.textChanged.connect(lambda _text: self._update_input_tooltips())
        self.build_id_edit.returnPressed.connect(self.run_classic_build_pipeline)
        self.artifact_list.currentItemChanged.connect(self._artifact_changed)
        self.artifact_filter.textChanged.connect(self._filter_artifacts)
        self.mode_combo.currentTextChanged.connect(lambda _text: self.render_current_slice())
        self.include_tests.stateChanged.connect(lambda _state: self.render_current_slice())
        self.slice_nodes.itemSelectionChanged.connect(self._slice_node_changed)
        self.svg_widget.nodeClicked.connect(self._graph_node_clicked)
        self.svg_widget.edgeClicked.connect(self._graph_edge_clicked)
        self.findings_table.itemActivated.connect(self._finding_activated)
        self.findings_table.itemDoubleClicked.connect(self._finding_activated)
        self.edges_table.itemActivated.connect(self._edge_activated)
        self.edges_table.itemDoubleClicked.connect(self._edge_activated)
        self.timeline_table.itemActivated.connect(self._timeline_activated)
        self.timeline_table.itemDoubleClicked.connect(self._timeline_activated)
        self.timeline_gantt.nodeActivated.connect(
            lambda node_id: self._navigate_to_node(node_id, prefer_artifact=False)
        )
        self.timeline_view_combo.currentIndexChanged.connect(self.timeline_stack.setCurrentIndex)
        self.evidence_table.itemActivated.connect(self._evidence_activated)
        self.evidence_table.itemDoubleClicked.connect(self._evidence_activated)
        self.security_table.itemActivated.connect(self._security_activated)
        self.security_table.itemDoubleClicked.connect(self._security_activated)
        self.cve_feed_edit.editingFinished.connect(self._refresh_security_table)
        self.dependency_table.itemActivated.connect(self._dependency_activated)
        self.dependency_table.itemDoubleClicked.connect(self._dependency_activated)
        self.dep_scope_combo.currentIndexChanged.connect(lambda _index: self._populate_dependency_table())
        self.dep_only_conflicts.toggled.connect(lambda _checked: self._populate_dependency_table())
        self.dep_only_unresolved.toggled.connect(lambda _checked: self._populate_dependency_table())
        self.source_table.itemActivated.connect(self._source_activated)
        self.source_table.itemDoubleClicked.connect(self._source_activated)
        self.query_run_button.clicked.connect(self._run_selected_query)
        self.query_combo.activated.connect(lambda _index: self._run_selected_query())
        self.query_table.itemActivated.connect(self._query_activated)
        self.query_table.itemDoubleClicked.connect(self._query_activated)
        self.finding_detail_table.itemActivated.connect(self._query_activated)
        self.finding_detail_table.itemDoubleClicked.connect(self._query_activated)
        self.compare_table.itemActivated.connect(self._compare_activated)
        self.compare_table.itemDoubleClicked.connect(self._compare_activated)
        self.recipe_combo.activated.connect(self._recipe_activated)
        self.graph_search_edit.returnPressed.connect(self.search_current_graph)
        for action in self.layer_actions.values():
            action.triggered.connect(lambda _checked: self.render_current_slice())

    def _update_input_tooltips(self) -> None:
        source = self.source_edit.text().strip()
        build_sbom = self.build_sbom_edit.text().strip()
        build_id = self.build_id_edit.text().strip()
        self.source_edit.setToolTip(source)
        self.build_sbom_edit.setToolTip(build_sbom)
        self.build_id_edit.setToolTip(f"Build id: {build_id}" if build_id else "")

    def _apply_style(self) -> None:
        self.dark_mode = self._is_dark_palette()
        if self.dark_mode:
            window = "#20242A"
            panel = "#262B32"
            panel_alt = "#303640"
            border = "#434B56"
            text = "#EEF2F6"
            muted = "#AAB5C2"
            selection = "#2F6FED"
            selection_text = "#FFFFFF"
            alternate = "#22272E"
        else:
            window = "#F6F7F9"
            panel = "#FFFFFF"
            panel_alt = "#EEF2F6"
            border = "#D8DDE6"
            text = "#263238"
            muted = "#52616F"
            selection = "#DCEBFF"
            selection_text = "#17212B"
            alternate = "#F7F9FC"
        self.setStyleSheet(
            f"""
            QMainWindow, QWidget {{
                background: {window};
                color: {text};
            }}
            QToolBar {{
                spacing: 8px;
                padding: 6px;
                background: {panel};
                border-bottom: 1px solid {border};
            }}
            QDockWidget {{
                color: {text};
                titlebar-close-icon: none;
                titlebar-normal-icon: none;
            }}
            QDockWidget::title {{
                background: {panel_alt};
                color: {text};
                padding: 4px;
            }}
            QListWidget, QTreeWidget, QTableWidget, QPlainTextEdit, QScrollArea, QLineEdit, QComboBox {{
                background: {panel};
                color: {text};
                border: 1px solid {border};
                selection-background-color: {selection};
                selection-color: {selection_text};
            }}
            QListWidget::item {{
                padding: 3px 6px;
            }}
            QTreeWidget, QTableWidget {{
                alternate-background-color: {alternate};
            }}
            QPlainTextEdit {{
                font-family: Menlo, Monaco, Consolas, monospace;
                font-size: 12px;
            }}
            QLabel {{
                color: {text};
            }}
            QLabel#GraphTitle {{
                font-size: 14px;
                font-weight: 700;
            }}
            QLabel#GraphMeta {{
                color: {muted};
                font-size: 12px;
            }}
            QHeaderView::section {{
                background: {panel_alt};
                color: {text};
                padding: 5px;
                border: 0;
                border-right: 1px solid {border};
            }}
            QTableCornerButton::section {{
                background: {panel_alt};
                border: 0;
            }}
            QTabWidget::pane {{
                border: 1px solid {border};
                background: {panel};
            }}
            QTabBar::tab {{
                background: {panel_alt};
                color: {muted};
                padding: 5px 14px;
                border: 1px solid {border};
            }}
            QTabBar::tab:selected {{
                background: {selection};
                color: {selection_text};
            }}
            QSplitter::handle {{
                background: {border};
            }}
            """
        )

    def _is_dark_palette(self) -> bool:
        return QtWidgets.QApplication.palette().color(QtGui.QPalette.Window).lightness() < 128

    def open_source(self) -> None:
        path, _filter = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Open ALBS build metadata",
            self._dialog_start_dir(),
            "JSON files (*.json);;All files (*)",
        )
        if path:
            self.source_edit.setText(path)
            self.build_id_edit.clear()

    def open_build_sbom(self) -> None:
        path, _filter = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Open build CycloneDX SBOM",
            self._dialog_start_dir(),
            "JSON files (*.json);;All files (*)",
        )
        if path:
            self.build_sbom_edit.setText(path)

    def _dialog_start_dir(self) -> str:
        source = self.source_edit.text().strip()
        if source:
            path = Path(source).expanduser()
            if path.exists():
                return str(path.parent if path.is_file() else path)
        sbom = self.build_sbom_edit.text().strip()
        if sbom:
            path = Path(sbom).expanduser()
            if path.exists():
                return str(path.parent if path.is_file() else path)
        return str(Path.cwd())

    def run_analysis(self) -> None:
        try:
            load_spec = self._load_spec()
            run_spec = self._run_spec(load_spec)
        except ValueError as exc:
            self._show_error(str(exc))
            return

        self.progress_label.setText("Analyzing...")
        self.log.clear()
        self._log("Starting analysis")
        if run_spec.build_sbom is not None:
            self._log(f"Using build SBOM {run_spec.build_sbom}")
        worker = AnalysisWorker(load_spec, run_spec)
        worker.signals.progress.connect(self._log)
        worker.signals.failed.connect(self._analysis_failed)
        worker.signals.finished.connect(self._analysis_finished)
        self._active_worker = worker  # keep a handle so closeEvent can detach it
        self.thread_pool.start(worker)

    def run_classic_build_pipeline(self) -> None:
        build_id = self.build_id_edit.text().strip()
        if not build_id:
            return
        if not build_id.isdigit():
            self._show_error("Build id must be a number.")
            return
        try:
            request = self._classic_build_request(build_id)
        except ValueError as exc:
            self._show_error(str(exc))
            return

        dialog = ConsoleProcessDialog(
            title=f"Classic ALBS provenance run for build {build_id}",
            program="/bin/bash",
            arguments=[str(request["script"])],
            cwd=request["classic_root"],
            environment=request["environment"],
            intro=str(request["intro"]),
            parent=self,
        )
        dialog.exec_()

        cache = request["cache"]
        if dialog.exit_code != 0:
            self._show_error("Classic ALBS provenance run did not finish successfully.")
            return
        if not cache.exists():
            self._show_error(f"Classic run finished but did not create {cache}.")
            return

        self.source_edit.setText(str(cache))
        self.build_id_edit.clear()
        sbom = request["sbom_file"]
        if sbom is not None and sbom.exists():
            self.build_sbom_edit.setText(str(sbom))
        self._log(f"Opening classic CLI cache {cache}")
        self.run_analysis()

    def _classic_build_request(self, build_id: str) -> dict[str, object]:
        classic_root = self._classic_root()
        script = classic_root / "example--full.sh"
        if not script.exists():
            raise ValueError(f"Classic example runner does not exist: {script}")

        run_root = CLASSIC_TMP_ROOT / f"build-{build_id}"
        live_dir = run_root / "live"
        out_dir = run_root / "demo"
        cache = live_dir / f"build-{build_id}.albs.json"
        live_dir.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(parents=True, exist_ok=True)

        sbom_file = self._classic_sbom_file(build_id, classic_root)
        environment = QtCore.QProcessEnvironment.systemEnvironment()
        environment.insert("BUILD_ID", build_id)
        environment.insert("LIVE_DIR", str(live_dir))
        environment.insert("OUT_DIR", str(out_dir))
        environment.insert("CACHE", str(cache))
        environment.insert("PYTHONPATH", _prepend_env_path(classic_root, environment.value("PYTHONPATH")))
        environment.insert("PATH", _prepend_env_path(Path(sys.executable).parent, environment.value("PATH")))
        if sbom_file is not None:
            environment.insert("SBOM_FILE", str(sbom_file))

        intro = "\n".join(
            [
                f"[workbench] classic root: {classic_root}",
                f"[workbench] output root: {run_root}",
                f"[workbench] cache target: {cache}",
                f"[workbench] command: BUILD_ID={build_id} /bin/bash {script}",
            ]
        )
        return {
            "classic_root": classic_root,
            "script": script,
            "environment": environment,
            "cache": cache,
            "sbom_file": sbom_file,
            "intro": intro,
        }

    def _classic_root(self) -> Path:
        configured = os.environ.get(CLASSIC_ROOT_ENV)
        candidates = []
        if configured:
            candidates.append(Path(configured).expanduser())
        candidates.append(_repo_root())
        candidates.append(_repo_root().parent / "albs-provenance-explorer")
        for candidate in candidates:
            if (candidate / "example--full.sh").exists():
                return candidate
        raise ValueError(
            "Could not find the classic max checkout. Set "
            f"{CLASSIC_ROOT_ENV} to the albs-provenance-explorer path."
        )

    def _classic_sbom_file(self, build_id: str, classic_root: Path) -> Path | None:
        for candidate in (
            _repo_root() / "examples" / f"build-{build_id}.cyclonedx.json",
            classic_root / "examples" / f"build-{build_id}.cyclonedx.json",
        ):
            if candidate.exists():
                return candidate
        return None

    def _load_spec(self) -> GraphLoadSpec:
        build_id = self.build_id_edit.text().strip()
        source = self.source_edit.text().strip()
        if build_id:
            return GraphLoadSpec(build_id=int(build_id), base_url=self.base_url)
        if not source:
            raise ValueError("Choose a source JSON or enter a build id.")
        path = Path(source).expanduser()
        if not path.exists():
            raise ValueError(f"Source JSON does not exist: {path}")
        return GraphLoadSpec(source=path)

    def _run_spec(self, load_spec: GraphLoadSpec) -> RunSpec:
        self._autofill_build_sbom(load_spec)
        build_sbom_path: Path | None = None
        build_sbom = self.build_sbom_edit.text().strip()
        if build_sbom:
            build_sbom_path = Path(build_sbom).expanduser()
            if not build_sbom_path.exists():
                raise ValueError(f"Build SBOM JSON does not exist: {build_sbom_path}")
            expected_build_id = self._build_id_for_spec(load_spec)
            sbom_build_id = _build_id_from_path(build_sbom_path)
            if expected_build_id and sbom_build_id and expected_build_id != sbom_build_id:
                raise ValueError(
                    f"Build SBOM appears to be for build {sbom_build_id}, "
                    f"but the current source is build {expected_build_id}."
                )
        return RunSpec(
            build_sbom=build_sbom_path,
            **self._errata_run_kwargs(),
            **self._verify_cpe_run_kwargs(),
        )

    def _verify_cpe_run_kwargs(self) -> dict[str, object]:
        """RunSpec CPE-verify kwargs from the toolbar field (D101/M3).

        An NVD-style CPE dictionary resolves a candidate to an official CPE, so
        the Security panel's CVE-feed matching has a real vendor/product to
        match (a vendor-asserted SBOM CPE rarely lines up with NVD tokens). A
        file wins; otherwise the value is treated as a live dictionary URL.
        """

        value = self.cpe_dict_edit.text().strip()
        if not value:
            return {}
        candidate = Path(value).expanduser()
        if candidate.exists():
            return {"verify_cpe": candidate}
        return {"verify_cpe_url": value}

    def _errata_run_kwargs(self) -> dict[str, object]:
        """RunSpec errata kwargs from the toolbar combo + feed field (D79/M3).

        "" -> no errata source (not_checked stays the default). "dnf" queries
        the host updateinfo (degrades to not-consulted off an AlmaLinux box).
        "http" reads an offline feed file when the field is an existing path,
        else treats it as a live feed URL; an empty field still selects http
        but simply degrades to not-consulted (logged), never crashes.
        """

        source = str(self.errata_combo.currentData() or "")
        if not source:
            return {}
        kwargs: dict[str, object] = {"errata_source": source}
        if source == "http":
            feed = self.errata_feed_edit.text().strip()
            if feed:
                candidate = Path(feed).expanduser()
                if candidate.exists():
                    kwargs["errata_feed"] = candidate
                else:
                    kwargs["errata_url"] = feed
        return kwargs

    def _autofill_build_sbom(self, load_spec: GraphLoadSpec) -> None:
        if self.build_sbom_edit.text().strip():
            return
        candidate = self._suggest_build_sbom(load_spec)
        if candidate is not None:
            self.build_sbom_edit.setText(str(candidate))

    def _suggest_build_sbom(self, load_spec: GraphLoadSpec) -> Path | None:
        # Reuse the shared CLI convention (discover_build_sbom, D78) rather than
        # a parallel re-implementation: it checks the source's directory and its
        # parent, then examples/, for build-<id>.cyclonedx.json.
        build_id = self._build_id_for_spec(load_spec)
        if build_id is None:
            return None
        return discover_build_sbom(
            int(build_id),
            cache_path=load_spec.source,
            search_dirs=(_repo_root() / "examples",),
        )

    def _build_id_for_spec(self, load_spec: GraphLoadSpec) -> str | None:
        if load_spec.build_id is not None:
            return str(load_spec.build_id)
        if load_spec.source is not None:
            return _build_id_from_path(load_spec.source)
        return None

    def _analysis_finished(self, result: AnalysisResult) -> None:
        self.result = result
        self.progress_label.setText("Analysis complete")
        self._log("Analysis complete")
        for warning in result.warnings:
            self._log(warning.message)
        self._populate_artifacts()
        self._populate_findings()
        self._populate_coverage_table()
        self._populate_evidence_table()
        self._populate_security_table()
        self._populate_dependency_table()
        self._populate_source_table()
        self._run_selected_query()
        self._populate_timeline()
        self._populate_recipes()
        self._update_coverage()
        if self.pending_session is not None:
            self._apply_session(self.pending_session)
            self.pending_session = None
        elif self.artifact_list.count():
            self.artifact_list.setCurrentRow(0)

    def _analysis_failed(self, message: str) -> None:
        self.progress_label.setText("Analysis failed")
        self._log(f"ERROR: {message}")
        self._show_error(message)

    def _populate_artifacts(self) -> None:
        self.artifact_list.clear()
        assert self.result is not None
        artifacts = GraphQueries(self.result.graph).artifacts()
        self.artifact_header.setText(f"Artifacts ({len(artifacts)})")
        for summary in artifacts:
            name = summary.metadata.get("name") or summary.label
            arch = summary.metadata.get("arch") or "?"
            item = QtWidgets.QListWidgetItem(f"{name}  [{arch}]")
            item.setData(QtCore.Qt.UserRole, summary.id)
            item.setData(QtCore.Qt.UserRole + 1, f"{name} {arch} {summary.id}".casefold())
            item.setToolTip(summary.id)
            self.artifact_list.addItem(item)

    def _filter_artifacts(self, text: str) -> None:
        needle = text.casefold().strip()
        visible = 0
        first_visible: QtWidgets.QListWidgetItem | None = None
        for index in range(self.artifact_list.count()):
            item = self.artifact_list.item(index)
            haystack = str(item.data(QtCore.Qt.UserRole + 1))
            hidden = bool(needle) and needle not in haystack
            item.setHidden(hidden)
            if not hidden:
                visible += 1
                if first_visible is None:
                    first_visible = item
        total = self.artifact_list.count()
        self.artifact_header.setText(f"Artifacts ({visible}/{total})" if needle else f"Artifacts ({total})")
        current = self.artifact_list.currentItem()
        if current is not None and current.isHidden() and first_visible is not None:
            self.artifact_list.setCurrentItem(first_visible)

    def _populate_findings(self) -> None:
        assert self.result is not None
        self.findings = findings_for_analysis(
            self.result.graph, self.result.coverage, self.result.reconciliation
        )
        self.findings_table.setRowCount(len(self.findings))
        for row, finding in enumerate(self.findings):
            values = [
                finding.severity,
                finding.code,
                finding.subject or "",
                finding.detail or "",
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, finding.subject or "")
                self.findings_table.setItem(row, column, item)
        self.findings_table.resizeColumnsToContents()

    def _populate_coverage_table(self) -> None:
        assert self.result is not None
        rows = coverage_rows(self.result.coverage)
        self.coverage_table.setRowCount(len(rows))
        for row, coverage in enumerate(rows):
            values = [
                coverage.axis,
                str(coverage.covered),
                str(coverage.total),
                f"{coverage.ratio:.2f}",
                coverage.status,
            ]
            for column, value in enumerate(values):
                self.coverage_table.setItem(row, column, QtWidgets.QTableWidgetItem(value))
        self.coverage_table.resizeColumnsToContents()

    def _populate_evidence_table(self) -> None:
        assert self.result is not None
        rows = evidence_matrix_rows(self.result.graph)
        self.evidence_table.setRowCount(len(rows))
        for row, evidence in enumerate(rows):
            values = [
                evidence.package,
                evidence.arch,
                evidence.version,
                evidence.release,
                evidence.provenance,
                evidence.security_context,
                evidence.build_task,
                evidence.source_cas,
                evidence.artifact_cas,
                evidence.signature,
                evidence.release_context,
                evidence.sbom,
                evidence.errata,
                evidence.tests,
                evidence.missing,
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, evidence.node_id)
                if value == "missing" or value == "incomplete":
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#F08A8A")))
                elif value == "ok" or value == "complete":
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#87D37C")))
                self.evidence_table.setItem(row, column, item)
        self.evidence_table.resizeColumnsToContents()

    def _ensure_cve_feed(self) -> CveFeed | None:
        """Load (and cache) the report-time CVE feed from the toolbar field.

        A path is read as a file; anything else is treated as a live feed URL
        (cached on disk via HttpCache). Cached by source string so it loads once;
        crash-safe -- a bad file/URL logs and degrades to no feed.
        """

        source = self.cve_feed_edit.text().strip()
        if not source:
            self.cve_feed = None
            self._cve_feed_source = None
            return None
        if source == self._cve_feed_source:
            return self.cve_feed
        candidate = Path(source).expanduser()
        try:
            feed = fetch_cve_feed_or_none(
                source_file=str(candidate) if candidate.exists() else None,
                url=None if candidate.exists() else source,
                on_progress=self._log,
            )
        except Exception as exc:  # noqa: BLE001 -- a bad feed must not crash the panel
            self._log(f"CVE feed unavailable ({exc}); continuing without it")
            feed = None
        self.cve_feed = feed
        self._cve_feed_source = source
        return feed

    def _refresh_security_table(self) -> None:
        # The CVE feed is a report-time input, so editing it re-renders the
        # Security panel without re-running the whole analysis.
        if self.result is not None:
            self._populate_security_table()

    def _populate_security_table(self) -> None:
        assert self.result is not None
        rows = security_rows(self.result.graph, cve_feed=self._ensure_cve_feed())
        self.security_table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            values = [
                entry.package,
                entry.arch,
                entry.identity,
                entry.cpe,
                entry.candidates,
                entry.errata,
                entry.addressed_cves,
                entry.potential_cves,
                entry.caveats,
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, entry.node_id)
                self._tint_security_cell(item, column, value)
                self.security_table.setItem(row, column, item)
        self.security_table.resizeColumnsToContents()

    def _tint_security_cell(self, item: QtWidgets.QTableWidgetItem, column: int, value: str) -> None:
        good = QtGui.QBrush(QtGui.QColor("#87D37C"))
        warn = QtGui.QBrush(QtGui.QColor("#E6B85C"))
        bad = QtGui.QBrush(QtGui.QColor("#F08A8A"))
        if column == 2:  # Identity
            if value == "verified":
                item.setForeground(good)
            elif value in ("vendor-asserted", "candidate", "ambiguous"):
                item.setForeground(warn)
            elif value == "none":
                item.setForeground(bad)
        elif column == 5:  # Errata three-state
            if value == "clean":
                item.setForeground(good)
            elif value == "advisory":
                item.setForeground(warn)
            elif value == "missing":
                item.setForeground(bad)
        elif column in (6, 7) and value not in ("", "-"):  # CVEs present
            item.setForeground(warn)
        elif column == 8 and "backport" in value:  # backport caveat
            item.setForeground(warn)

    def _security_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.UserRole)
        if node_id:
            self._navigate_to_node(str(node_id), prefer_artifact=True)

    def _populate_dependency_table(self) -> None:
        if self.result is None:
            return
        facet = str(self.dep_scope_combo.currentData() or "")
        rows = dependency_rows(
            self.result.graph,
            scope_facets={facet} if facet else None,
            only_conflicts=self.dep_only_conflicts.isChecked(),
            only_unresolved=self.dep_only_unresolved.isChecked(),
        )
        self.dependency_table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            values = [
                entry.subject,
                entry.coordinate,
                entry.ecosystem,
                entry.scope,
                entry.linkage,
                entry.resolution_state,
                entry.verdict,
                entry.conflict_kinds,
                entry.context_issue,
                entry.versions,
                entry.evidence,
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, entry.subject_id)
                self._tint_dependency_cell(item, column, value)
                self.dependency_table.setItem(row, column, item)
        self.dependency_table.resizeColumnsToContents()

    def _tint_dependency_cell(self, item: QtWidgets.QTableWidgetItem, column: int, value: str) -> None:
        good = QtGui.QBrush(QtGui.QColor("#87D37C"))
        warn = QtGui.QBrush(QtGui.QColor("#E6B85C"))
        bad = QtGui.QBrush(QtGui.QColor("#F08A8A"))
        if column == 6:  # Verdict
            if value in ("consensus", "compatible"):
                item.setForeground(good)
            elif value == "conflict":
                item.setForeground(bad)
            elif value == "insufficient_evidence":
                item.setForeground(warn)
        elif column == 7 and value not in ("", "-"):  # Conflict kinds present
            item.setForeground(bad)
        elif column == 8 and value not in ("", "-"):  # Context issue present
            item.setForeground(warn)

    def _dependency_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.UserRole)
        if node_id:
            self._navigate_to_node(str(node_id), prefer_artifact=True)

    # --- M4 Universe workbench ----------------------------------------------

    def _create_universe_panel(self) -> QtWidgets.QWidget:
        """Build the Universe tab: open a SQLite store, search, walk, find paths.

        Independent of the loaded build -- it queries a separate universe store
        (D74) through the read-only ``UniverseStore`` facade, so the recursive
        CTEs run in SQLite and never load the whole arch graph into memory.
        """

        panel = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(panel)
        layout.setContentsMargins(6, 4, 6, 4)

        open_row = QtWidgets.QHBoxLayout()
        open_button = QtWidgets.QPushButton("Open Universe")
        open_button.clicked.connect(lambda _checked=False: self.open_universe())
        self.universe_path_label = QtWidgets.QLabel("No universe store open")
        self.universe_path_label.setObjectName("GraphMeta")
        open_row.addWidget(open_button)
        open_row.addWidget(self.universe_path_label, 1)
        self.universe_fav_combo = QtWidgets.QComboBox()
        self.universe_fav_combo.addItem("Favourites", "")
        self.universe_fav_combo.activated.connect(self._universe_apply_favourite)
        save_fav_button = QtWidgets.QPushButton("Save Favourite")
        save_fav_button.clicked.connect(self._universe_save_favourite)
        open_row.addWidget(self.universe_fav_combo)
        open_row.addWidget(save_fav_button)
        layout.addLayout(open_row)

        search_row = QtWidgets.QHBoxLayout()
        self.universe_search_edit = QtWidgets.QLineEdit()
        self.universe_search_edit.setPlaceholderText("Search packages / capabilities")
        self.universe_search_edit.returnPressed.connect(self._universe_search)
        search_button = QtWidgets.QPushButton("Search")
        search_button.clicked.connect(self._universe_search)
        search_row.addWidget(self.universe_search_edit, 1)
        search_row.addWidget(search_button)
        layout.addLayout(search_row)

        body = QtWidgets.QSplitter()
        self.universe_packages_table = QtWidgets.QTableWidget(0, 3)
        self.universe_packages_table.setHorizontalHeaderLabels(["Type", "Label", "Node id"])
        self.universe_packages_table.horizontalHeader().setStretchLastSection(True)
        self.universe_packages_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.universe_packages_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.universe_packages_table.setAlternatingRowColors(True)
        self.universe_packages_table.itemSelectionChanged.connect(self._universe_focus_changed)
        body.addWidget(self.universe_packages_table)

        right = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.universe_focus_label = QtWidgets.QLabel("Focus: -")
        right_layout.addWidget(self.universe_focus_label)
        walk_row = QtWidgets.QHBoxLayout()
        for label, kind in (("Dependencies", "dependencies"), ("Dependents", "dependents"),
                            ("Reachable", "reachable")):
            button = QtWidgets.QPushButton(label)
            button.clicked.connect(lambda _checked=False, k=kind: self._universe_traverse(k))
            walk_row.addWidget(button)
        right_layout.addLayout(walk_row)
        path_row = QtWidgets.QHBoxLayout()
        self.universe_target_edit = QtWidgets.QLineEdit()
        self.universe_target_edit.setPlaceholderText("Target package for paths")
        self.universe_target_edit.returnPressed.connect(self._universe_find_paths)
        paths_button = QtWidgets.QPushButton("Find Paths")
        paths_button.clicked.connect(self._universe_find_paths)
        path_row.addWidget(self.universe_target_edit, 1)
        path_row.addWidget(paths_button)
        right_layout.addLayout(path_row)
        self.universe_results_table = QtWidgets.QTableWidget(0, 3)
        self.universe_results_table.setHorizontalHeaderLabels(["Kind", "Result", "Detail"])
        self.universe_results_table.horizontalHeader().setStretchLastSection(True)
        self.universe_results_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.universe_results_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.universe_results_table.setAlternatingRowColors(True)
        right_layout.addWidget(self.universe_results_table)
        body.addWidget(right)
        body.setStretchFactor(0, 1)
        body.setStretchFactor(1, 2)
        layout.addWidget(body)
        return panel

    def open_universe(self, path: str | None = None) -> None:
        if not path:
            path, _filter = QtWidgets.QFileDialog.getOpenFileName(
                self,
                "Open universe SQLite store",
                str(Path.cwd()),
                "SQLite store (*.db *.sqlite *.sqlite3);;All files (*)",
            )
        if not path:
            return
        try:
            store = UniverseStore(path)
            version = store.schema_version
        except Exception as exc:  # noqa: BLE001 -- a bad file must not crash the app
            self._show_error(f"Could not open universe store: {exc}")
            return
        self.universe_store = store
        self.universe_focus = None
        self.universe_focus_label.setText("Focus: -")
        self.universe_results_table.setRowCount(0)
        self.universe_path_label.setText(f"{path} (schema v{version})")
        self._log(f"Opened universe store {path} (schema v{version})")
        self._universe_search()

    def _universe_search(self) -> None:
        if self.universe_store is None:
            self._show_error("Open a universe store first.")
            return
        needle = self.universe_search_edit.text().strip()
        rows = self.universe_store.search(needle, limit=300)
        self.universe_packages_table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            for column, value in enumerate((entry.node_type, entry.label, entry.node_id)):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, entry.label)
                self.universe_packages_table.setItem(row, column, item)
        self.universe_packages_table.resizeColumnsToContents()
        self._log(f"Universe search '{needle}': {len(rows)} matches")

    def _universe_focus_changed(self) -> None:
        item = self.universe_packages_table.currentItem()
        if item is None:
            return
        row = item.row()
        label_item = self.universe_packages_table.item(row, 1)
        if label_item is not None:
            self.universe_focus = label_item.text()
            self.universe_focus_label.setText(f"Focus: {self.universe_focus}")

    def _universe_traverse(self, kind: str) -> None:
        if self.universe_store is None or not self.universe_focus:
            self._show_error("Open a store and select a focus package first.")
            return
        focus = self.universe_focus
        if kind == "dependencies":
            results = self.universe_store.dependencies(focus)
        elif kind == "dependents":
            results = self.universe_store.dependents(focus)
        else:
            results = self.universe_store.reachable(focus)
        self.universe_results_table.setRowCount(len(results))
        for row, label in enumerate(results):
            for column, value in enumerate((kind, label, "")):
                item = QtWidgets.QTableWidgetItem(value)
                self.universe_results_table.setItem(row, column, item)
        self.universe_results_table.resizeColumnsToContents()
        self._log(f"Universe {kind} of {focus}: {len(results)}")

    def _universe_find_paths(self) -> None:
        if self.universe_store is None or not self.universe_focus:
            self._show_error("Open a store and select a focus package first.")
            return
        target = self.universe_target_edit.text().strip()
        if not target:
            self._show_error("Enter a target package for the path search.")
            return
        rows: list[UniversePathRow] = self.universe_store.paths(self.universe_focus, target)
        self.universe_results_table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            values = ("path", entry.display, f"{entry.hops} hops")
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                self.universe_results_table.setItem(row, column, item)
        self.universe_results_table.resizeColumnsToContents()
        self._log(f"Universe paths {self.universe_focus} -> {target}: {len(rows)}")

    def _universe_save_favourite(self) -> None:
        if self.universe_store is None:
            self._show_error("Open a universe store first.")
            return
        favourite = {
            "store": str(self.universe_store.db_path),
            "search": self.universe_search_edit.text().strip(),
            "focus": self.universe_focus or "",
            "target": self.universe_target_edit.text().strip(),
        }
        label = favourite["focus"] or favourite["search"] or favourite["store"]
        if favourite["target"]:
            label = f"{label} -> {favourite['target']}"
        self.universe_favourites.append(favourite)
        self.universe_fav_combo.addItem(label, str(len(self.universe_favourites) - 1))
        self._log(f"Saved universe favourite: {label}")

    def _universe_apply_favourite(self, index: int) -> None:
        data = self.universe_fav_combo.itemData(index)
        if data is None or str(data) == "":
            return
        favourite = self.universe_favourites[int(data)]
        if self.universe_store is None or str(self.universe_store.db_path) != favourite["store"]:
            self.open_universe(favourite["store"])
        self.universe_search_edit.setText(favourite["search"])
        self.universe_target_edit.setText(favourite["target"])
        self._universe_search()
        if favourite["focus"]:
            self.universe_focus = favourite["focus"]
            self.universe_focus_label.setText(f"Focus: {favourite['focus']}")

    def _populate_source_table(self, subject_id: str | None = None) -> None:
        if self.result is None:
            return
        rows = source_evidence_rows(self.result.graph, subject_id or self._current_subject_id())
        self._populate_query_like_table(self.source_table, rows)

    def _run_selected_query(self) -> None:
        if self.result is None:
            return
        code = self.query_combo.currentData()
        rows = run_graph_query(
            self.result.graph,
            str(code or "coverage_gaps"),
            subject_id=self._current_subject_id(),
        )
        self._populate_query_like_table(self.query_table, rows)

    def _populate_finding_detail(self, finding) -> None:
        if self.result is None:
            return
        rows = finding_drilldown_rows(self.result.graph, finding)
        self._populate_query_like_table(self.finding_detail_table, rows)

    def _populate_query_like_table(self, table: QtWidgets.QTableWidget, rows) -> None:
        table.setRowCount(len(rows))
        for row, item_data in enumerate(rows):
            values = [
                item_data.category if hasattr(item_data, "category") else item_data.kind,
                item_data.label,
                item_data.node_id,
                item_data.detail,
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(str(value))
                item.setData(QtCore.Qt.UserRole, item_data.node_id)
                table.setItem(row, column, item)
        table.resizeColumnsToContents()

    def _current_subject_id(self) -> str | None:
        current = self.artifact_list.currentItem()
        if current is not None:
            return str(current.data(QtCore.Qt.UserRole))
        return self.selected_node_id

    def _populate_timeline(self) -> None:
        assert self.result is not None
        self.timeline_table.clear()
        for event in timeline_tree(self.result.graph, self.result.build_analysis):
            self.timeline_table.addTopLevelItem(self._timeline_item(event))
        self.timeline_gantt.set_events(
            self.result.graph,
            self.result.build_analysis,
            dark=self.dark_mode,
        )
        self.timeline_table.expandToDepth(1)
        for column in range(self.timeline_table.columnCount()):
            self.timeline_table.resizeColumnToContents(column)

    def _timeline_item(self, event) -> QtWidgets.QTreeWidgetItem:
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
        item.setData(0, QtCore.Qt.UserRole, event.node_id)
        for child in event.children:
            item.addChild(self._timeline_item(child))
        return item

    def _populate_recipes(self) -> None:
        assert self.result is not None
        self.recipe_combo.blockSignals(True)
        self.recipe_combo.clear()
        self.recipe_combo.addItem("Recipes")
        for recipe in investigation_recipes(self.result.graph, self.result.coverage, self.findings):
            self.recipe_combo.addItem(recipe.title, recipe.to_dict())
        self._resize_recipe_popup()
        self.recipe_combo.blockSignals(False)

    def _resize_recipe_popup(self) -> None:
        metrics = QtGui.QFontMetrics(self.recipe_combo.font())
        widest_item = max(
            (
                metrics.horizontalAdvance(self.recipe_combo.itemText(index))
                for index in range(self.recipe_combo.count())
            ),
            default=0,
        )
        self.recipe_combo.view().setMinimumWidth(max(RECIPE_POPUP_MIN_WIDTH, widest_item + 72))

    def _update_coverage(self) -> None:
        assert self.result is not None
        parts = [
            f"{axis.name}: {axis.covered}/{axis.total}"
            for axis in self.result.coverage.axes()
        ]
        self.coverage_label.setText("\n".join(parts))

    def _artifact_changed(self, current: QtWidgets.QListWidgetItem | None) -> None:
        if current is None:
            return
        self.selected_node_id = str(current.data(QtCore.Qt.UserRole))
        self.render_current_slice()

    def render_current_slice(self) -> None:
        if self.result is None:
            return
        current = self.artifact_list.currentItem()
        if current is None:
            return
        subject_id = current.data(QtCore.Qt.UserRole)
        slices = GraphSlices(self.result.graph)
        try:
            mode = self.mode_combo.currentText()
            if mode == "Dependency Evidence":
                graph_slice = slices.dependency_evidence(subject_id)
            elif mode == "Security Context":
                graph_slice = slices.security_context(subject_id)
            elif mode == "Node Neighborhood":
                focus_id = (
                    self.selected_node_id
                    if self.selected_node_id in self.result.graph.nodes
                    else subject_id
                )
                graph_slice = slices.node_neighborhood(focus_id)
            else:
                graph_slice = slices.trust_path(
                    subject_id,
                    include_tests=self.include_tests.isChecked(),
                )
            graph_slice = self._apply_layer_filter(graph_slice)
        except Exception as exc:
            self._show_error(str(exc))
            return
        self.current_slice = graph_slice
        self.selected_node_id = graph_slice.focus or subject_id
        self.selected_edge_index = None
        self.graph_fit_to_view = False
        self.graph_scale = 1.0
        self._update_graph_header(graph_slice, subject_id)
        self._render_current_svg()
        self._populate_slice_nodes(graph_slice)
        self._populate_source_table(subject_id)
        self._run_selected_query()
        self._show_node(self.selected_node_id, render_graph=False)

    def _apply_layer_filter(self, graph_slice: GraphSlice) -> GraphSlice:
        enabled = {
            code for code, action in self.layer_actions.items() if action.isChecked()
        }
        filtered = filter_graph_layers(
            graph_slice.graph,
            enabled,
            always_nodes={node_id for node_id in (graph_slice.focus,) if node_id},
        )
        if filtered is graph_slice.graph:
            return graph_slice
        return GraphSlice(
            name=graph_slice.name,
            graph=filtered,
            focus=graph_slice.focus,
            metadata=graph_slice.metadata | {"layers": sorted(enabled)},
        )

    def _update_graph_header(self, graph_slice: GraphSlice, subject_id: str) -> None:
        assert self.result is not None
        focus_id = graph_slice.focus or subject_id
        node = self.result.graph.nodes.get(focus_id)
        title = node.label if node is not None else focus_id
        self.graph_title.setText(f"{self.mode_combo.currentText()}: {title}")
        self.graph_meta.setText(f"{len(graph_slice.graph.nodes)} nodes / {len(graph_slice.graph.edges)} edges")

    def _render_current_svg(self) -> None:
        if self.current_slice is None:
            return
        rendering = workbench_graph_rendering(
            self.current_slice.graph,
            dark=self.dark_mode,
            selected_node_id=self.selected_node_id,
            selected_edge_index=self.selected_edge_index,
        )
        self.current_svg = rendering.svg
        self._load_svg(self.current_svg, rendering.node_regions, rendering.edge_regions)

    def _load_svg(
        self,
        svg: str,
        node_regions: tuple[NodeRegion, ...],
        edge_regions: tuple[EdgeRegion, ...],
    ) -> None:
        self.svg_widget.load(QtCore.QByteArray(svg.encode("utf-8")))
        self.svg_widget.set_regions(node_regions, edge_regions)
        renderer = self.svg_widget.renderer()
        size = renderer.defaultSize()
        if not size.isValid() or size.width() <= 0 or size.height() <= 0:
            size = QtCore.QSize(900, 560)
        self.svg_default_size = size
        target = self._graph_target_size(size)
        self.svg_widget.setFixedSize(target)

    def _graph_target_size(self, size: QtCore.QSize) -> QtCore.QSize:
        viewport = self.svg_scroll.viewport().size()
        if self.graph_fit_to_view:
            scale = min(
                viewport.width() / max(1, size.width()),
                viewport.height() / max(1, size.height()),
            )
            self.graph_scale = max(0.15, min(2.5, scale))
        elif self.graph_scale == 1.0:
            if size.width() < viewport.width() and size.height() < viewport.height():
                self.graph_scale = min(1.35, viewport.width() / max(1, size.width()))
            elif size.width() <= viewport.width() * 1.4:
                self.graph_scale = max(0.8, min(1.0, viewport.width() / max(1, size.width())))
        return QtCore.QSize(
            max(720, int(size.width() * self.graph_scale)),
            max(520, int(size.height() * self.graph_scale)),
        )

    def _resize_current_graph(self) -> None:
        self.svg_widget.setFixedSize(self._graph_target_size(self.svg_default_size))

    def zoom_in_graph(self) -> None:
        self.graph_fit_to_view = False
        self.graph_scale = min(4.0, self.graph_scale * 1.2)
        self._resize_current_graph()

    def zoom_out_graph(self) -> None:
        self.graph_fit_to_view = False
        self.graph_scale = max(0.2, self.graph_scale / 1.2)
        self._resize_current_graph()

    def fit_graph(self) -> None:
        self.graph_fit_to_view = True
        self._resize_current_graph()

    def reset_graph_zoom(self) -> None:
        self.graph_fit_to_view = False
        self.graph_scale = 1.0
        self._resize_current_graph()

    def search_current_graph(self) -> None:
        text = self.graph_search_edit.text().strip()
        if not text:
            return
        if self.current_slice is not None:
            matches = GraphQueries(self.current_slice.graph).find_nodes(text, limit=1)
            if matches:
                self._show_node(matches[0].id)
                return
        if self.result is not None:
            matches = GraphQueries(self.result.graph).find_nodes(text, limit=1)
            if matches:
                self._navigate_to_node(matches[0].id, prefer_artifact=True)
                return
        self._log(f"No graph match for {text}")

    def _populate_slice_nodes(self, graph_slice: GraphSlice) -> None:
        rows = sorted(
            graph_slice.graph.nodes.values(),
            key=lambda node: (str(node.type), node.label, node.id),
        )
        self.slice_nodes.setRowCount(len(rows))
        for row, node in enumerate(rows):
            values = [str(node.type), node.label, node.id]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, node.id)
                self.slice_nodes.setItem(row, column, item)
        self.slice_nodes.resizeColumnsToContents()

    def _slice_node_changed(self) -> None:
        selected = self.slice_nodes.selectedItems()
        if not selected:
            return
        node_id = selected[0].data(QtCore.Qt.UserRole)
        if node_id:
            self._show_node(str(node_id))

    def _graph_node_clicked(self, node_id: str) -> None:
        self._show_node(node_id)

    def _graph_edge_clicked(self, edge_index: int) -> None:
        self._show_edge(edge_index, from_slice=True)

    def _finding_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        row = item.row()
        if 0 <= row < len(self.findings):
            self._populate_finding_detail(self.findings[row])
        subject = item.data(QtCore.Qt.UserRole)
        if subject:
            self._navigate_to_node(str(subject), prefer_artifact=True)

    def _edge_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        edge_index = item.data(QtCore.Qt.UserRole)
        if edge_index is not None:
            self._show_edge(int(edge_index), from_slice=False)

    def _timeline_activated(self, item: QtWidgets.QTreeWidgetItem, _column: int = 0) -> None:
        node_id = item.data(0, QtCore.Qt.UserRole)
        if node_id:
            self._navigate_to_node(str(node_id), prefer_artifact=False)

    def _evidence_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.UserRole)
        if node_id:
            self._navigate_to_node(str(node_id), prefer_artifact=True)

    def _source_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.UserRole)
        if node_id:
            self._navigate_to_node(str(node_id), prefer_artifact=False)

    def _query_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.UserRole)
        if node_id:
            self._navigate_to_node(str(node_id), prefer_artifact=True)

    def _recipe_activated(self, index: int) -> None:
        if index <= 0:
            return
        recipe = self.recipe_combo.itemData(index)
        if not isinstance(recipe, dict):
            return
        mode = str(recipe.get("mode") or "Trust Path")
        mode_index = self.mode_combo.findText(mode)
        if mode_index >= 0:
            self.mode_combo.setCurrentIndex(mode_index)
        subject = recipe.get("subject")
        if subject:
            self._navigate_to_node(str(subject), prefer_artifact=True)
        else:
            self.render_current_slice()
        self.recipe_combo.setCurrentIndex(0)

    def _compare_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.UserRole)
        if node_id:
            self._navigate_to_node(str(node_id), prefer_artifact=True)

    def _show_node(self, node_id: str, *, render_graph: bool = True) -> None:
        if self.result is None:
            return
        try:
            view = inspector_view(self.result.graph, node_id)
        except ValueError:
            if self.current_slice is None:
                return
            view = inspector_view(self.current_slice.graph, node_id)
        self._populate_key_value_table(self.summary_table, view.summary)
        self._populate_key_value_table(self.metadata_table, view.metadata)
        self._populate_edges_table(view.incoming + view.outgoing)
        self.raw_inspector.setPlainText(raw_json(view))
        self._select_slice_node(node_id)
        previous_edge = self.selected_edge_index
        self.selected_edge_index = None
        if self.current_slice is not None and node_id in self.current_slice.graph.nodes:
            previous = self.selected_node_id
            self.selected_node_id = node_id
            if render_graph and (previous != node_id or previous_edge is not None):
                self._render_current_svg()

    def _show_edge(self, edge_index: int, *, from_slice: bool) -> None:
        graph = self.current_slice.graph if from_slice and self.current_slice is not None else None
        if graph is None:
            if self.result is None:
                return
            graph = self.result.graph
        try:
            view = edge_inspector_view(graph, edge_index)
        except ValueError:
            return
        self._populate_key_value_table(self.summary_table, view.summary)
        self._populate_key_value_table(self.metadata_table, view.metadata)
        self._populate_edges_table([])
        self.raw_inspector.setPlainText(raw_json(view))
        if from_slice:
            self.selected_edge_index = edge_index
            self.selected_node_id = None
            self.slice_nodes.clearSelection()
            self._render_current_svg()

    def _select_slice_node(self, node_id: str) -> None:
        for row in range(self.slice_nodes.rowCount()):
            item = self.slice_nodes.item(row, 0)
            if item is not None and item.data(QtCore.Qt.UserRole) == node_id:
                self.slice_nodes.blockSignals(True)
                self.slice_nodes.selectRow(row)
                self.slice_nodes.blockSignals(False)
                return

    def _navigate_to_node(self, node_id: str, *, prefer_artifact: bool) -> None:
        if self.result is None or node_id not in self.result.graph.nodes:
            return
        if prefer_artifact and self._select_artifact(node_id):
            return
        if self.current_slice is not None and node_id in self.current_slice.graph.nodes:
            self._show_node(node_id)
            return
        self.selected_node_id = node_id
        mode_index = self.mode_combo.findText("Node Neighborhood")
        if mode_index >= 0:
            if self.mode_combo.currentIndex() == mode_index:
                self.render_current_slice()
            else:
                self.mode_combo.setCurrentIndex(mode_index)
        else:
            self.render_current_slice()

    def _select_artifact(self, node_id: str) -> bool:
        for row in range(self.artifact_list.count()):
            item = self.artifact_list.item(row)
            if item.data(QtCore.Qt.UserRole) == node_id:
                if self.artifact_list.currentItem() is item:
                    self.render_current_slice()
                else:
                    self.artifact_list.setCurrentItem(item)
                return True
        return False

    def _populate_key_value_table(
        self, table: QtWidgets.QTableWidget, rows: list[tuple[str, str]]
    ) -> None:
        table.setRowCount(len(rows))
        for row, (key, value) in enumerate(rows):
            table.setItem(row, 0, QtWidgets.QTableWidgetItem(key))
            table.setItem(row, 1, QtWidgets.QTableWidgetItem(value))
        table.resizeColumnsToContents()

    def _populate_edges_table(self, edges: list[InspectorEdge]) -> None:
        self.edges_table.setRowCount(len(edges))
        for row, edge in enumerate(edges):
            values = [
                edge.direction,
                edge.relation,
                edge.other_id,
                edge.other_label,
                str(edge.index),
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, edge.index)
                self.edges_table.setItem(row, column, item)
        self.edges_table.resizeColumnsToContents()

    def export_svg(self) -> None:
        if not self.current_svg:
            self._show_error("No rendered graph slice to export.")
            return
        path, _filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export current graph slice",
            "trust-slice.svg",
            "SVG files (*.svg);;All files (*)",
        )
        if not path:
            return
        Path(path).write_text(self.current_svg, encoding="utf-8")
        self._log(f"Exported SVG to {path}")

    def export_bundle(self) -> None:
        if self.result is None:
            self._show_error("No analysis result to export.")
            return
        path, _filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export investigation evidence bundle",
            "investigation-bundle.json",
            "JSON files (*.json);;All files (*)",
        )
        if not path:
            return
        data = self._current_bundle()
        Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._log(f"Exported evidence bundle to {path}")

    def _current_bundle(self) -> dict:
        assert self.result is not None
        return evidence_bundle(
            graph=self.result.graph,
            graph_slice=self.current_slice,
            coverage=self.result.coverage,
            findings=self.findings,
            selected_node_id=self.selected_node_id,
            selected_edge_index=self.selected_edge_index,
            selected_edge_graph=(
                self.current_slice.graph
                if self.selected_edge_index is not None and self.current_slice is not None
                else None
            ),
            svg=self.current_svg,
            session=self._current_session(),
            build_analysis=self.result.build_analysis,
        )

    def export_html_report(self) -> None:
        if self.result is None:
            self._show_error("No analysis result to export.")
            return
        path, _filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export investigation HTML report",
            "investigation-report.html",
            "HTML files (*.html);;All files (*)",
        )
        if not path:
            return
        Path(path).write_text(evidence_report_html(self._current_bundle()), encoding="utf-8")
        self._log(f"Exported HTML report to {path}")

    def export_markdown_report(self) -> None:
        if self.result is None:
            self._show_error("No analysis result to export.")
            return
        path, _filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export investigation Markdown report",
            "investigation-report.md",
            "Markdown files (*.md);;All files (*)",
        )
        if not path:
            return
        Path(path).write_text(evidence_report_markdown(self._current_bundle()), encoding="utf-8")
        self._log(f"Exported Markdown report to {path}")

    def export_png(self) -> None:
        if not self.current_svg:
            self._show_error("No rendered graph slice to export.")
            return
        path, _filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export current graph slice as PNG",
            "trust-slice.png",
            "PNG files (*.png);;All files (*)",
        )
        if not path:
            return
        renderer = QtSvg.QSvgRenderer(QtCore.QByteArray(self.current_svg.encode("utf-8")))
        size = renderer.defaultSize()
        if not size.isValid() or size.isEmpty():
            size = self.svg_default_size
        image = QtGui.QImage(size, QtGui.QImage.Format_ARGB32)
        image.fill(QtCore.Qt.white)
        painter = QtGui.QPainter(image)
        try:
            renderer.render(painter)
        finally:
            painter.end()
        if image.save(path, "PNG"):
            self._log(f"Exported PNG to {path}")
        else:
            self._show_error(f"Could not write PNG to {path}")

    def compare_with_source(self) -> None:
        if self.result is None:
            self._show_error("Run analysis before comparing.")
            return
        path, _filter = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Compare with ALBS build metadata",
            str(Path.cwd()),
            "JSON files (*.json);;All files (*)",
        )
        if not path:
            return
        try:
            other = AnalysisService().analyze(GraphLoadSpec(source=Path(path)), RunSpec())
        except Exception as exc:
            self._show_error(str(exc))
            return
        deltas = compare_builds(
            self.result.graph,
            other.graph,
            left_build_analysis=self.result.build_analysis,
            right_build_analysis=other.build_analysis,
        )
        self.compare_table.setRowCount(len(deltas))
        for row, delta in enumerate(deltas):
            values = [delta.area, delta.change, delta.key, delta.left, delta.right, delta.detail]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, delta.left_node_id or delta.right_node_id or "")
                self.compare_table.setItem(row, column, item)
        self.compare_table.resizeColumnsToContents()
        self._log(f"Compared current graph with {path}: {len(deltas)} build deltas")

    def save_session(self) -> None:
        path, _filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save workbench session",
            "investigation-session.json",
            "JSON files (*.json);;All files (*)",
        )
        if not path:
            return
        self._current_session().save(Path(path))
        self._log(f"Saved session to {path}")

    def load_session(self) -> None:
        path, _filter = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Load workbench session",
            str(Path.cwd()),
            "JSON files (*.json);;All files (*)",
        )
        if not path:
            return
        session = WorkbenchSession.load(Path(path))
        self.pending_session = session
        self.source_edit.setText(session.source)
        self.build_id_edit.setText(session.build_id)
        self.build_sbom_edit.setText(session.build_sbom)
        self.include_tests.setChecked(session.include_tests)
        self.artifact_filter.setText(session.artifact_filter)
        self._set_errata_source(session.errata_source)
        self.errata_feed_edit.setText(session.errata_feed)
        self.cpe_dict_edit.setText(session.verify_cpe)
        self.cve_feed_edit.setText(session.cve_feed)
        self._set_dep_scope(session.dep_scope)
        self.dep_only_conflicts.setChecked(session.dep_only_conflicts)
        self.dep_only_unresolved.setChecked(session.dep_only_unresolved)
        self._restore_universe_session(session)
        self.run_analysis()

    def _set_dep_scope(self, value: str) -> None:
        index = self.dep_scope_combo.findData(value or "")
        self.dep_scope_combo.setCurrentIndex(max(index, 0))

    def _restore_universe_session(self, session: WorkbenchSession) -> None:
        self.universe_favourites = [dict(fav) for fav in session.universe_favourites]
        self.universe_fav_combo.clear()
        self.universe_fav_combo.addItem("Favourites", "")
        for index, fav in enumerate(self.universe_favourites):
            label = fav.get("focus") or fav.get("search") or fav.get("store") or "favourite"
            if fav.get("target"):
                label = f"{label} -> {fav['target']}"
            self.universe_fav_combo.addItem(label, str(index))
        if session.universe_store and Path(session.universe_store).exists():
            self.open_universe(session.universe_store)

    def _current_session(self) -> WorkbenchSession:
        current = self.artifact_list.currentItem()
        return WorkbenchSession(
            source=self.source_edit.text(),
            build_id=self.build_id_edit.text(),
            build_sbom=self.build_sbom_edit.text(),
            mode=self.mode_combo.currentText(),
            include_tests=self.include_tests.isChecked(),
            artifact_filter=self.artifact_filter.text(),
            errata_source=str(self.errata_combo.currentData() or ""),
            errata_feed=self.errata_feed_edit.text(),
            verify_cpe=self.cpe_dict_edit.text(),
            cve_feed=self.cve_feed_edit.text(),
            dep_scope=str(self.dep_scope_combo.currentData() or ""),
            dep_only_conflicts=self.dep_only_conflicts.isChecked(),
            dep_only_unresolved=self.dep_only_unresolved.isChecked(),
            universe_store=(
                str(self.universe_store.db_path) if self.universe_store is not None else ""
            ),
            universe_favourites=tuple(self.universe_favourites),
            selected_artifact_id=(
                str(current.data(QtCore.Qt.UserRole)) if current is not None else None
            ),
            selected_node_id=self.selected_node_id,
            selected_edge_index=self.selected_edge_index,
        )

    def _set_errata_source(self, value: str) -> None:
        index = self.errata_combo.findData(value or "")
        if index < 0:
            index = self.errata_combo.findData("")
        self.errata_combo.setCurrentIndex(max(index, 0))

    def _apply_session(self, session: WorkbenchSession) -> None:
        self.build_sbom_edit.setText(session.build_sbom)
        mode_index = self.mode_combo.findText(session.mode)
        if mode_index >= 0:
            self.mode_combo.setCurrentIndex(mode_index)
        self.include_tests.setChecked(session.include_tests)
        self.artifact_filter.setText(session.artifact_filter)
        self._set_errata_source(session.errata_source)
        self.errata_feed_edit.setText(session.errata_feed)
        self.cpe_dict_edit.setText(session.verify_cpe)
        self.cve_feed_edit.setText(session.cve_feed)
        if session.selected_artifact_id and self._select_artifact(session.selected_artifact_id):
            if session.selected_node_id:
                self._navigate_to_node(session.selected_node_id, prefer_artifact=False)
            elif session.selected_edge_index is not None:
                self._show_edge(session.selected_edge_index, from_slice=True)
            return
        if self.artifact_list.count():
            self.artifact_list.setCurrentRow(0)

    def _log(self, message: str) -> None:
        self.log.appendPlainText(message)

    def _show_error(self, message: str) -> None:
        QtWidgets.QMessageBox.warning(self, "Workbench", message)

    def reload_program(self) -> None:
        self._log("Reloading workbench process")
        started = QtCore.QProcess.startDetached(sys.executable, sys.argv)
        if not started:
            self._show_error("Could not start a replacement workbench process.")
            return
        self.close()

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        # A running analysis worker cannot be interrupted mid-fetch; detach its
        # signals so a late emit does not target the half-destroyed window, then
        # drop queued work. We do not block the close on a network fetch.
        if self._active_worker is not None:
            for sig in (
                self._active_worker.signals.progress,
                self._active_worker.signals.finished,
                self._active_worker.signals.failed,
            ):
                try:
                    sig.disconnect()
                except (TypeError, RuntimeError):
                    pass
        self.thread_pool.clear()
        self.thread_pool.waitForDone(100)
        event.accept()


def run(
    *,
    source: Path | None = None,
    build_id: int | None = None,
    build_sbom: Path | None = None,
    base_url: str = "https://build.almalinux.org",
) -> int:
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    app.setApplicationName("ALBS Provenance Investigation Workbench")
    signal.signal(signal.SIGINT, lambda _signum, _frame: app.quit())
    signal_timer = QtCore.QTimer()
    signal_timer.timeout.connect(lambda: None)
    signal_timer.start(200)
    window = WorkbenchWindow(
        initial_source=source,
        initial_build_id=build_id,
        initial_build_sbom=build_sbom,
        base_url=base_url,
    )
    window._signal_timer = signal_timer
    window.show()
    return int(app.exec_())


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

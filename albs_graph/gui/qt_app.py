# mypy: ignore-errors
from __future__ import annotations

import json
from pathlib import Path
import sys

from PyQt5 import QtCore, QtGui, QtSvg, QtWidgets

from albs_graph.gui.inspect import (
    InspectorEdge,
    edge_inspector_view,
    inspector_view,
    raw_json,
)
from albs_graph.pipeline import RunSpec
from albs_graph.gui.hitmap import EdgeRegion, NodeRegion, edge_at, node_at
from albs_graph.gui.render import workbench_graph_rendering
from albs_graph.services import (
    AnalysisResult,
    AnalysisService,
    compare_artifacts,
    evidence_report_html,
    GraphLoadSpec,
    GraphQueries,
    GraphSlice,
    GraphSlices,
    WorkbenchSession,
    coverage_rows,
    evidence_bundle,
    findings_for_analysis,
    investigation_recipes,
    timeline_tree,
)


RECIPE_COMBO_WIDTH = 136
RECIPE_POPUP_MIN_WIDTH = 460


class AnalysisSignals(QtCore.QObject):
    progress = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(object)
    failed = QtCore.pyqtSignal(str)


class AnalysisWorker(QtCore.QRunnable):
    def __init__(self, load_spec: GraphLoadSpec) -> None:
        super().__init__()
        self.load_spec = load_spec
        self.signals = AnalysisSignals()

    @QtCore.pyqtSlot()
    def run(self) -> None:
        try:
            result = AnalysisService().analyze(
                self.load_spec,
                RunSpec(),
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


class WorkbenchWindow(QtWidgets.QMainWindow):
    def __init__(
        self,
        *,
        initial_source: Path | None = None,
        initial_build_id: int | None = None,
        base_url: str = "https://build.almalinux.org",
    ) -> None:
        super().__init__()
        self.setWindowTitle("ALBS Provenance Investigation Workbench")
        self.resize(1500, 930)

        self.thread_pool = QtCore.QThreadPool.globalInstance()
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
        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(
            ["Trust Path", "Dependency Evidence", "Security Context", "Node Neighborhood"]
        )
        self.recipe_combo = QtWidgets.QComboBox()
        self.recipe_combo.addItem("Recipes")
        self.recipe_combo.setFixedWidth(RECIPE_COMBO_WIDTH)
        self.recipe_combo.setSizePolicy(
            QtWidgets.QSizePolicy.Fixed,
            QtWidgets.QSizePolicy.Fixed,
        )
        self.recipe_combo.view().setTextElideMode(QtCore.Qt.ElideNone)
        self.recipe_combo.view().setMinimumWidth(RECIPE_POPUP_MIN_WIDTH)
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
        self.timeline_table = QtWidgets.QTreeWidget()
        self.timeline_table.setHeaderLabels(
            ["Stage", "Status", "Duration", "Started", "Finished", "Graph node", "Detail"]
        )
        self.timeline_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.timeline_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.timeline_table.setAlternatingRowColors(True)
        self.compare_table = QtWidgets.QTableWidget(0, 5)
        self.compare_table.setHorizontalHeaderLabels(["Change", "Key", "Left", "Right", "Detail"])
        self.compare_table.horizontalHeader().setStretchLastSection(True)
        self.compare_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.compare_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(500)

        self._build_ui()
        self._connect_signals()
        self._apply_style()

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
        compare_action = QtWidgets.QAction("Compare", self)
        compare_action.triggered.connect(self.compare_with_source)
        save_session_action = QtWidgets.QAction("Save Session", self)
        save_session_action.triggered.connect(self.save_session)
        load_session_action = QtWidgets.QAction("Load Session", self)
        load_session_action.triggered.connect(self.load_session)
        zoom_in_action = QtWidgets.QAction("Zoom In", self)
        zoom_in_action.triggered.connect(self.zoom_in_graph)
        zoom_out_action = QtWidgets.QAction("Zoom Out", self)
        zoom_out_action.triggered.connect(self.zoom_out_graph)
        fit_action = QtWidgets.QAction("Fit", self)
        fit_action.triggered.connect(self.fit_graph)
        reset_action = QtWidgets.QAction("Reset", self)
        reset_action.triggered.connect(self.reset_graph_zoom)

        toolbar.addAction(open_action)
        toolbar.addAction(run_action)
        toolbar.addAction(export_action)
        toolbar.addAction(export_bundle_action)
        toolbar.addAction(export_html_action)
        toolbar.addAction(compare_action)
        toolbar.addAction(save_session_action)
        toolbar.addAction(load_session_action)
        toolbar.addSeparator()
        toolbar.addWidget(QtWidgets.QLabel("Source"))
        self.source_edit.setMinimumWidth(360)
        toolbar.addWidget(self.source_edit)
        toolbar.addSeparator()
        toolbar.addWidget(QtWidgets.QLabel("Build id"))
        self.build_id_edit.setFixedWidth(100)
        toolbar.addWidget(self.build_id_edit)
        toolbar.addSeparator()
        toolbar.addWidget(QtWidgets.QLabel("Mode"))
        toolbar.addWidget(self.mode_combo)
        toolbar.addWidget(self.recipe_combo)
        toolbar.addAction(zoom_in_action)
        toolbar.addAction(zoom_out_action)
        toolbar.addAction(fit_action)
        toolbar.addAction(reset_action)
        toolbar.addWidget(self.graph_search_edit)
        toolbar.addWidget(self.include_tests)

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
        bottom.addTab(self.findings_table, "Findings")
        bottom.addTab(self.coverage_table, "Coverage")
        bottom.addTab(self.timeline_table, "Timeline")
        bottom.addTab(self.compare_table, "Compare")
        bottom.addTab(self.log, "Log")
        dock = QtWidgets.QDockWidget("Investigation Output")
        dock.setWidget(bottom)
        dock.setAllowedAreas(QtCore.Qt.BottomDockWidgetArea)
        self.addDockWidget(QtCore.Qt.BottomDockWidgetArea, dock)
        self.statusBar().addWidget(self.progress_label)

    def _connect_signals(self) -> None:
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
        self.compare_table.itemActivated.connect(self._compare_activated)
        self.compare_table.itemDoubleClicked.connect(self._compare_activated)
        self.recipe_combo.activated.connect(self._recipe_activated)
        self.graph_search_edit.returnPressed.connect(self.search_current_graph)

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
            str(Path.cwd()),
            "JSON files (*.json);;All files (*)",
        )
        if path:
            self.source_edit.setText(path)
            self.build_id_edit.clear()

    def run_analysis(self) -> None:
        try:
            load_spec = self._load_spec()
        except ValueError as exc:
            self._show_error(str(exc))
            return

        self.progress_label.setText("Analyzing...")
        self.log.clear()
        self._log("Starting analysis")
        worker = AnalysisWorker(load_spec)
        worker.signals.progress.connect(self._log)
        worker.signals.failed.connect(self._analysis_failed)
        worker.signals.finished.connect(self._analysis_finished)
        self.thread_pool.start(worker)

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

    def _analysis_finished(self, result: AnalysisResult) -> None:
        self.result = result
        self.progress_label.setText("Analysis complete")
        self._log("Analysis complete")
        for warning in result.warnings:
            self._log(warning.message)
        self._populate_artifacts()
        self._populate_findings()
        self._populate_coverage_table()
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

    def _populate_timeline(self) -> None:
        assert self.result is not None
        self.timeline_table.clear()
        for event in timeline_tree(self.result.graph, self.result.build_analysis):
            self.timeline_table.addTopLevelItem(self._timeline_item(event))
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
        self._show_node(self.selected_node_id, render_graph=False)

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
        data = evidence_bundle(
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
        Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._log(f"Exported evidence bundle to {path}")

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
        bundle = evidence_bundle(
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
        Path(path).write_text(evidence_report_html(bundle), encoding="utf-8")
        self._log(f"Exported HTML report to {path}")

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
        deltas = compare_artifacts(self.result.graph, other.graph)
        self.compare_table.setRowCount(len(deltas))
        for row, delta in enumerate(deltas):
            values = [delta.change, delta.key, delta.left or "", delta.right or "", delta.detail]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.UserRole, delta.left or "")
                self.compare_table.setItem(row, column, item)
        self.compare_table.resizeColumnsToContents()
        self._log(f"Compared current graph with {path}: {len(deltas)} artifact deltas")

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
        self.include_tests.setChecked(session.include_tests)
        self.artifact_filter.setText(session.artifact_filter)
        self.run_analysis()

    def _current_session(self) -> WorkbenchSession:
        current = self.artifact_list.currentItem()
        return WorkbenchSession(
            source=self.source_edit.text(),
            build_id=self.build_id_edit.text(),
            mode=self.mode_combo.currentText(),
            include_tests=self.include_tests.isChecked(),
            artifact_filter=self.artifact_filter.text(),
            selected_artifact_id=(
                str(current.data(QtCore.Qt.UserRole)) if current is not None else None
            ),
            selected_node_id=self.selected_node_id,
            selected_edge_index=self.selected_edge_index,
        )

    def _apply_session(self, session: WorkbenchSession) -> None:
        mode_index = self.mode_combo.findText(session.mode)
        if mode_index >= 0:
            self.mode_combo.setCurrentIndex(mode_index)
        self.include_tests.setChecked(session.include_tests)
        self.artifact_filter.setText(session.artifact_filter)
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


def run(
    *,
    source: Path | None = None,
    build_id: int | None = None,
    base_url: str = "https://build.almalinux.org",
) -> int:
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    app.setApplicationName("ALBS Provenance Investigation Workbench")
    window = WorkbenchWindow(
        initial_source=source,
        initial_build_id=build_id,
        base_url=base_url,
    )
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

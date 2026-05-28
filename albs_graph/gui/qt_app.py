# mypy: ignore-errors
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from PyQt5 import QtCore, QtSvg, QtWidgets

from albs_graph.pipeline import RunSpec
from albs_graph.render import graph_to_svg
from albs_graph.services import (
    AnalysisResult,
    AnalysisService,
    GraphLoadSpec,
    GraphQueries,
    GraphSlice,
    GraphSlices,
    findings_for_analysis,
)


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
        self.current_svg = ""
        self.base_url = base_url

        self.source_edit = QtWidgets.QLineEdit(str(initial_source or ""))
        self.build_id_edit = QtWidgets.QLineEdit(str(initial_build_id or ""))
        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["Trust Path", "Dependency Evidence", "Security Context"])
        self.include_tests = QtWidgets.QCheckBox("Tests")
        self.coverage_label = QtWidgets.QLabel("No graph loaded")
        self.progress_label = QtWidgets.QLabel("")

        self.artifact_list = QtWidgets.QListWidget()
        self.slice_nodes = QtWidgets.QTableWidget(0, 3)
        self.slice_nodes.setHorizontalHeaderLabels(["Type", "Label", "Node id"])
        self.slice_nodes.horizontalHeader().setStretchLastSection(True)
        self.slice_nodes.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.slice_nodes.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.svg_widget = QtSvg.QSvgWidget()
        self.svg_widget.setMinimumSize(720, 520)
        self.svg_scroll = QtWidgets.QScrollArea()
        self.svg_scroll.setWidget(self.svg_widget)
        self.svg_scroll.setWidgetResizable(True)

        self.inspector = QtWidgets.QPlainTextEdit()
        self.inspector.setReadOnly(True)
        self.findings_table = QtWidgets.QTableWidget(0, 4)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Code", "Subject", "Detail"])
        self.findings_table.horizontalHeader().setStretchLastSection(True)
        self.findings_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

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

        toolbar.addAction(open_action)
        toolbar.addAction(run_action)
        toolbar.addAction(export_action)
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
        toolbar.addWidget(self.include_tests)

        left = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.addWidget(QtWidgets.QLabel("Artifacts"))
        left_layout.addWidget(self.artifact_list)
        left_layout.addWidget(self.coverage_label)

        center = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        center.addWidget(self.svg_scroll)
        center.addWidget(self.slice_nodes)
        center.setStretchFactor(0, 4)
        center.setStretchFactor(1, 1)

        right = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.setContentsMargins(8, 8, 8, 8)
        right_layout.addWidget(QtWidgets.QLabel("Inspector"))
        right_layout.addWidget(self.inspector)

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
        bottom.addTab(self.log, "Log")
        dock = QtWidgets.QDockWidget("Investigation Output")
        dock.setWidget(bottom)
        dock.setAllowedAreas(QtCore.Qt.BottomDockWidgetArea)
        self.addDockWidget(QtCore.Qt.BottomDockWidgetArea, dock)
        self.statusBar().addWidget(self.progress_label)

    def _connect_signals(self) -> None:
        self.artifact_list.currentItemChanged.connect(self._artifact_changed)
        self.mode_combo.currentTextChanged.connect(lambda _text: self.render_current_slice())
        self.include_tests.stateChanged.connect(lambda _state: self.render_current_slice())
        self.slice_nodes.itemSelectionChanged.connect(self._slice_node_changed)

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background: #f6f7f9; }
            QToolBar { spacing: 8px; padding: 6px; background: #ffffff; border-bottom: 1px solid #d8dde6; }
            QListWidget, QTableWidget, QPlainTextEdit, QScrollArea {
                background: #ffffff;
                border: 1px solid #d8dde6;
            }
            QLabel { color: #263238; }
            QHeaderView::section { background: #eef2f6; padding: 5px; border: 0; }
            """
        )

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
        self._update_coverage()
        if self.artifact_list.count():
            self.artifact_list.setCurrentRow(0)

    def _analysis_failed(self, message: str) -> None:
        self.progress_label.setText("Analysis failed")
        self._log(f"ERROR: {message}")
        self._show_error(message)

    def _populate_artifacts(self) -> None:
        self.artifact_list.clear()
        assert self.result is not None
        for summary in GraphQueries(self.result.graph).artifacts():
            name = summary.metadata.get("name") or summary.label
            arch = summary.metadata.get("arch") or "?"
            item = QtWidgets.QListWidgetItem(f"{name}  [{arch}]")
            item.setData(QtCore.Qt.UserRole, summary.id)
            item.setToolTip(summary.id)
            self.artifact_list.addItem(item)

    def _populate_findings(self) -> None:
        assert self.result is not None
        findings = findings_for_analysis(
            self.result.graph, self.result.coverage, self.result.reconciliation
        )
        self.findings_table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            values = [
                finding.severity,
                finding.code,
                finding.subject or "",
                finding.detail or "",
            ]
            for column, value in enumerate(values):
                self.findings_table.setItem(row, column, QtWidgets.QTableWidgetItem(value))
        self.findings_table.resizeColumnsToContents()

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
            else:
                graph_slice = slices.trust_path(
                    subject_id,
                    include_tests=self.include_tests.isChecked(),
                )
        except Exception as exc:
            self._show_error(str(exc))
            return
        self.current_slice = graph_slice
        self.current_svg = graph_to_svg(graph_slice.graph)
        self.svg_widget.load(QtCore.QByteArray(self.current_svg.encode("utf-8")))
        self._populate_slice_nodes(graph_slice)
        self._show_node(subject_id)

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

    def _show_node(self, node_id: str) -> None:
        if self.result is None:
            return
        queries = GraphQueries(self.result.graph)
        try:
            summary = queries.node_summary(node_id)
        except ValueError:
            if self.current_slice is None:
                return
            summary = GraphQueries(self.current_slice.graph).node_summary(node_id)
            incoming = []
            outgoing = []
        else:
            incoming = [edge.to_dict() for edge in queries.incoming(node_id)]
            outgoing = [edge.to_dict() for edge in queries.outgoing(node_id)]
        payload: dict[str, Any] = {
            "node": summary.to_dict(),
            "incoming": incoming,
            "outgoing": outgoing,
        }
        self.inspector.setPlainText(json.dumps(payload, indent=2, sort_keys=True))

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

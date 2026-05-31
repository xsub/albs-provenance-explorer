from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
import re
import signal
import sys
import time
from typing import Any, Callable, TypeVar

from PyQt5 import QtCore, QtGui, QtSvg, QtWidgets

from albs_graph.adapters.albs import (
    BuildNotFoundError,
    BuildSummary,
    fetch_build_summary,
    fetch_recent_builds,
)
from albs_graph.adapters.errata_source import almalinux_errata_feed_url, almalinux_major_version
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
    BuildCatalog,
    evidence_report_html,
    evidence_report_markdown,
    GraphLoadSpec,
    GraphQueries,
    Finding,
    GraphSlice,
    GraphSlices,
    WorkbenchSession,
    compare_builds,
    coverage_rows,
    evidence_bundle,
    evidence_matrix_rows,
    filter_graph_layers,
    finding_drilldown_rows,
    findings_for_analysis,
    graph_layers,
    graph_query_presets,
    investigation_recipes,
    run_graph_query,
    source_evidence_rows,
)
from albs_graph.gui.dependency_panel import DependencyPanel
from albs_graph.gui.security_panel import SecurityPanel
from albs_graph.gui.timeline_panel import TimelinePanel
from albs_graph.gui.universe_panel import UniversePanel


RECIPE_COMBO_WIDTH = 136
RECIPE_POPUP_MIN_WIDTH = 460
BOTTOM_DOCK_MIN_HEIGHT = 96
BOTTOM_PAGE_MIN_HEIGHT = 0
INSPECTION_TMP_ROOT = Path("/private/tmp/albs-provenance-workbench")

_T = TypeVar("_T")


def _require(value: _T | None) -> _T:
    """Narrow an Optional Qt accessor that never returns None in this app.

    ``menuBar()`` / ``horizontalHeader()`` / ``style()`` / ``statusBar()`` and
    friends are typed ``X | None`` in the PyQt5 stubs but are always present
    here. Wrapping the call in ``_require`` narrows it with a single assert,
    so the module stays free of the blanket ``# mypy: ignore-errors``.
    """

    assert value is not None
    return value


_EL_FAMILY_IDS = frozenset({"almalinux", "rhel", "centos", "rocky", "fedora", "el"})


def _os_release_ids(text: str) -> set[str]:
    """The ``ID`` + ``ID_LIKE`` tokens from an ``/etc/os-release`` body."""

    ids: set[str] = set()
    for line in text.splitlines():
        if line.startswith(("ID=", "ID_LIKE=")):
            ids.update(line.split("=", 1)[1].strip().strip('"').split())
    return ids


def _is_almalinux_family_host() -> bool:
    """True on an AlmaLinux / RHEL-family host with ``rpm`` available.

    Gates host-RPM-only features (Inspect Binary). macOS and non-EL distros
    return False -- no matching ``/etc/os-release`` ``ID`` / ``ID_LIKE`` or no
    ``rpm`` on PATH -- so the action greys out there.
    """

    if shutil.which("rpm") is None:
        return False
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(_os_release_ids(text) & _EL_FAMILY_IDS)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _build_id_from_path(path: Path) -> str | None:
    match = re.search(r"build[-_](\d+)", path.name)
    return match.group(1) if match else None


def _prepend_env_path(path: Path, existing: str) -> str:
    prefix = str(path)
    return f"{prefix}{os.pathsep}{existing}" if existing else prefix


# Interactive status-bar source badges (D114): the external sources fetchable
# from a build id alone. A badge greys out when its data is missing or its cache
# is stale for the current build id; clicking it fetches just that resource,
# while build id + Enter fetches them all in sequence.
_SOURCE_ALBS = "ALBS"
_SOURCE_ERRATA = "ERRATA"
_SOURCE_SBOM = "SBOM"
_SOURCE_BADGES: tuple[str, ...] = (_SOURCE_ALBS, _SOURCE_ERRATA, _SOURCE_SBOM)
_SOURCE_ACTIVE_COLORS = {
    _SOURCE_ALBS: "#2F6FED",
    _SOURCE_ERRATA: "#C0563F",
    _SOURCE_SBOM: "#B07D3A",
}
_BADGE_STALE_COLOR = "#B8860B"  # amber: cache present but older than the TTL
_BADGE_MISSING_COLOR = "#586069"  # grey: not fetched / no data for this build

_STATE_ACTIVE = "active"
_STATE_STALE = "stale"
_STATE_MISSING = "missing"


def _cache_file_state(path: Path, ttl_seconds: int, build_id: str | None) -> str:
    """Return ``active`` / ``stale`` / ``missing`` for an on-disk JSON cache file.

    A file present but older than the TTL is ``stale``; a file whose embedded
    build id does not match the requested one counts as ``missing`` for that id
    (the same guard ``fetch_build_metadata`` applies before trusting a cache).
    """

    try:
        stat = path.stat()
    except OSError:
        return _STATE_MISSING
    if build_id is not None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return _STATE_MISSING
        cached_id = data.get("id")
        if cached_id is None:
            cached_id = data.get("build_id")
        if cached_id is not None and str(cached_id) != str(build_id):
            return _STATE_MISSING
    age = time.time() - stat.st_mtime
    return _STATE_STALE if age > ttl_seconds else _STATE_ACTIVE


class AnalysisSignals(QtCore.QObject):
    progress = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(object)
    failed = QtCore.pyqtSignal(str)
    build_not_found = QtCore.pyqtSignal(str)  # the missing build id (a sparse-id 404)


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
        except BuildNotFoundError:
            # A sparse-id 404 is not a tool failure -- route it to a calm
            # "build not found" path rather than the red "Analysis failed".
            self.signals.build_not_found.emit(str(self.load_spec.build_id or ""))
            return
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

    def mousePressEvent(self, event: QtGui.QMouseEvent | None) -> None:
        if event is None:
            super().mousePressEvent(event)
            return
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
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

    def mouseMoveEvent(self, event: QtGui.QMouseEvent | None) -> None:
        if event is None:
            super().mouseMoveEvent(event)
            return
        cursor = (
            QtCore.Qt.CursorShape.PointingHandCursor
            if self._node_id_at(event.pos()) is not None
            or self._edge_index_at(event.pos()) is not None
            else QtCore.Qt.CursorShape.ArrowCursor
        )
        self.setCursor(cursor)
        super().mouseMoveEvent(event)

    def leaveEvent(self, event: QtCore.QEvent | None) -> None:
        self.unsetCursor()
        super().leaveEvent(event)

    def _node_id_at(self, point: QtCore.QPoint) -> str | None:
        if not self._node_regions:
            return None
        size = _require(self.renderer()).defaultSize()
        if not size.isValid() or self.width() <= 0 or self.height() <= 0:
            return None
        x = point.x() * size.width() / self.width()
        y = point.y() * size.height() / self.height()
        return node_at(self._node_regions, x, y)

    def _edge_index_at(self, point: QtCore.QPoint) -> int | None:
        if not self._edge_regions:
            return None
        size = _require(self.renderer()).defaultSize()
        if not size.isValid() or self.width() <= 0 or self.height() <= 0:
            return None
        x = point.x() * size.width() / self.width()
        y = point.y() * size.height() / self.height()
        return edge_at(self._edge_regions, x, y)


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
            QtCore.Qt.TextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
            | QtCore.Qt.TextInteractionFlag.TextSelectableByKeyboard
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
        self.process.setProcessChannelMode(QtCore.QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._read_output)
        self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(self._failed)

        self._append(intro.rstrip() + "\n\n")
        self.process.start(program, arguments)

    def stop_process(self) -> None:
        if self.process.state() == QtCore.QProcess.ProcessState.NotRunning:
            return
        self._append("\n[workbench] stopping subprocess...\n")
        self.process.terminate()
        if not self.process.waitForFinished(3000):
            self.process.kill()

    def closeEvent(self, event: QtGui.QCloseEvent | None) -> None:
        if self.process.state() != QtCore.QProcess.ProcessState.NotRunning:
            self.stop_process()
        if event is not None:
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
        status = "ok" if exit_code == 0 and exit_status == QtCore.QProcess.ExitStatus.NormalExit else "failed"
        self._append(f"\n[workbench] subprocess finished: {status} (exit code {exit_code})\n")
        self.stop_button.setEnabled(False)
        self.ok_button.setEnabled(True)

    def _append(self, text: str) -> None:
        cursor = self.output.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()


def _describe_build(build: BuildSummary) -> str:
    """One-line description of a build for the catalog list (D121)."""

    package = build.packages[0] if build.packages else "?"
    extra = f" +{len(build.packages) - 1}" if len(build.packages) > 1 else ""
    platform = build.platforms[0] if build.platforms else ""
    when = (build.created_at or "")[:16].replace("T", " ")  # YYYY-MM-DD HH:MM
    owner = f"  ·  {build.owner}" if build.owner else ""
    return f"{build.build_id}   {package}{extra}   {platform}   {when}{owner}".rstrip()


class _BuildPickerDialog(QtWidgets.QDialog):
    """A filterable list of catalog builds (id + short description), sorted by
    build time (the catalog hands them over newest-first). Returns the picked
    build id via ``selected_build_id`` (D121)."""

    def __init__(
        self, builds: list[BuildSummary], parent: QtWidgets.QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Browse builds")
        self.resize(600, 440)
        self.selected_build_id: str | None = None

        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by id / package / platform / owner")
        self.filter_edit.setClearButtonEnabled(True)
        self.list = QtWidgets.QListWidget()
        for build in builds:
            item = QtWidgets.QListWidgetItem(_describe_build(build))
            item.setData(QtCore.Qt.ItemDataRole.UserRole, str(build.build_id))
            haystack = " ".join(
                [str(build.build_id), *build.packages, *build.platforms, build.owner or ""]
            )
            item.setData(QtCore.Qt.ItemDataRole.UserRole + 1, haystack.casefold())
            self.list.addItem(item)
        if self.list.count():
            self.list.setCurrentRow(0)
        buttons = QtWidgets.QDialogButtonBox()
        buttons.addButton(QtWidgets.QDialogButtonBox.StandardButton.Open)
        buttons.addButton(QtWidgets.QDialogButtonBox.StandardButton.Cancel)

        layout = QtWidgets.QVBoxLayout(self)
        header = QtWidgets.QLabel(f"{len(builds)} known builds (newest first)")
        layout.addWidget(header)
        layout.addWidget(self.filter_edit)
        layout.addWidget(self.list)
        layout.addWidget(buttons)

        self.filter_edit.textChanged.connect(self._filter)
        self.list.itemActivated.connect(lambda _item: self.accept())
        self.list.itemDoubleClicked.connect(lambda _item: self.accept())
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def _filter(self, text: str) -> None:
        needle = text.casefold().strip()
        first_visible: QtWidgets.QListWidgetItem | None = None
        for index in range(self.list.count()):
            item = _require(self.list.item(index))
            haystack = str(item.data(QtCore.Qt.ItemDataRole.UserRole + 1))
            hidden = bool(needle) and needle not in haystack
            item.setHidden(hidden)
            if not hidden and first_visible is None:
                first_visible = item
        current = self.list.currentItem()
        if first_visible is not None and (current is None or current.isHidden()):
            self.list.setCurrentItem(first_visible)

    def accept(self) -> None:
        item = self.list.currentItem()
        if item is not None and not item.isHidden():
            self.selected_build_id = str(item.data(QtCore.Qt.ItemDataRole.UserRole))
        super().accept()


VerifyFn = Callable[[str], tuple[bool, str]]


class _InspectBuildIdDialog(QtWidgets.QDialog):
    """Enter an arbitrary ALBS build id and verify it exists (fetch its
    name/desc) before analysing -- so a sparse-id 404 is caught up front, and
    the user confirms it is the build they meant (D122). ``Inspect`` enables
    only once a verification succeeds."""

    def __init__(self, verify: VerifyFn, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Inspect by ALBS Build ID")
        self.resize(440, 160)
        self._verify = verify
        self.selected_build_id: str | None = None

        self.build_id_edit = QtWidgets.QLineEdit()
        self.build_id_edit.setPlaceholderText("ALBS build id (a number)")
        self.status = QtWidgets.QLabel("Enter a build id, then Verify.")
        self.status.setWordWrap(True)
        verify_button = QtWidgets.QPushButton("Verify")
        self._buttons = QtWidgets.QDialogButtonBox()
        self._ok = _require(self._buttons.addButton(QtWidgets.QDialogButtonBox.StandardButton.Open))
        self._buttons.addButton(QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        self._ok.setText("Inspect")
        self._ok.setEnabled(False)

        entry = QtWidgets.QHBoxLayout()
        entry.addWidget(self.build_id_edit)
        entry.addWidget(verify_button)
        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(entry)
        layout.addWidget(self.status)
        layout.addWidget(self._buttons)

        verify_button.clicked.connect(self.verify_now)
        self.build_id_edit.returnPressed.connect(self.verify_now)
        self.build_id_edit.textChanged.connect(self._invalidate)
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)

    def _invalidate(self, _text: str = "") -> None:
        self._ok.setEnabled(False)
        self.selected_build_id = None

    def verify_now(self) -> None:
        build_id = self.build_id_edit.text().strip()
        if not build_id.isdigit():
            self.status.setText("Build id must be a number.")
            return
        self.status.setText(f"Verifying build {build_id}…")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        QtWidgets.QApplication.processEvents()
        try:
            ok, description = self._verify(build_id)
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()
        self.status.setText(description)
        self._ok.setEnabled(ok)
        self.selected_build_id = build_id if ok else None

    def accept(self) -> None:
        if self.selected_build_id:  # only a verified id may proceed
            super().accept()


class _StartDialog(QtWidgets.QDialog):
    """The startup launcher: choose how to begin an investigation (D122)."""

    OPTIONS = (
        ("session", "Open Saved Session…"),
        ("build_id", "Inspect by ALBS Build ID…"),
        ("browse", "Inspect by ALBS Build ID (choose from list)…"),
        ("file", "Inspect by ALBS file (build metadata JSON)…"),
        ("package", "Inspect by ALBS package (local RPM)…"),
        ("synthetic", "Open the offline demo (synthetic fixture)"),
    )

    def __init__(
        self, parent: QtWidgets.QWidget | None = None, *, package_enabled: bool = True
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("ALBS Provenance Investigation Workbench")
        self.choice: str | None = None

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(QtWidgets.QLabel("How would you like to begin?"))
        for key, label in self.OPTIONS:
            button = QtWidgets.QPushButton(label)
            button.setMinimumHeight(34)
            if key == "package" and not package_enabled:
                button.setEnabled(False)  # host RPM tooling only (Inspect Binary)
                button.setToolTip(
                    "Available only on an AlmaLinux / RHEL-family host (rpm required)."
                )
            button.clicked.connect(lambda _checked=False, choice=key: self._choose(choice))
            layout.addWidget(button)
        cancel = QtWidgets.QDialogButtonBox()
        cancel.addButton(QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        cancel.rejected.connect(self.reject)
        layout.addWidget(cancel)

    def _choose(self, choice: str) -> None:
        self.choice = choice
        self.accept()


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

        self.thread_pool = _require(QtCore.QThreadPool.globalInstance())
        self._active_worker: AnalysisWorker | None = None
        # M3: a report-time CVE feed for the Security panel's Potential CVEs
        # column, cached by the source string it was loaded from.
        self.cve_feed: CveFeed | None = None
        self._cve_feed_source: str | None = None
        self.result: AnalysisResult | None = None
        self._source_badges: dict[str, QtWidgets.QToolButton] = {}
        self.cache_ttl_seconds = 300  # ALBS metadata cache freshness (badge state)
        self._pending_refresh = False  # next build-id fetch forces a refetch
        self._deep_fetch = False  # next run pulls every host-available enrichment
        self.build_catalog = BuildCatalog()  # cached db of real build ids (D120)
        self.build_list_limit = 100  # how many recent builds a refresh fetches (D121)
        self.current_slice: GraphSlice | None = None
        self.findings: list[Finding] = []
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
        # Autocomplete build ids from the cached catalog (D120) so a real id is a
        # keystroke away, not a guess.
        self._build_completer = QtWidgets.QCompleter([], self)
        self._build_completer.setCaseSensitivity(QtCore.Qt.CaseSensitivity.CaseInsensitive)
        self._build_completer.setFilterMode(QtCore.Qt.MatchFlag.MatchContains)
        self.build_id_edit.setCompleter(self._build_completer)
        self.build_sbom_edit = QtWidgets.QLineEdit(str(initial_build_sbom or ""))
        self.build_sbom_edit.setPlaceholderText("Build SBOM")
        self.build_sbom_edit.setClearButtonEnabled(True)
        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(
            ["Trust Path", "Dependency Evidence", "Security Context", "Node Neighborhood"]
        )
        # Live errata source (D79/M3): off / http feed / host dnf / both (D119,
        # cross-check the two and mark agreement). The combo's userData is the
        # RunSpec.errata_source value (""/"http"/"dnf"/"both").
        self.errata_combo = QtWidgets.QComboBox()
        # The "Errata" toolbar label already provides context, so keep the items
        # short -- and wide enough that the selection is never truncated.
        self.errata_combo.addItem("off", "")
        self.errata_combo.addItem("http (almalinux.org)", "http")
        self.errata_combo.addItem("dnf (host)", "dnf")
        self.errata_combo.addItem("both (cross-check)", "both")
        self.errata_combo.setMinimumWidth(165)
        self.errata_feed_edit = QtWidgets.QLineEdit()
        self.errata_feed_edit.setPlaceholderText("blank = errata.almalinux.org")
        self.errata_feed_edit.setToolTip(
            "Errata feed file or URL for 'Errata: http'. Leave blank to use the "
            "official AlmaLinux feed for the build's distro "
            "(errata.almalinux.org/<N>/errata.full.json)."
        )
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
        _require(self.recipe_combo.view()).setTextElideMode(QtCore.Qt.TextElideMode.ElideNone)
        _require(self.recipe_combo.view()).setMinimumWidth(RECIPE_POPUP_MIN_WIDTH)
        self.layer_button = QtWidgets.QToolButton()
        self.layer_button.setText("Layers")
        self.layer_button.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        self.layer_menu = QtWidgets.QMenu(self.layer_button)
        self.layer_actions: dict[str, QtWidgets.QAction] = {}
        for layer in graph_layers():
            action = _require(self.layer_menu.addAction(layer.label))
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
        _require(self.slice_nodes.horizontalHeader()).setStretchLastSection(True)
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
            _require(table.horizontalHeader()).setStretchLastSection(True)
            table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            table.setAlternatingRowColors(True)
        self.inspector_tabs.addTab(self.summary_table, "Summary")
        self.inspector_tabs.addTab(self.metadata_table, "Metadata")
        self.inspector_tabs.addTab(self.edges_table, "Edges")
        self.inspector_tabs.addTab(self.raw_inspector, "Raw")

        self.findings_table = QtWidgets.QTableWidget(0, 4)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Code", "Subject", "Detail"])
        _require(self.findings_table.horizontalHeader()).setStretchLastSection(True)
        self.findings_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.findings_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.coverage_table = QtWidgets.QTableWidget(0, 5)
        self.coverage_table.setHorizontalHeaderLabels(["Axis", "Covered", "Total", "Ratio", "Status"])
        _require(self.coverage_table.horizontalHeader()).setStretchLastSection(True)
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
        _require(self.evidence_table.horizontalHeader()).setStretchLastSection(True)
        self.evidence_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.evidence_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.evidence_table.setAlternatingRowColors(True)
        self.security_panel = SecurityPanel(
            navigate=lambda node_id: self._navigate_to_node(node_id, prefer_artifact=True)
        )
        self.dependency_panel = DependencyPanel(
            navigate=lambda node_id: self._navigate_to_node(node_id, prefer_artifact=True)
        )
        self.source_table = QtWidgets.QTableWidget(0, 4)
        self.source_table.setHorizontalHeaderLabels(["Category", "Label", "Node id", "Detail"])
        _require(self.source_table.horizontalHeader()).setStretchLastSection(True)
        self.source_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.source_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.source_table.setAlternatingRowColors(True)
        self.query_combo = QtWidgets.QComboBox()
        for preset in graph_query_presets():
            self.query_combo.addItem(preset.title, preset.code)
        self.query_run_button = QtWidgets.QPushButton("Run")
        self.query_table = QtWidgets.QTableWidget(0, 4)
        self.query_table.setHorizontalHeaderLabels(["Kind", "Label", "Node id", "Detail"])
        _require(self.query_table.horizontalHeader()).setStretchLastSection(True)
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
        _require(self.finding_detail_table.horizontalHeader()).setStretchLastSection(True)
        self.finding_detail_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.finding_detail_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.finding_detail_table.setAlternatingRowColors(True)
        self.timeline_panel = TimelinePanel(
            navigate=lambda node_id: self._navigate_to_node(node_id, prefer_artifact=False)
        )
        self.compare_table = QtWidgets.QTableWidget(0, 6)
        self.compare_table.setHorizontalHeaderLabels(["Area", "Change", "Key", "Left", "Right", "Detail"])
        _require(self.compare_table.horizontalHeader()).setStretchLastSection(True)
        self.compare_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.compare_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(500)

        self.universe_panel = UniversePanel(log=self._log, show_error=self._show_error)

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
            _require(self.style()).standardIcon(QtWidgets.QStyle.StandardPixmap.SP_DialogOpenButton),
            "Open",
            self,
        )
        open_action.triggered.connect(self.open_source)
        run_action = QtWidgets.QAction(
            _require(self.style()).standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MediaPlay),
            "Analyze",
            self,
        )
        run_action.setToolTip(
            "Analyze: for a build id, fetch every host-available source; "
            "for a cached source file, (re)analyse it offline."
        )
        run_action.triggered.connect(self._analyze_or_fetch_all)
        export_action = QtWidgets.QAction(
            _require(self.style()).standardIcon(QtWidgets.QStyle.StandardPixmap.SP_DialogSaveButton),
            "Export SVG",
            self,
        )
        export_action.triggered.connect(self.export_svg)
        export_bundle_action = QtWidgets.QAction(
            _require(self.style()).standardIcon(QtWidgets.QStyle.StandardPixmap.SP_DriveFDIcon),
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
        run_classic_action = QtWidgets.QAction("Run Full Inspection (run.sh)…", self)
        run_classic_action.setToolTip(
            "Run run.sh for the entered build id in a subprocess -- a complete "
            "inspection pulling from every source the host supports (ALBS, dnf, "
            "RPM headers/payloads, GPG signatures, SBOM, errata.almalinux.org), "
            "then load the result."
        )
        run_classic_action.triggered.connect(self.run_full_inspection)
        inspect_build_action = QtWidgets.QAction("Inspect Build Id…", self)
        inspect_build_action.setToolTip("Prompt for an ALBS build id and analyse it in-app.")
        inspect_build_action.triggered.connect(self.prompt_inspect_build_id)
        build_sbom_action = QtWidgets.QAction("SBOM", self)
        build_sbom_action.setToolTip("Choose a build CycloneDX SBOM")
        build_sbom_action.triggered.connect(self.open_build_sbom)
        inspect_binary_action = QtWidgets.QAction("Inspect Binary (RPM)…", self)
        if _is_almalinux_family_host():
            inspect_binary_action.setToolTip("Inspect a local RPM with the host RPM tooling.")
            inspect_binary_action.triggered.connect(self.inspect_binary)
        else:
            inspect_binary_action.setEnabled(False)  # host RPM tooling only
            inspect_binary_action.setToolTip(
                "Available only on an AlmaLinux / RHEL-family host (rpm required)."
            )
        save_session_action = QtWidgets.QAction("Save Session", self)
        save_session_action.triggered.connect(self.save_session)
        load_session_action = QtWidgets.QAction("Load Session", self)
        load_session_action.triggered.connect(self.load_session)
        reload_program_action = QtWidgets.QAction("Reload Program", self)
        reload_program_action.triggered.connect(self.reload_program)
        exit_action = QtWidgets.QAction("Exit", self)
        # QWidget.close() returns bool; connecting it to a void signal is idiomatic
        # but trips the PyQt5 stub's Callable[..., None] expectation.
        exit_action.triggered.connect(self.close)  # type: ignore[arg-type]
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
            run_classic_action=run_classic_action,
            inspect_build_action=inspect_build_action,
            inspect_binary_action=inspect_binary_action,
            save_session_action=save_session_action,
            load_session_action=load_session_action,
            reload_program_action=reload_program_action,
            exit_action=exit_action,
            zoom_in_action=zoom_in_action,
            zoom_out_action=zoom_out_action,
            fit_action=fit_action,
            reset_action=reset_action,
        )

        toolbar.addAction(open_action)
        toolbar.addAction(run_action)
        toolbar.addSeparator()
        toolbar.addWidget(QtWidgets.QLabel("Build id"))
        self.build_id_edit.setFixedWidth(90)
        toolbar.addWidget(self.build_id_edit)
        toolbar.addWidget(QtWidgets.QLabel("Source"))
        self.source_edit.setFixedWidth(240)
        toolbar.addWidget(self.source_edit)
        toolbar.addAction(build_sbom_action)
        self.build_sbom_edit.setFixedWidth(180)
        toolbar.addWidget(self.build_sbom_edit)
        toolbar.addSeparator()
        toolbar.addWidget(QtWidgets.QLabel("Mode"))
        toolbar.addWidget(self.mode_combo)
        toolbar.addWidget(self.recipe_combo)
        toolbar.addWidget(self.layer_button)
        toolbar.addWidget(self.graph_search_edit)
        toolbar.addWidget(self.include_tests)

        # The security feed inputs (errata / CPE / CVE) live on a second row so
        # the primary inputs above never overflow into the toolbar extension menu.
        self.addToolBarBreak()
        security_toolbar = QtWidgets.QToolBar("Security sources")
        security_toolbar.setMovable(False)
        self.addToolBar(security_toolbar)
        security_toolbar.addWidget(QtWidgets.QLabel("Errata"))
        security_toolbar.addWidget(self.errata_combo)
        security_toolbar.addWidget(self.errata_feed_edit)
        security_toolbar.addSeparator()
        security_toolbar.addWidget(QtWidgets.QLabel("CPE dict"))
        security_toolbar.addWidget(self.cpe_dict_edit)
        security_toolbar.addSeparator()
        security_toolbar.addWidget(QtWidgets.QLabel("CVE feed"))
        security_toolbar.addWidget(self.cve_feed_edit)

        left = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.addWidget(self.artifact_header)
        left_layout.addWidget(self.artifact_filter)
        left_layout.addWidget(self.artifact_list)
        left_layout.addWidget(self.coverage_label)

        center = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
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
        bottom.addTab(self.security_panel, "Security")
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
        dock.setAllowedAreas(QtCore.Qt.DockWidgetArea.BottomDockWidgetArea)
        self.output_tabs = bottom
        self.output_dock = dock
        self.addDockWidget(QtCore.Qt.DockWidgetArea.BottomDockWidgetArea, dock)
        _require(self.statusBar()).addWidget(self.progress_label)
        self._install_source_badges()
        self._update_build_completer()  # seed build-id autocomplete from the cached catalog

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
        run_classic_action: QtWidgets.QAction,
        inspect_build_action: QtWidgets.QAction,
        inspect_binary_action: QtWidgets.QAction,
        save_session_action: QtWidgets.QAction,
        load_session_action: QtWidgets.QAction,
        reload_program_action: QtWidgets.QAction,
        exit_action: QtWidgets.QAction,
        zoom_in_action: QtWidgets.QAction,
        zoom_out_action: QtWidgets.QAction,
        fit_action: QtWidgets.QAction,
        reset_action: QtWidgets.QAction,
    ) -> None:
        menu_bar = _require(self.menuBar())
        file_menu = _require(menu_bar.addMenu("File"))
        start_action = QtWidgets.QAction("Start…", self)
        start_action.setToolTip("Choose how to begin: saved session, build id, file, package…")
        start_action.triggered.connect(self.present_start_dialog)
        file_menu.addAction(start_action)
        file_menu.addSeparator()
        file_menu.addAction(open_action)
        file_menu.addAction(build_sbom_action)
        file_menu.addAction(inspect_binary_action)
        file_menu.addSeparator()
        file_menu.addAction(save_session_action)
        file_menu.addAction(load_session_action)
        export_menu = _require(file_menu.addMenu("Export"))
        export_menu.addAction(export_action)
        export_menu.addAction(export_png_action)
        export_menu.addAction(export_bundle_action)
        export_menu.addAction(export_html_action)
        export_menu.addAction(export_markdown_action)
        file_menu.addSeparator()
        file_menu.addAction(reload_program_action)
        file_menu.addAction(exit_action)

        run_menu = _require(menu_bar.addMenu("Run"))
        run_menu.addAction(run_action)
        run_menu.addAction(inspect_build_action)
        run_menu.addAction(compare_action)
        run_menu.addSeparator()
        run_menu.addAction(run_classic_action)

        # Builds menu: a cached catalog of real build ids to pick from, so a
        # sparse-id guess (a 404) is avoidable (D120/D121).
        builds_menu = _require(menu_bar.addMenu("Builds"))
        browse_builds_action = QtWidgets.QAction("Browse Builds…", self)
        browse_builds_action.setToolTip("Pick a known build id from the cached catalog.")
        browse_builds_action.triggered.connect(self.browse_builds)
        builds_menu.addAction(browse_builds_action)
        builds_menu.addSeparator()
        # Refresh ▸ Last N: fetch the N most recent ALBS builds (configurable).
        refresh_menu = _require(builds_menu.addMenu("Refresh from ALBS"))
        for count in (50, 100, 200, 500):
            action = QtWidgets.QAction(f"Last {count} builds", self)
            action.triggered.connect(lambda _checked=False, n=count: self.refresh_build_list(n))
            refresh_menu.addAction(action)

        view_menu = _require(menu_bar.addMenu("View"))
        view_menu.addAction(zoom_in_action)
        view_menu.addAction(zoom_out_action)
        view_menu.addAction(fit_action)
        view_menu.addAction(reset_action)

    def _relax_bottom_panel_minimums(self, bottom: QtWidgets.QTabWidget) -> None:
        for index in range(bottom.count()):
            page = _require(bottom.widget(index))
            page.setMinimumHeight(BOTTOM_PAGE_MIN_HEIGHT)
            page.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Ignored)

    def _connect_signals(self) -> None:
        self.source_edit.textChanged.connect(lambda _text: self._update_input_tooltips())
        self.build_sbom_edit.textChanged.connect(lambda _text: self._update_input_tooltips())
        self.build_id_edit.textChanged.connect(lambda _text: self._update_input_tooltips())
        self.build_id_edit.textChanged.connect(lambda _text: self._refresh_source_badges())
        # Enter in the build-id field fetches every build-id source in sequence
        # (D114); the classic example--full.sh subprocess is an explicit Run-menu
        # action. Enter in Source means "load this file" (drops any stale id).
        self.build_id_edit.returnPressed.connect(self._fetch_all_sources)
        self.source_edit.returnPressed.connect(self._analyze_source)
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
        self.evidence_table.itemActivated.connect(self._evidence_activated)
        self.evidence_table.itemDoubleClicked.connect(self._evidence_activated)
        self.cve_feed_edit.editingFinished.connect(self._refresh_security_table)
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
            self.build_id_edit.clear()  # a chosen file wins over any stale build id
            self.run_analysis()  # load it immediately so the artifacts populate

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

    def _analyze_source(self) -> None:
        # "Load this source": a path in the Source field wins over a stale build
        # id (the loader otherwise prefers build id), then analyse.
        if self.source_edit.text().strip():
            self.build_id_edit.clear()
        self.run_analysis()

    def run_analysis(self) -> None:
        try:
            load_spec = self._load_spec()
            run_spec = self._run_spec(load_spec)
        except ValueError as exc:
            self._deep_fetch = False  # the one-shot did not reach _run_spec
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
        worker.signals.build_not_found.connect(self._build_not_found)
        worker.signals.finished.connect(self._analysis_finished)
        self._active_worker = worker  # keep a handle so closeEvent can detach it
        self.thread_pool.start(worker)

    def inspect_binary(self) -> None:
        # Host-RPM-only (AlmaLinux/RHEL family): inspect a local RPM via the CLI
        # inspect-rpm command in a subprocess dialog.
        path, _filter = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Inspect a binary RPM",
            self._dialog_start_dir(),
            "RPM files (*.rpm);;All files (*)",
        )
        if not path:
            return
        environment = QtCore.QProcessEnvironment.systemEnvironment()
        environment.insert(
            "PYTHONPATH", _prepend_env_path(_repo_root(), environment.value("PYTHONPATH"))
        )
        dialog = ConsoleProcessDialog(
            title=f"Inspect binary: {Path(path).name}",
            program=sys.executable,
            arguments=["-m", "albs_graph.cli.main", "inspect-rpm", path],
            cwd=_repo_root(),
            environment=environment,
            intro=f"[workbench] inspecting RPM: {path}",
            parent=self,
        )
        dialog.exec_()

    def prompt_inspect_build_id(self) -> None:
        # Menu entry point: ask for a build id, then analyse it in-app (the fast
        # path, no subprocess). A blank source means the build id wins.
        current = self.build_id_edit.text().strip()
        build_id, ok = QtWidgets.QInputDialog.getText(
            self, "Inspect Build Id", "ALBS build id:", text=current
        )
        if not ok:
            return
        build_id = build_id.strip()
        if not build_id.isdigit():
            self._show_error("Build id must be a number.")
            return
        self.build_id_edit.setText(build_id)
        self.source_edit.clear()  # the build id is the explicit choice now
        self.run_analysis()

    def present_start_dialog(self) -> None:
        # The startup launcher (D122): choose how to begin. Also reachable from
        # File > Start…. Dispatches the choice to the matching entry point.
        dialog = _StartDialog(self, package_enabled=_is_almalinux_family_host())
        dialog.exec_()
        self._dispatch_start_choice(dialog.choice)

    def _dispatch_start_choice(self, choice: str | None) -> None:
        actions: dict[str, Callable[[], None]] = {
            "session": self.load_session,
            "build_id": self.inspect_build_id_verified,
            "browse": self.browse_builds,
            "file": self.open_source,
            "package": self.inspect_binary,
            "synthetic": self._load_synthetic_demo,
        }
        action = actions.get(choice or "")
        if action is not None:
            action()

    def inspect_build_id_verified(self) -> None:
        # Enter an arbitrary build id, verify it against ALBS (name/desc), then
        # analyse it -- "Inspect by ALBS Build ID" (D122).
        dialog = _InspectBuildIdDialog(self._verify_build_id, self)
        if dialog.exec_() == QtWidgets.QDialog.DialogCode.Accepted and dialog.selected_build_id:
            self.build_id_edit.setText(dialog.selected_build_id)
            self.source_edit.clear()  # the build id is the explicit choice now
            self._analyze_or_fetch_all()

    def _verify_build_id(self, build_id: str) -> tuple[bool, str]:
        # Confirm a build id exists. The cached catalog answers instantly; an
        # unknown id is verified live (and recorded so next time is instant).
        known = {build.build_id: build for build in self.build_catalog.load()}.get(int(build_id))
        if known is not None and (known.packages or known.created_at):
            return True, f"Verified: {known.label()}"
        try:
            summary = fetch_build_summary(int(build_id), self.base_url, progress=self._log)
        except BuildNotFoundError:
            return False, f"Build {build_id} not found on ALBS."
        except Exception as exc:  # noqa: BLE001 -- a live verify must not crash the UI
            return False, f"Verification failed: {exc}"
        self.build_catalog.record(summary)
        self._update_build_completer()
        return True, f"Verified: {summary.label()}"

    def _load_synthetic_demo(self) -> None:
        # The offline demo: load the bundled synthetic fixture (D122).
        from albs_graph.gui.entry import default_source_path

        self.build_id_edit.clear()
        self.source_edit.setText(str(default_source_path()))
        self._analyze_source()

    def browse_builds(self) -> None:
        # Pick a known build id from the cached catalog (D120/D121) -- a
        # filterable list sorted by build time -- instead of guessing a sparse
        # number. Offers to refresh from ALBS when the catalog is empty.
        builds = self.build_catalog.load()
        if not builds:
            answer = QtWidgets.QMessageBox.question(
                self,
                "No cached builds",
                "The build catalog is empty. Fetch the most recent ALBS builds now?",
            )
            if answer == QtWidgets.QMessageBox.StandardButton.Yes:
                self.refresh_build_list()
                builds = self.build_catalog.load()
            if not builds:
                return
        build_id = self._pick_build(builds)
        if not build_id:
            return
        self.build_id_edit.setText(build_id)
        self.source_edit.clear()  # the build id is the explicit choice now
        self._analyze_or_fetch_all()

    def _pick_build(self, builds: list[BuildSummary]) -> str | None:
        dialog = _BuildPickerDialog(builds, self)
        if dialog.exec_() == QtWidgets.QDialog.DialogCode.Accepted:
            return dialog.selected_build_id
        return None

    def refresh_build_list(self, limit: int | None = None) -> None:
        # Fetch the most recent `limit` ALBS builds into the cached catalog
        # (D121: configurable last-N from the Builds menu).
        limit = limit or self.build_list_limit
        self.build_list_limit = limit  # remember the chosen size
        self.progress_label.setText(f"Fetching last {limit} builds…")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        try:
            builds = fetch_recent_builds(self.base_url, limit=limit, progress=self._log)
        except Exception as exc:  # noqa: BLE001 -- a live fetch must never crash the UI
            self.progress_label.setText("Build list unavailable")
            self._log(f"Build list refresh failed: {exc}")
            return
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()
        merged = self.build_catalog.merge(builds)
        self._update_build_completer()
        self.progress_label.setText(f"Build catalog: {len(merged)} known builds")
        self._log(f"Fetched {len(builds)} builds; catalog now holds {len(merged)}")

    def _update_build_completer(self) -> None:
        ids = [str(build_id) for build_id in self.build_catalog.build_ids()]
        self._build_completer.setModel(QtCore.QStringListModel(ids, self))

    def _record_analyzed_build(self) -> None:
        # Remember a build the user actually analyzed, so it is in the catalog
        # even if it has aged off the recent-builds page (D120). Preserve any
        # build time already known for it so the time sort (D121) stays correct.
        build_id = self._current_build_id()
        if not build_id or not build_id.isdigit() or self.result is None:
            return
        graph = self.result.graph
        packages = tuple(node.label for node in graph.find_by_type("source_package"))
        major = almalinux_major_version(graph)
        platforms = (f"AlmaLinux-{major}",) if major else ()
        known = {build.build_id: build for build in self.build_catalog.load()}.get(int(build_id))
        self.build_catalog.record(
            BuildSummary(
                build_id=int(build_id),
                created_at=known.created_at if known else None,
                finished_at=known.finished_at if known else None,
                owner=known.owner if known else None,
                packages=packages,
                platforms=platforms,
            )
        )
        self._update_build_completer()

    def run_full_inspection(self) -> None:
        # Run run.sh -- the full-inspection template -- for the entered build id
        # in a subprocess (it pulls from every source the host supports), then
        # load its cached ALBS metadata back into the workbench.
        build_id = self.build_id_edit.text().strip()
        if not build_id:
            self._show_error("Enter a build id to run the full inspection.")
            return
        if not build_id.isdigit():
            self._show_error("Build id must be a number.")
            return
        script = _repo_root() / "run.sh"
        if not script.exists():
            self._show_error(f"Inspection script not found: {script}")
            return

        out_dir = INSPECTION_TMP_ROOT / f"build-{build_id}"
        cache = out_dir / f"build-{build_id}.albs.json"
        out_dir.mkdir(parents=True, exist_ok=True)
        environment = QtCore.QProcessEnvironment.systemEnvironment()
        environment.insert("BUILD_ID", build_id)
        environment.insert("OUT_DIR", str(out_dir))
        environment.insert("CACHE", str(cache))
        environment.insert(
            "PYTHONPATH", _prepend_env_path(_repo_root(), environment.value("PYTHONPATH"))
        )
        environment.insert(
            "PATH", _prepend_env_path(Path(sys.executable).parent, environment.value("PATH"))
        )
        intro = "\n".join(
            [
                f"[workbench] inspection script: {script}",
                f"[workbench] build id: {build_id}",
                f"[workbench] output dir: {out_dir}",
                f"[workbench] command: bash run.sh {build_id}",
            ]
        )
        dialog = ConsoleProcessDialog(
            title=f"Full inspection for build {build_id}",
            program="/bin/bash",
            arguments=[str(script), build_id],
            cwd=_repo_root(),
            environment=environment,
            intro=intro,
            parent=self,
        )
        dialog.exec_()

        if dialog.exit_code != 0:
            self._show_error("Full inspection did not finish successfully (see the log).")
            return
        if not cache.exists():
            self._show_error(f"Inspection finished but did not create {cache}.")
            return
        self.source_edit.setText(str(cache))
        self.build_id_edit.clear()
        self._log(f"Loading inspected build cache {cache}")
        self.run_analysis()

    def _load_spec(self) -> GraphLoadSpec:
        build_id = self.build_id_edit.text().strip()
        source = self.source_edit.text().strip()
        if build_id:
            refresh = self._pending_refresh
            self._pending_refresh = False
            # Cache the metadata under the shared OUT_DIR convention so the ALBS
            # badge has a file to probe for freshness on the next refresh (D114).
            return GraphLoadSpec(
                build_id=int(build_id),
                base_url=self.base_url,
                cache=self._workbench_cache_path(build_id),
                cache_ttl_seconds=self.cache_ttl_seconds,
                refresh_cache=refresh,
            )
        if not source:
            raise ValueError("Choose a source JSON or enter a build id.")
        path = Path(source).expanduser()
        if not path.exists():
            raise ValueError(f"Source JSON does not exist: {path}")
        return GraphLoadSpec(source=path)

    def _run_spec(self, load_spec: GraphLoadSpec) -> RunSpec:
        deep_fetch = self._deep_fetch  # capture + clear up front (one-shot)
        self._deep_fetch = False
        self._autofill_build_sbom(load_spec)
        build_sbom_path: Path | None = None
        build_sbom = self.build_sbom_edit.text().strip()
        if build_sbom:
            candidate = Path(build_sbom).expanduser()
            if not candidate.exists():
                raise ValueError(f"Build SBOM JSON does not exist: {candidate}")
            expected_build_id = self._build_id_for_spec(load_spec)
            sbom_build_id = _build_id_from_path(candidate)
            if expected_build_id and sbom_build_id and expected_build_id != sbom_build_id:
                # The SBOM is auxiliary evidence: a mismatch should not block the
                # whole analysis (that left users stuck behind a modal). Drop it
                # with a log note and analyse the build anyway.
                self._log(
                    f"Ignoring build SBOM for build {sbom_build_id} "
                    f"(current build is {expected_build_id})"
                )
            else:
                build_sbom_path = candidate
        deep_kwargs: dict[str, Any] = {}
        if deep_fetch:
            deep_kwargs = self._host_enrichment_kwargs()
            enabled = ", ".join(sorted(deep_kwargs))
            self._log(f"Fetch all: pulling every host-available source ({enabled})")
        return RunSpec(
            build_sbom=build_sbom_path,
            **self._errata_run_kwargs(),
            **self._verify_cpe_run_kwargs(),
            **deep_kwargs,
        )

    def _verify_cpe_run_kwargs(self) -> dict[str, Any]:
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

    def _errata_run_kwargs(self) -> dict[str, Any]:
        """RunSpec errata kwargs from the toolbar combo + feed field (D79/M3).

        "" -> no errata source (not_checked stays the default). "dnf" queries
        the host updateinfo (degrades to not-consulted off an AlmaLinux box).
        "http" reads an offline feed file when the field is an existing path,
        else treats it as a live feed URL; an empty field still selects http
        but simply degrades to not-consulted (logged), never crashes. "both"
        cross-checks the web feed against dnf and marks the advisories they
        agree on (D119) -- the feed field still feeds the http side.
        """

        source = str(self.errata_combo.currentData() or "")
        if not source:
            return {}
        kwargs: dict[str, object] = {"errata_source": source}
        if source in ("http", "both"):
            feed = self.errata_feed_edit.text().strip()
            if feed:
                candidate = Path(feed).expanduser()
                if candidate.exists():
                    kwargs["errata_feed"] = candidate
                else:
                    kwargs["errata_url"] = feed
        return kwargs

    def _autofill_build_sbom(self, load_spec: GraphLoadSpec) -> None:
        expected = self._build_id_for_spec(load_spec)
        current = self.build_sbom_edit.text().strip()
        if current:
            sbom_id = _build_id_from_path(Path(current).expanduser())
            if not (expected and sbom_id and expected != sbom_id):
                return  # the current SBOM is consistent (or we can't tell) -- keep it
            # A stale SBOM for a different build -- drop it and re-discover the
            # right one below so switching builds does not get stuck on it.
            self._log(f"Build SBOM was for build {sbom_id}, not {expected}; re-discovering")
            self.build_sbom_edit.clear()
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
        self._record_analyzed_build()  # remember this build id in the catalog (D120)
        self._refresh_source_badges()
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

    def _install_source_badges(self) -> None:
        # Persistent, clickable status-bar badges for the build-id sources (D114).
        # They live for the window's lifetime; _refresh_source_badges recolours
        # them as the cache state for the current build id changes.
        bar = _require(self.statusBar())
        for name in _SOURCE_BADGES:
            badge = QtWidgets.QToolButton()
            badge.setText(name)
            badge.setAutoRaise(True)
            badge.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            badge.clicked.connect(lambda _checked=False, source=name: self._fetch_source(source))
            bar.addPermanentWidget(badge)
            self._source_badges[name] = badge
        self._refresh_source_badges()

    def _refresh_source_badges(self) -> None:
        # Recolour each badge from its source's cache state for the current build
        # id: active (data fresh), stale (cache older than the TTL) or missing
        # (greyed out -- not fetched / no data). The resource URI is on hover.
        build_id = self._current_build_id()
        for name, badge in self._source_badges.items():
            state, uri = self._source_state(name, build_id)
            badge.setText(self._source_badge_text(name, build_id, state))
            self._style_source_badge(badge, name, state, uri)

    def _source_badge_text(self, name: str, build_id: str | None, state: str) -> str:
        # Show the source's identifier inline (ALBS: <id>, SBOM: <serial/id>,
        # ERRATA: <count>). ALBS always names its build id (so you can see which
        # build the grey/active badge is for); ERRATA/SBOM show their value only
        # once present (there is no id to show before they are fetched).
        if name == _SOURCE_ALBS:
            return f"ALBS: {build_id}" if build_id else "ALBS"
        if state == _STATE_MISSING:
            return name
        if name == _SOURCE_ERRATA:
            count = len(self.result.graph.find_by_type("errata")) if self.result else 0
            return f"ERRATA: {count}" if count else "ERRATA"
        if name == _SOURCE_SBOM:
            ident = self._sbom_identifier(build_id)
            return f"SBOM: {ident}" if ident else "SBOM"
        return name

    def _sbom_identifier(self, build_id: str | None) -> str | None:
        # The SBOM's serial number (a hash, shortened) when the graph carries an
        # SBOM node, else the build id the discovered SBOM file belongs to.
        if self.result is not None:
            for node in self.result.graph.find_by_type("sbom"):
                raw = node.id.split(":", 1)[1] if ":" in node.id else node.id
                if raw.lower().startswith("urn:uuid:"):
                    return raw.rsplit(":", 1)[-1][:8]  # short serial hash
                match = re.search(r"build[-_](\d+)", raw)
                return match.group(1) if match else (build_id or raw)
        return build_id

    def _current_build_id(self) -> str | None:
        # The build id under investigation: the entered id, else the one inferred
        # from a loaded source path (build-<id>.albs.json).
        build_id = self.build_id_edit.text().strip()
        if build_id:
            return build_id
        source = self.source_edit.text().strip()
        if source:
            return _build_id_from_path(Path(source))
        return None

    def _source_state(self, name: str, build_id: str | None) -> tuple[str, str]:
        """Return ``(state, hover-uri)`` for a source badge."""

        if name == _SOURCE_ALBS:
            uri = (
                f"{self.base_url}/api/v1/builds/{build_id}/"
                if build_id
                else f"{self.base_url}/api/v1/builds/"
            )
            if build_id is None:
                return _STATE_MISSING, uri
            state = _cache_file_state(
                self._workbench_cache_path(build_id), self.cache_ttl_seconds, build_id
            )
            if state == _STATE_MISSING:
                # An explicitly loaded source file counts as fetched-and-fresh.
                source = self.source_edit.text().strip()
                if source and _build_id_from_path(Path(source)) == build_id:
                    state = _cache_file_state(Path(source), self.cache_ttl_seconds, build_id)
            return state, uri
        if name == _SOURCE_ERRATA:
            uri = self._errata_source_uri()
            present = self.result is not None and bool(self.result.graph.find_by_type("errata"))
            return (_STATE_ACTIVE if present else _STATE_MISSING), uri
        if name == _SOURCE_SBOM:
            candidate = self._discovered_build_sbom(build_id)
            if candidate is not None:
                return _STATE_ACTIVE, str(candidate)
            label = f"build-{build_id}.cyclonedx.json" if build_id else "build SBOM"
            return _STATE_MISSING, f"no build SBOM discovered ({label})"
        return _STATE_MISSING, name

    def _style_source_badge(
        self, badge: QtWidgets.QToolButton, name: str, state: str, uri: str
    ) -> None:
        if state == _STATE_ACTIVE:
            color, fg, note = _SOURCE_ACTIVE_COLORS[name], "#FFFFFF", "fetched"
        elif state == _STATE_STALE:
            color, fg, note = _BADGE_STALE_COLOR, "#FFFFFF", "stale cache -- click to refresh"
        else:
            color, fg, note = _BADGE_MISSING_COLOR, "#C9CFD6", "not fetched -- click to fetch"
        badge.setToolTip(f"{uri}\n({note})")
        badge.setStyleSheet(
            f"QToolButton{{background:{color};color:{fg};border:none;border-radius:7px;"
            "padding:1px 8px;margin:0 2px;font-size:11px;font-weight:600;}"
            "QToolButton:hover{border:1px solid #FFFFFF;}"
        )

    def _errata_source_uri(self) -> str:
        selected = str(self.errata_combo.currentData() or "")
        if selected == "dnf":
            return "dnf updateinfo (host)"
        if selected == "both":
            return "web feed + dnf updateinfo (cross-checked)"
        feed = self.errata_feed_edit.text().strip()
        if feed:
            return feed
        if self.result is not None:
            version = almalinux_major_version(self.result.graph)
            if version:
                return almalinux_errata_feed_url(version)
        return "errata.almalinux.org"

    def _workbench_cache_path(self, build_id: str) -> Path:
        # Where a build-id fetch caches its ALBS metadata (shared with run.sh's
        # OUT_DIR convention) so the ALBS badge has a file to probe.
        return INSPECTION_TMP_ROOT / f"build-{build_id}" / f"build-{build_id}.albs.json"

    def _discovered_build_sbom(self, build_id: str | None) -> Path | None:
        current = self.build_sbom_edit.text().strip()
        if current:
            candidate = Path(current).expanduser()
            if candidate.exists():
                sbom_id = _build_id_from_path(candidate)
                if not (build_id and sbom_id and build_id != sbom_id):
                    return candidate
        if build_id is None or not build_id.isdigit():
            return None
        source = self.source_edit.text().strip()
        return discover_build_sbom(
            int(build_id),
            cache_path=Path(source) if source else None,
            search_dirs=(_repo_root() / "examples", self._workbench_cache_path(build_id).parent),
        )

    def _fetch_source(self, name: str) -> None:
        # Click a badge to (re)fetch just that resource for the current build id.
        if self._current_build_id() is None:
            self._show_error("Enter a build id first, then click a source to fetch it.")
            return
        if name == _SOURCE_ALBS:
            self._pending_refresh = True  # force a refetch of the build metadata
        elif name == _SOURCE_ERRATA:
            self._select_default_errata()
        elif name == _SOURCE_SBOM:
            self.build_sbom_edit.clear()  # re-discover from the build-id convention
        self.run_analysis()

    def _analyze_or_fetch_all(self) -> None:
        # The primary Analyze action (toolbar + Ctrl+R). For a live build id it
        # fetches every host-available source (the rich result); for an already
        # cached source file it just (re)analyses it offline -- so working from a
        # local file never triggers a surprise network pull.
        if self.build_id_edit.text().strip():
            self._fetch_all_sources()
        else:
            self.run_analysis()

    def _fetch_all_sources(self) -> None:
        # Build id + Enter: pull every build-id source the host can in one run --
        # ALBS (base) + errata (host default) + SBOM autodiscovery + the
        # host-available enrichments (RPM headers, dnf/sonames, cas). The heavy
        # RPM-download rungs (payloads/ELF, signature checksig) and SBOM
        # *generation* stay in Run > Run Full Inspection (run.sh).
        self._select_default_errata()
        self._deep_fetch = True
        self.run_analysis()

    def _default_errata_source(self) -> str:
        # On an AlmaLinux / RHEL-family host the local `dnf updateinfo` is the
        # authoritative errata source; off such a host (e.g. macOS) fall back to
        # the errata.almalinux.org HTTP feed.
        if shutil.which("dnf") and _is_almalinux_family_host():
            return "dnf"
        return "http"

    def _select_default_errata(self) -> None:
        # Turn errata on for a fetch-all using the host-appropriate default
        # (dnf on AlmaLinux, http elsewhere), but respect an explicit choice
        # already made: only switch when the combo is "off".
        if str(self.errata_combo.currentData() or ""):
            return
        index = self.errata_combo.findData(self._default_errata_source())
        if index >= 0:
            self.errata_combo.setCurrentIndex(index)

    def _host_enrichment_kwargs(self) -> dict[str, Any]:
        """The richer enrichments a fetch-all pulls, each gated on its host tool.

        RPM headers are an HTTP range read (light, always on). ``dnf`` /
        ``cas`` are consulted only when present so the run degrades gracefully
        off an AlmaLinux box (the same shape ``run.sh`` uses). The heavy
        full-RPM-download rungs (payloads, signature checksig) are deliberately
        left out of the one-keystroke path.
        """

        kwargs: dict[str, Any] = {"with_rpm_headers": True}
        if shutil.which("dnf"):
            kwargs["use_dnf"] = True
            kwargs["resolve_sonames"] = True
        if shutil.which("cas"):
            kwargs["use_cas"] = True
        return kwargs

    def _analysis_failed(self, message: str) -> None:
        self.progress_label.setText("Analysis failed")
        self._log(f"ERROR: {message}")
        self._show_error(message)

    def _build_not_found(self, build_id: str) -> None:
        # A sparse-id 404: the build simply does not exist. Treat it as an
        # informational outcome, not a red "Analysis failed" -- the previous
        # result (if any) stays so the user does not lose their place.
        label = f"build {build_id}" if build_id else "that build id"
        self.progress_label.setText(f"Build {build_id} not found".strip())
        self._log(
            f"ALBS {label} was not found on {self.base_url}. "
            "Build ids are not sequential -- most numbers have no build."
        )
        self._refresh_source_badges()  # ALBS greys out for the missing id
        QtWidgets.QMessageBox.information(
            self,
            "Build not found",
            f"ALBS {label} was not found on {self.base_url}.\n\n"
            "ALBS build ids are not sequential -- most numbers have no build. "
            "Check the id on build.almalinux.org and enter one that exists.",
        )

    def _populate_artifacts(self) -> None:
        self.artifact_list.clear()
        assert self.result is not None
        artifacts = GraphQueries(self.result.graph).artifacts()
        self.artifact_header.setText(f"Artifacts ({len(artifacts)})")
        for summary in artifacts:
            name = summary.metadata.get("name") or summary.label
            arch = summary.metadata.get("arch") or "?"
            item = QtWidgets.QListWidgetItem(f"{name}  [{arch}]")
            item.setData(QtCore.Qt.ItemDataRole.UserRole, summary.id)
            item.setData(QtCore.Qt.ItemDataRole.UserRole + 1, f"{name} {arch} {summary.id}".casefold())
            item.setToolTip(summary.id)
            self.artifact_list.addItem(item)

    def _filter_artifacts(self, text: str) -> None:
        needle = text.casefold().strip()
        visible = 0
        first_visible: QtWidgets.QListWidgetItem | None = None
        for index in range(self.artifact_list.count()):
            item = _require(self.artifact_list.item(index))
            haystack = str(item.data(QtCore.Qt.ItemDataRole.UserRole + 1))
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
                item.setData(QtCore.Qt.ItemDataRole.UserRole, finding.subject or "")
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
                item.setData(QtCore.Qt.ItemDataRole.UserRole, evidence.node_id)
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
        # The CVE feed is loaded here (the host owns the toolbar field); the
        # typed SecurityPanel owns the table rendering + colour-tinting.
        self.security_panel.populate(self.result.graph, cve_feed=self._ensure_cve_feed())

    def _populate_dependency_table(self) -> None:
        if self.result is not None:
            self.dependency_panel.populate(self.result.graph)

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

    def _populate_finding_detail(self, finding: Finding) -> None:
        if self.result is None:
            return
        rows = finding_drilldown_rows(self.result.graph, finding)
        self._populate_query_like_table(self.finding_detail_table, rows)

    def _populate_query_like_table(self, table: QtWidgets.QTableWidget, rows: list[Any]) -> None:
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
                item.setData(QtCore.Qt.ItemDataRole.UserRole, item_data.node_id)
                table.setItem(row, column, item)
        table.resizeColumnsToContents()

    def _current_subject_id(self) -> str | None:
        current = self.artifact_list.currentItem()
        if current is not None:
            return str(current.data(QtCore.Qt.ItemDataRole.UserRole))
        return self.selected_node_id

    def _populate_timeline(self) -> None:
        assert self.result is not None
        self.timeline_panel.populate(
            self.result.graph, self.result.build_analysis, dark=self.dark_mode
        )

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
        _require(self.recipe_combo.view()).setMinimumWidth(max(RECIPE_POPUP_MIN_WIDTH, widest_item + 72))

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
        self.selected_node_id = str(current.data(QtCore.Qt.ItemDataRole.UserRole))
        self.render_current_slice()

    def render_current_slice(self) -> None:
        if self.result is None:
            return
        current = self.artifact_list.currentItem()
        if current is None:
            return
        subject_id = current.data(QtCore.Qt.ItemDataRole.UserRole)
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
        renderer = _require(self.svg_widget.renderer())
        size = renderer.defaultSize()
        if not size.isValid() or size.width() <= 0 or size.height() <= 0:
            size = QtCore.QSize(900, 560)
        self.svg_default_size = size
        target = self._graph_target_size(size)
        self.svg_widget.setFixedSize(target)

    def _graph_target_size(self, size: QtCore.QSize) -> QtCore.QSize:
        viewport = _require(self.svg_scroll.viewport()).size()
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
                item.setData(QtCore.Qt.ItemDataRole.UserRole, node.id)
                self.slice_nodes.setItem(row, column, item)
        self.slice_nodes.resizeColumnsToContents()

    def _slice_node_changed(self) -> None:
        selected = self.slice_nodes.selectedItems()
        if not selected:
            return
        node_id = selected[0].data(QtCore.Qt.ItemDataRole.UserRole)
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
        subject = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if subject:
            self._navigate_to_node(str(subject), prefer_artifact=True)

    def _edge_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        edge_index = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if edge_index is not None:
            self._show_edge(int(edge_index), from_slice=False)

    def _evidence_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if node_id:
            self._navigate_to_node(str(node_id), prefer_artifact=True)

    def _source_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if node_id:
            self._navigate_to_node(str(node_id), prefer_artifact=False)

    def _query_activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.ItemDataRole.UserRole)
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
        node_id = item.data(QtCore.Qt.ItemDataRole.UserRole)
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
            if item is not None and item.data(QtCore.Qt.ItemDataRole.UserRole) == node_id:
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
            item = _require(self.artifact_list.item(row))
            if item.data(QtCore.Qt.ItemDataRole.UserRole) == node_id:
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
                item.setData(QtCore.Qt.ItemDataRole.UserRole, edge.index)
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

    def _current_bundle(self) -> dict[str, Any]:
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
        image.fill(QtCore.Qt.GlobalColor.white)
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
                item.setData(QtCore.Qt.ItemDataRole.UserRole, delta.left_node_id or delta.right_node_id or "")
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
        self.dependency_panel.restore(
            session.dep_scope, session.dep_only_conflicts, session.dep_only_unresolved
        )
        self.universe_panel.restore(session.universe_store, session.universe_favourites)
        self.run_analysis()

    def _current_session(self) -> WorkbenchSession:
        current = self.artifact_list.currentItem()
        dep_scope, dep_only_conflicts, dep_only_unresolved = self.dependency_panel.filters()
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
            dep_scope=dep_scope,
            dep_only_conflicts=dep_only_conflicts,
            dep_only_unresolved=dep_only_unresolved,
            universe_store=self.universe_panel.store_path(),
            universe_favourites=tuple(self.universe_panel.favourites()),
            selected_artifact_id=(
                str(current.data(QtCore.Qt.ItemDataRole.UserRole)) if current is not None else None
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

    def closeEvent(self, event: QtGui.QCloseEvent | None) -> None:
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
        if event is not None:
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
    if source is None and build_id is None:
        # A bare launch: offer the start launcher (D122) rather than auto-loading.
        window.present_start_dialog()
    return int(app.exec_())

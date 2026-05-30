"""The M4 Universe panel, extracted from the main window as a typed widget.

This is the first step of splitting the single-class ``WorkbenchWindow`` (which
carries a blanket mypy ignore) into smaller, individually *type-checked* panels.
The Universe panel is the natural first extraction: it is
self-contained -- it queries a separate SQLite universe store (D74) through the
read-only :class:`UniverseStore` facade and never touches the loaded build graph
-- so it only needs two callbacks from the host window (``log`` and
``show_error``). Unlike ``qt_app.py`` this module type-checks under mypy strict.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Sequence

from PyQt5 import QtCore, QtWidgets

from albs_graph.services.universe import UniversePathRow, UniverseStore

LogFn = Callable[[str], None]


class UniversePanel(QtWidgets.QWidget):
    """Open a universe store, search packages, walk it, and render paths.

    Owns its widgets, the open store, the current focus package and the saved
    favourites; the host window only injects ``log`` / ``show_error`` and reads
    back the session state (:meth:`store_path`, :meth:`favourites`,
    :meth:`restore`).
    """

    def __init__(
        self,
        *,
        log: LogFn,
        show_error: LogFn,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._log = log
        self._show_error = show_error
        self.store: UniverseStore | None = None
        self.focus: str | None = None
        self._favourites: list[dict[str, str]] = []
        self._build_ui()

    # --- construction --------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)

        open_row = QtWidgets.QHBoxLayout()
        open_button = QtWidgets.QPushButton("Open Universe")
        open_button.clicked.connect(lambda _checked=False: self.open_store())
        self.path_label = QtWidgets.QLabel("No universe store open")
        self.path_label.setObjectName("GraphMeta")
        open_row.addWidget(open_button)
        open_row.addWidget(self.path_label, 1)
        self.fav_combo = QtWidgets.QComboBox()
        self.fav_combo.addItem("Favourites", "")
        self.fav_combo.activated.connect(self._apply_favourite)
        save_fav_button = QtWidgets.QPushButton("Save Favourite")
        save_fav_button.clicked.connect(lambda _checked=False: self._save_favourite())
        open_row.addWidget(self.fav_combo)
        open_row.addWidget(save_fav_button)
        layout.addLayout(open_row)

        search_row = QtWidgets.QHBoxLayout()
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Search packages / capabilities")
        self.search_edit.returnPressed.connect(self._search)
        search_button = QtWidgets.QPushButton("Search")
        search_button.clicked.connect(lambda _checked=False: self._search())
        search_row.addWidget(self.search_edit, 1)
        search_row.addWidget(search_button)
        layout.addLayout(search_row)

        body = QtWidgets.QSplitter()
        self.packages_table = QtWidgets.QTableWidget(0, 3)
        self.packages_table.setHorizontalHeaderLabels(["Type", "Label", "Node id"])
        _stretch_last(self.packages_table)
        self.packages_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.packages_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.packages_table.setAlternatingRowColors(True)
        self.packages_table.itemSelectionChanged.connect(self._focus_changed)
        body.addWidget(self.packages_table)

        right = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.focus_label = QtWidgets.QLabel("Focus: -")
        right_layout.addWidget(self.focus_label)
        walk_row = QtWidgets.QHBoxLayout()
        for label, kind in (
            ("Dependencies", "dependencies"),
            ("Dependents", "dependents"),
            ("Reachable", "reachable"),
        ):
            button = QtWidgets.QPushButton(label)
            button.clicked.connect(lambda _checked=False, k=kind: self._traverse(k))
            walk_row.addWidget(button)
        right_layout.addLayout(walk_row)
        path_row = QtWidgets.QHBoxLayout()
        self.target_edit = QtWidgets.QLineEdit()
        self.target_edit.setPlaceholderText("Target package for paths")
        self.target_edit.returnPressed.connect(self._find_paths)
        paths_button = QtWidgets.QPushButton("Find Paths")
        paths_button.clicked.connect(lambda _checked=False: self._find_paths())
        path_row.addWidget(self.target_edit, 1)
        path_row.addWidget(paths_button)
        right_layout.addLayout(path_row)
        self.results_table = QtWidgets.QTableWidget(0, 3)
        self.results_table.setHorizontalHeaderLabels(["Kind", "Result", "Detail"])
        _stretch_last(self.results_table)
        self.results_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.results_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.results_table.setAlternatingRowColors(True)
        right_layout.addWidget(self.results_table)
        body.addWidget(right)
        body.setStretchFactor(0, 1)
        body.setStretchFactor(1, 2)
        layout.addWidget(body)

    # --- actions -------------------------------------------------------------

    def open_store(self, path: str | None = None) -> None:
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
        self.store = store
        self.focus = None
        self.focus_label.setText("Focus: -")
        self.results_table.setRowCount(0)
        self.path_label.setText(f"{path} (schema v{version})")
        self._log(f"Opened universe store {path} (schema v{version})")
        self._search()

    def _search(self) -> None:
        if self.store is None:
            self._show_error("Open a universe store first.")
            return
        needle = self.search_edit.text().strip()
        rows = self.store.search(needle, limit=300)
        self.packages_table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            for column, value in enumerate((entry.node_type, entry.label, entry.node_id)):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(QtCore.Qt.ItemDataRole.UserRole, entry.label)
                self.packages_table.setItem(row, column, item)
        self.packages_table.resizeColumnsToContents()
        self._log(f"Universe search '{needle}': {len(rows)} matches")

    def _focus_changed(self) -> None:
        item = self.packages_table.currentItem()
        if item is None:
            return
        label_item = self.packages_table.item(item.row(), 1)
        if label_item is not None:
            self.focus = label_item.text()
            self.focus_label.setText(f"Focus: {self.focus}")

    def _traverse(self, kind: str) -> None:
        if self.store is None or not self.focus:
            self._show_error("Open a store and select a focus package first.")
            return
        focus = self.focus
        if kind == "dependencies":
            results = self.store.dependencies(focus)
        elif kind == "dependents":
            results = self.store.dependents(focus)
        else:
            results = self.store.reachable(focus)
        self.results_table.setRowCount(len(results))
        for row, label in enumerate(results):
            for column, value in enumerate((kind, label, "")):
                self.results_table.setItem(row, column, QtWidgets.QTableWidgetItem(value))
        self.results_table.resizeColumnsToContents()
        self._log(f"Universe {kind} of {focus}: {len(results)}")

    def _find_paths(self) -> None:
        if self.store is None or not self.focus:
            self._show_error("Open a store and select a focus package first.")
            return
        target = self.target_edit.text().strip()
        if not target:
            self._show_error("Enter a target package for the path search.")
            return
        rows: list[UniversePathRow] = self.store.paths(self.focus, target)
        self.results_table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            values = ("path", entry.display, f"{entry.hops} hops")
            for column, value in enumerate(values):
                self.results_table.setItem(row, column, QtWidgets.QTableWidgetItem(value))
        self.results_table.resizeColumnsToContents()
        self._log(f"Universe paths {self.focus} -> {target}: {len(rows)}")

    def _save_favourite(self) -> None:
        if self.store is None:
            self._show_error("Open a universe store first.")
            return
        favourite = {
            "store": str(self.store.db_path),
            "search": self.search_edit.text().strip(),
            "focus": self.focus or "",
            "target": self.target_edit.text().strip(),
        }
        self._favourites.append(favourite)
        self.fav_combo.addItem(_favourite_label(favourite), str(len(self._favourites) - 1))
        self._log(f"Saved universe favourite: {_favourite_label(favourite)}")

    def _apply_favourite(self, index: int) -> None:
        data = self.fav_combo.itemData(index)
        if data is None or str(data) == "":
            return
        favourite = self._favourites[int(data)]
        if self.store is None or str(self.store.db_path) != favourite["store"]:
            self.open_store(favourite["store"])
        self.search_edit.setText(favourite["search"])
        self.target_edit.setText(favourite["target"])
        self._search()
        if favourite["focus"]:
            self.focus = favourite["focus"]
            self.focus_label.setText(f"Focus: {favourite['focus']}")

    # --- session integration -------------------------------------------------

    def store_path(self) -> str:
        return str(self.store.db_path) if self.store is not None else ""

    def favourites(self) -> list[dict[str, str]]:
        return list(self._favourites)

    def restore(self, store: str, favourites: Sequence[dict[str, str]]) -> None:
        self._favourites = [dict(fav) for fav in favourites]
        self.fav_combo.clear()
        self.fav_combo.addItem("Favourites", "")
        for index, fav in enumerate(self._favourites):
            self.fav_combo.addItem(_favourite_label(fav), str(index))
        if store and Path(store).exists():
            self.open_store(store)


def _stretch_last(table: QtWidgets.QTableWidget) -> None:
    header = table.horizontalHeader()
    if header is not None:
        header.setStretchLastSection(True)


def _favourite_label(favourite: dict[str, str]) -> str:
    label = favourite.get("focus") or favourite.get("search") or favourite.get("store") or "favourite"
    if favourite.get("target"):
        label = f"{label} -> {favourite['target']}"
    return label

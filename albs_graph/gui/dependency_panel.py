"""The M2 Dependency panel, extracted from the main window as a typed widget.

Third cut of the god-object split (after ``universe_panel.py`` /
``security_panel.py``). The Dependency panel groups the reconciled dependency
verdicts (``dependency_rows``) and owns its own scope / only-conflicts /
only-unresolved filters: changing a filter re-renders from the last graph it was
given, so the host only drives it with :meth:`populate` and reads/writes the
filter state through :meth:`filters` / :meth:`restore`. It needs one injected
``navigate`` callback and type-checks under mypy strict, unlike ``qt_app.py``.
"""

from __future__ import annotations

from typing import Callable

from PyQt5 import QtCore, QtGui, QtWidgets

from albs_graph.model import ProvenanceGraph
from albs_graph.services import dependency_rows

NavigateFn = Callable[[str], None]

_COLUMNS = [
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
_SCOPE_CHOICES = (
    ("All scopes", ""),
    ("Runtime", "runtime"),
    ("Build", "build"),
    ("Static", "static"),
    ("Test", "test"),
)


class DependencyPanel(QtWidgets.QWidget):
    """Reconciled dependency groups with scope / conflict / unresolved filters.

    The host injects ``navigate`` (called with a node id on row activation) and
    calls :meth:`populate` with the analysed graph; the panel owns the filter
    header, the table and the colour-tinting, and re-renders itself when a
    filter changes.
    """

    def __init__(self, *, navigate: NavigateFn, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._navigate = navigate
        self._graph: ProvenanceGraph | None = None

        self.scope_combo = QtWidgets.QComboBox()
        for label, facet in _SCOPE_CHOICES:
            self.scope_combo.addItem(label, facet)
        self.only_conflicts = QtWidgets.QCheckBox("Only conflicts")
        self.only_unresolved = QtWidgets.QCheckBox("Only unresolved")
        self.table = QtWidgets.QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        header = self.table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        header_row = QtWidgets.QHBoxLayout()
        header_row.setContentsMargins(6, 4, 6, 4)
        header_row.addWidget(QtWidgets.QLabel("Scope"))
        header_row.addWidget(self.scope_combo)
        header_row.addWidget(self.only_conflicts)
        header_row.addWidget(self.only_unresolved)
        header_row.addStretch(1)
        layout.addLayout(header_row)
        layout.addWidget(self.table)

        self.scope_combo.currentIndexChanged.connect(lambda _index: self._refresh())
        self.only_conflicts.toggled.connect(lambda _checked: self._refresh())
        self.only_unresolved.toggled.connect(lambda _checked: self._refresh())
        self.table.itemActivated.connect(self._activated)
        self.table.itemDoubleClicked.connect(self._activated)

    # --- host API ------------------------------------------------------------

    def populate(self, graph: ProvenanceGraph) -> None:
        self._graph = graph
        self._refresh()

    def filters(self) -> tuple[str, bool, bool]:
        return (
            str(self.scope_combo.currentData() or ""),
            self.only_conflicts.isChecked(),
            self.only_unresolved.isChecked(),
        )

    def restore(self, scope: str, only_conflicts: bool, only_unresolved: bool) -> None:
        index = self.scope_combo.findData(scope or "")
        self.scope_combo.setCurrentIndex(max(index, 0))
        self.only_conflicts.setChecked(only_conflicts)
        self.only_unresolved.setChecked(only_unresolved)

    # --- internals -----------------------------------------------------------

    def _refresh(self) -> None:
        if self._graph is None:
            return
        facet = str(self.scope_combo.currentData() or "")
        rows = dependency_rows(
            self._graph,
            scope_facets={facet} if facet else None,
            only_conflicts=self.only_conflicts.isChecked(),
            only_unresolved=self.only_unresolved.isChecked(),
        )
        self.table.setRowCount(len(rows))
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
                item.setData(QtCore.Qt.ItemDataRole.UserRole, entry.subject_id)
                _tint_cell(item, column, value)
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()

    def _activated(self, item: QtWidgets.QTableWidgetItem) -> None:
        node_id = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if node_id:
            self._navigate(str(node_id))


def _tint_cell(item: QtWidgets.QTableWidgetItem, column: int, value: str) -> None:
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
    elif column == 7 and value not in ("", "-"):  # conflict kinds present
        item.setForeground(bad)
    elif column == 8 and value not in ("", "-"):  # context issue present
        item.setForeground(warn)

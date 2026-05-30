"""The M3 Security panel, extracted from the main window as a typed widget.

Second step of splitting the single-class ``WorkbenchWindow`` (which carries a
blanket mypy ignore) into individually *type-checked* panels, after
``universe_panel.py``. The Security panel renders the per-RPM security posture
(``security_rows``): CPE identity (verified / vendor-asserted / candidate),
the errata three-state, the addressed and potentially-affected CVEs, and the
caveats. It only needs the loaded graph plus an optional report-time CVE feed
(the host loads that from its toolbar field) and one ``navigate`` callback, so
unlike ``qt_app.py`` this module type-checks under mypy strict.
"""

from __future__ import annotations

from typing import Callable

from PyQt5 import QtCore, QtGui, QtWidgets

from albs_graph.model import ProvenanceGraph
from albs_graph.security.cve_feed import CveFeed
from albs_graph.services import security_rows

NavigateFn = Callable[[str], None]

_COLUMNS = [
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


class SecurityPanel(QtWidgets.QWidget):
    """Per-RPM security posture: identity, errata three-state, CVEs, caveats.

    The host injects ``navigate`` (called with a node id when a row is
    activated) and drives the panel with :meth:`populate`; the panel owns its
    table and the colour-tinting.
    """

    def __init__(self, *, navigate: NavigateFn, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._navigate = navigate
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.table = QtWidgets.QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        header = self.table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.itemActivated.connect(self._activated)
        self.table.itemDoubleClicked.connect(self._activated)
        layout.addWidget(self.table)

    def populate(self, graph: ProvenanceGraph, *, cve_feed: CveFeed | None = None) -> None:
        rows = security_rows(graph, cve_feed=cve_feed)
        self.table.setRowCount(len(rows))
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
                item.setData(QtCore.Qt.ItemDataRole.UserRole, entry.node_id)
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
    elif column in (6, 7) and value not in ("", "-"):  # addressed / potential CVEs present
        item.setForeground(warn)
    elif column == 8 and "backport" in value:  # distro-backport caveat
        item.setForeground(warn)

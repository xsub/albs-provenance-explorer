"""A reusable text filter for the bottom output tables (D138).

``filter_table_rows`` hides the rows of a ``QTableWidget`` that do not contain a
query (case-insensitive) in any cell; ``FilteredTable`` wraps a bare table with a
search box above it so every row-table tab (Evidence, Findings, Coverage, Source,
Compare, …) becomes filterable the same way the timeline already is. The custom
panels (Security, Dependencies) reuse ``filter_table_rows`` directly.
"""

from __future__ import annotations

from PyQt5 import QtWidgets

__all__ = ["FilteredTable", "filter_table_rows"]


def filter_table_rows(table: QtWidgets.QTableWidget, query: str) -> int:
    """Hide rows of ``table`` that do not contain ``query`` (case-insensitive) in
    any cell; an empty query shows every row. Returns the visible row count."""

    needle = query.casefold().strip()
    visible = 0
    for row in range(table.rowCount()):
        match = not needle
        if needle:
            for column in range(table.columnCount()):
                item = table.item(row, column)
                if item is not None and needle in item.text().casefold():
                    match = True
                    break
        table.setRowHidden(row, not match)
        visible += int(match)
    return visible


class FilteredTable(QtWidgets.QWidget):
    """A ``QTableWidget`` with a search box above it that hides non-matching rows.

    The table is reparented into this wrapper; callers keep their own reference to
    the table for population, so only the *tab page* changes (the table itself is
    untouched)."""

    def __init__(
        self,
        table: QtWidgets.QTableWidget,
        *,
        placeholder: str = "Filter…",
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.table = table
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText(placeholder)
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._apply)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(self.search)
        layout.addWidget(table)

    def _apply(self, text: str) -> None:
        filter_table_rows(self.table, text)

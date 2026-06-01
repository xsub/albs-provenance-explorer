"""The inspector "Package" tab: a *Show package info* button (with an optional
auto-fetch) that fetches and renders an RPM / source node's description (D140).

Mirrors the CVE tab: the view is dumb -- it emits ``fetchRequested(name,
rpm_filename)`` and renders whatever ``PackageInfo`` the host hands back (the host
runs the dnf / network fetch off the UI thread). With *auto-fetch* ticked,
selecting a package node fetches immediately, no button click needed.
"""

from __future__ import annotations

import html

from PyQt5 import QtCore, QtWidgets

from albs_graph.adapters.package_info import PackageInfo

__all__ = ["PackageInfoView", "render_package_html"]


class PackageInfoView(QtWidgets.QWidget):
    """Inspector tab that fetches + renders the selected package node's info."""

    fetchRequested = QtCore.pyqtSignal(str, str)  # name, rpm filename (may be "")

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._name: str | None = None
        self._rpm = ""
        self.header = QtWidgets.QLabel("Select an RPM / source node to see its package info.")
        self.header.setWordWrap(True)
        self.auto_fetch = QtWidgets.QCheckBox("auto-fetch")
        self.auto_fetch.setToolTip("Fetch automatically when a package node is selected.")
        self.button = QtWidgets.QPushButton("Show package info")
        self.button.setEnabled(False)
        self.button.clicked.connect(self._request)
        self.body = QtWidgets.QTextBrowser()
        self.body.setOpenExternalLinks(True)

        top = QtWidgets.QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.addWidget(self.header, 1)
        top.addWidget(self.auto_fetch)
        top.addWidget(self.button)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.addLayout(top)
        layout.addWidget(self.body, 1)

    def set_package(self, name: str | None, rpm_filename: str = "") -> None:
        """Point the tab at a package node (enables the button), or ``None`` for a
        non-package node. With auto-fetch ticked, fetch immediately."""

        self._name = name
        self._rpm = rpm_filename or ""
        self.button.setEnabled(name is not None)
        self.body.clear()
        if name is None:
            self.header.setText("Select an RPM / source node to see its package info.")
            return
        self.header.setText(f"{name} — click “Show package info” to fetch it.")
        if self.auto_fetch.isChecked():
            self._request()

    def _request(self) -> None:
        if self._name:
            self.button.setEnabled(False)
            self.header.setText(f"Fetching {self._name}…")
            self.fetchRequested.emit(self._name, self._rpm)

    def show_info(self, info: PackageInfo) -> None:
        self.button.setEnabled(self._name is not None)
        self.header.setText(info.name)
        self.body.setHtml(render_package_html(info))

    def show_message(self, message: str) -> None:
        self.button.setEnabled(self._name is not None)
        self.body.setHtml(f"<p style='color:#c0392b'>{html.escape(message)}</p>")


def render_package_html(info: PackageInfo) -> str:
    parts = [f"<h3>{html.escape(info.name)}</h3>"]
    if info.summary:
        parts.append(f"<p><b>{html.escape(info.summary)}</b></p>")
    if info.license:
        parts.append(f"<p><b>License:</b> {html.escape(info.license)}</p>")
    if info.url:
        url = html.escape(info.url)
        parts.append(f"<p><b>URL:</b> <a href='{url}'>{url}</a></p>")
    if info.description:
        parts.append(f"<p>{html.escape(info.description).replace(chr(10), '<br>')}</p>")
    elif not info.has_content:
        parts.append(
            "<p><i>No description was available from dnf or the RPM header "
            "(offline, or the package is not on a public mirror).</i></p>"
        )
    if info.source:
        parts.append(f"<p style='color:#888'>source: {html.escape(info.source)}</p>")
    return "".join(parts)

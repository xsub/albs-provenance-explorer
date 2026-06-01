"""The inspector "CVE" tab: a *Show CVE details* button that fetches and renders
a CVE's description / CVSS / references (D134).

The view is dumb -- it emits ``fetchRequested(cve_id)`` on the button click and
renders whatever ``CveDetails`` the host hands back via ``show_details`` (the
host runs the network fetch off the UI thread). ``cve_id_in`` pulls a canonical
``CVE-YYYY-NNNN`` out of a node id so the host knows when to enable the tab.
"""

from __future__ import annotations

import html
import re

from PyQt5 import QtCore, QtWidgets

from albs_graph.security.cve_details import CveDetails

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

__all__ = ["CveDetailsView", "cve_id_in", "render_cve_html"]


def cve_id_in(text: str) -> str | None:
    """The canonical ``CVE-YYYY-NNNN`` contained in ``text`` (a node id/label), or
    ``None`` -- so the inspector can tell a CVE node from any other."""

    match = _CVE_RE.search(text or "")
    return match.group(0).upper() if match else None


class CveDetailsView(QtWidgets.QWidget):
    """Inspector tab that fetches + renders details for the selected CVE node."""

    fetchRequested = QtCore.pyqtSignal(str)  # cve id to fetch

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._cve_id: str | None = None
        self.header = QtWidgets.QLabel("Select a CVE node to see its details.")
        self.header.setWordWrap(True)
        self.button = QtWidgets.QPushButton("Show CVE details")
        self.button.setEnabled(False)
        self.button.clicked.connect(self._request)
        self.body = QtWidgets.QTextBrowser()
        self.body.setOpenExternalLinks(True)  # reference links open in the browser

        top = QtWidgets.QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.addWidget(self.header, 1)
        top.addWidget(self.button)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.addLayout(top)
        layout.addWidget(self.body, 1)

    def set_cve(self, cve_id: str | None) -> None:
        """Point the tab at ``cve_id`` (enables the button), or ``None`` for a
        non-CVE node (disables it)."""

        self._cve_id = cve_id
        self.button.setEnabled(cve_id is not None)
        self.body.clear()
        if cve_id is None:
            self.header.setText("Select a CVE node to see its details.")
        else:
            self.header.setText(f"{cve_id} — click “Show CVE details” to fetch it.")

    def _request(self) -> None:
        if self._cve_id:
            self.button.setEnabled(False)
            self.header.setText(f"Fetching {self._cve_id}…")
            self.fetchRequested.emit(self._cve_id)

    def show_details(self, details: CveDetails) -> None:
        self.button.setEnabled(self._cve_id is not None)
        self.header.setText(details.id)
        self.body.setHtml(render_cve_html(details))

    def show_message(self, message: str) -> None:
        self.button.setEnabled(self._cve_id is not None)
        self.body.setHtml(f"<p style='color:#c0392b'>{html.escape(message)}</p>")


def render_cve_html(details: CveDetails) -> str:
    parts = [f"<h3>{html.escape(details.id)}</h3>"]
    cvss = [
        bit
        for bit in (
            f"{details.cvss_score:g}" if details.cvss_score is not None else "",
            html.escape(details.severity or ""),
            html.escape(details.cvss_vector or ""),
        )
        if bit
    ]
    if cvss:
        parts.append(f"<p><b>CVSS:</b> {' · '.join(cvss)}</p>")
    if details.published:
        parts.append(f"<p><b>Published:</b> {html.escape(details.published)}</p>")
    if details.description:
        parts.append(f"<p>{html.escape(details.description)}</p>")
    elif not details.has_content:
        parts.append(
            "<p><i>No description was available from NVD or OSV (offline?). "
            "See the reference links below.</i></p>"
        )
    if details.references:
        items = "".join(
            f"<li><a href='{html.escape(url)}'>{html.escape(url)}</a></li>"
            for url in details.references
        )
        parts.append(f"<p><b>References:</b></p><ul>{items}</ul>")
    if details.source:
        parts.append(f"<p style='color:#888'>source: {html.escape(details.source)}</p>")
    return "".join(parts)

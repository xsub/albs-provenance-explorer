"""The inspector "Git" tab: query the ALBS Gitea server for a ``git_commit`` node
and show the commit message + changed-file list; clicking a file fetches and
shows that file's diff in a pop-up (D144).

The view is dumb -- it emits ``commitRequested(repo_url, sha)`` and
``diffRequested(repo_url, sha, path)`` and renders whatever ``GitCommit`` / diff
text the host hands back (the host runs the network fetch off the UI thread).
With *auto-fetch* ticked, selecting a commit node fetches immediately.
"""

from __future__ import annotations

import html

from PyQt5 import QtCore, QtWidgets

from albs_graph.adapters.git_source import GitCommit, GitFileChange

__all__ = ["GitCommitView", "GitDiffDialog", "render_commit_html", "render_diff_html"]

# A short status glyph in front of each changed file in the list.
_STATUS_MARK = {
    "added": "+",
    "modified": "~",
    "changed": "~",
    "deleted": "−",  # minus sign
    "removed": "−",
    "renamed": "→",  # rightwards arrow
    "copied": "⇒",  # rightwards double arrow
}


class GitCommitView(QtWidgets.QWidget):
    """Inspector tab: a commit's message + changed files, with a per-file diff
    pop-up. ``set_commit`` points it at a git_commit node; the host fetches."""

    commitRequested = QtCore.pyqtSignal(str, str)  # repo_url, sha
    diffRequested = QtCore.pyqtSignal(str, str, str)  # repo_url, sha, path

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._repo_url = ""
        self._sha = ""
        self._package = ""
        self._dialog: GitDiffDialog | None = None

        self.header = QtWidgets.QLabel("Select a git commit node to see its changes.")
        self.header.setWordWrap(True)
        self.auto_fetch = QtWidgets.QCheckBox("auto-fetch")
        self.auto_fetch.setToolTip("Fetch automatically when a git commit node is selected.")
        self.button = QtWidgets.QPushButton("Show commit")
        self.button.setEnabled(False)
        self.button.clicked.connect(self._request)
        self.message = QtWidgets.QTextBrowser()
        self.message.setOpenExternalLinks(True)
        self.message.setMaximumHeight(160)
        self.files_label = QtWidgets.QLabel("Changed files")
        self.files = QtWidgets.QListWidget()
        self.files.setToolTip("Click a file to fetch and view its diff.")
        self.files.itemClicked.connect(self._file_clicked)

        top = QtWidgets.QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.addWidget(self.header, 1)
        top.addWidget(self.auto_fetch)
        top.addWidget(self.button)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.addLayout(top)
        layout.addWidget(self.message)
        layout.addWidget(self.files_label)
        layout.addWidget(self.files, 1)

    def set_commit(self, repo_url: str, sha: str, package: str = "") -> None:
        """Point the tab at a git_commit node, or ``("", "", "")`` for a non-commit
        node. The button is enabled only when there is a queryable git URL + sha.
        With auto-fetch ticked, fetch immediately."""

        self._repo_url = repo_url or ""
        self._sha = sha or ""
        self._package = package or ""
        self.message.clear()
        self.files.clear()
        enabled = bool(self._repo_url and self._sha)
        self.button.setEnabled(enabled)
        if not self._sha:
            self.header.setText("Select a git commit node to see its changes.")
            return
        if enabled:
            self.header.setText(f"{self._label()} — click “Show commit” to fetch it.")
            if self.auto_fetch.isChecked():
                self._request()
        else:
            self.header.setText(f"{self._label()} — no queryable git URL for this commit.")

    def show_commit(self, commit: GitCommit) -> None:
        self.button.setEnabled(bool(self._repo_url and self._sha))
        self.header.setText(self._label(commit.short_sha))
        self.message.setHtml(render_commit_html(commit))
        self.files.clear()
        for change in commit.files:
            item = QtWidgets.QListWidgetItem(_file_label(change))
            item.setData(QtCore.Qt.ItemDataRole.UserRole, change.path)
            self.files.addItem(item)
        if not commit.files:
            self.files.addItem(_disabled_item("No changed files reported."))

    def show_diff(self, path: str, diff_text: str) -> None:
        """Open (or replace) the diff pop-up for ``path``."""

        self.button.setEnabled(bool(self._repo_url and self._sha))
        self.header.setText(self._label())
        dialog = GitDiffDialog(path, diff_text, self)
        self._dialog = dialog  # keep a reference so it is not garbage-collected
        dialog.show()
        dialog.raise_()

    def show_message(self, message: str) -> None:
        self.button.setEnabled(bool(self._repo_url and self._sha))
        self.header.setText(self._label())
        self.message.setHtml(f"<p style='color:#c0392b'>{html.escape(message)}</p>")

    def _request(self) -> None:
        if self._repo_url and self._sha:
            self.button.setEnabled(False)
            self.header.setText(f"Fetching {self._sha[:12]}…")
            self.commitRequested.emit(self._repo_url, self._sha)

    def _file_clicked(self, item: QtWidgets.QListWidgetItem) -> None:
        path = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if not path or not self._repo_url or not self._sha:
            return
        self.header.setText(f"Fetching diff for {path}…")
        self.diffRequested.emit(self._repo_url, self._sha, str(path))

    def _label(self, short_sha: str = "") -> str:
        short = short_sha or self._sha[:12]
        return f"{self._package} @ {short}" if self._package else short


class GitDiffDialog(QtWidgets.QDialog):
    """A modeless pop-up showing one file's unified diff, syntax-coloured."""

    def __init__(
        self, path: str, diff_text: str, parent: QtWidgets.QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Diff — {path}")
        self.resize(820, 560)
        self.browser = QtWidgets.QTextBrowser()
        self.browser.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.NoWrap)
        self.browser.setHtml(render_diff_html(diff_text))
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.addWidget(self.browser, 1)
        layout.addWidget(buttons)


def render_commit_html(commit: GitCommit) -> str:
    parts: list[str] = []
    if commit.message:
        parts.append(f"<p><b>{html.escape(commit.subject)}</b></p>")
        body = commit.message.split("\n", 1)[1].strip() if "\n" in commit.message else ""
        if body:
            parts.append(f"<pre style='white-space:pre-wrap'>{html.escape(body)}</pre>")
    meta = [html.escape(bit) for bit in (commit.author, commit.date) if bit]
    if meta:
        parts.append(f"<p style='color:#888'>{' · '.join(meta)}</p>")
    if commit.html_url:
        url = html.escape(commit.html_url)
        parts.append(f"<p><a href='{url}'>{url}</a></p>")
    if not parts:
        parts.append(
            "<p><i>No commit details were available (offline, or the commit is not "
            "on the public server).</i></p>"
        )
    return "".join(parts)


def render_diff_html(diff_text: str) -> str:
    if not diff_text.strip():
        return "<p><i>No diff was available for this file.</i></p>"
    rows: list[str] = []
    for line in diff_text.splitlines():
        escaped = html.escape(line) or "&nbsp;"
        color = _diff_line_color(line)
        rows.append(f"<span style='color:{color}'>{escaped}</span>" if color else escaped)
    return "<pre style='font-family:monospace; white-space:pre'>" + "\n".join(rows) + "</pre>"


def _diff_line_color(line: str) -> str:
    if line.startswith(("+++", "---")):
        return "#8a8a8a"  # file headers: muted
    if line.startswith("+"):
        return "#1a7f37"  # additions: green
    if line.startswith("-"):
        return "#cf222e"  # removals: red
    if line.startswith("@@"):
        return "#0969da"  # hunk header: blue
    if line.startswith(
        ("diff ", "index ", "new file", "deleted file", "rename ", "similarity ", "old mode", "new mode")
    ):
        return "#8250df"  # git metadata: purple
    return ""  # context line: inherit the theme's text colour


def _file_label(change: GitFileChange) -> str:
    mark = _STATUS_MARK.get(change.status.lower(), "")
    return f"{mark} {change.path}" if mark else change.path


def _disabled_item(text: str) -> QtWidgets.QListWidgetItem:
    item = QtWidgets.QListWidgetItem(text)
    item.setFlags(QtCore.Qt.ItemFlag.NoItemFlags)
    return item

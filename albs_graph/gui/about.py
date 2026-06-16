"""The About dialog: the workbench splash artwork, a short blurb, and the
repository link at the very bottom (D141)."""

from __future__ import annotations

from pathlib import Path

from PyQt5 import QtCore, QtGui, QtWidgets

ABOUT_REPO_URL = "https://github.com/xsub/albs-provenance-explorer/tree/main"
_ABOUT_WIDTH = 560

__all__ = ["ABOUT_REPO_URL", "AboutDialog", "about_image_path"]


def about_image_path() -> Path:
    """The bundled splash artwork shown in the About dialog (and the README)."""

    return Path(__file__).resolve().parent / "resources" / "about-splash.png"


class AboutDialog(QtWidgets.QDialog):
    """Splash artwork + a one-line blurb + the repository link at the very bottom."""

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About")
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 14)
        layout.setSpacing(10)

        self.image = QtWidgets.QLabel()
        pixmap = QtGui.QPixmap(str(about_image_path()))
        if not pixmap.isNull():  # degrade gracefully if the asset is missing
            self.image.setPixmap(
                pixmap.scaledToWidth(
                    _ABOUT_WIDTH, QtCore.Qt.TransformationMode.SmoothTransformation
                )
            )
        self.image.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.image)

        blurb = QtWidgets.QLabel(
            "A read-only provenance explorer over the AlmaLinux Build System "
            "(ALBS), RPM, SBOM, CAS attestation and errata — from the source "
            "commit to the signed, shipped RPM."
        )
        blurb.setWordWrap(True)
        blurb.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        blurb.setContentsMargins(18, 0, 18, 0)
        layout.addWidget(blurb)

        self.link = QtWidgets.QLabel(f"<a href='{ABOUT_REPO_URL}'>{ABOUT_REPO_URL}</a>")
        self.link.setOpenExternalLinks(True)
        self.link.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextBrowserInteraction)
        self.link.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.link)

        self.setFixedWidth(_ABOUT_WIDTH)

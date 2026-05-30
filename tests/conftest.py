"""Test-suite environment normalisation.

Two environment sensitivities are pinned here so the suite is reproducible
everywhere -- local, CI, narrow terminals:

* **Rich/Typer help width + colour.** A few CLI tests assert on rendered
  ``--help`` text with plain substring checks. Under ``FORCE_COLOR`` (which CI
  runners such as GitHub Actions set) Rich interleaves ANSI escape codes, and at
  a narrow width it wraps/truncates flags -- both break the assertions. We pin a
  dumb terminal (no ANSI) at a wide column count (matching ``example--full.sh``).

* **Qt platform.** The PyQt5 workbench tests must not require a display. We pin
  the ``offscreen`` platform so ``pytest`` runs headless without each invocation
  having to export ``QT_QPA_PLATFORM`` (``setdefault`` keeps an explicit
  override, e.g. a developer wanting a real window).

This runs at conftest import, before any test module imports the CLI or Qt, so
the Rich/Typer consoles and the QApplication read these values when they start.
"""

from __future__ import annotations

import os

os.environ["TERM"] = "dumb"                          # plain text, no ANSI
os.environ["COLUMNS"] = "200"                        # no flag/description wrap
os.environ.pop("FORCE_COLOR", None)                  # CI colour must not win
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # headless Qt for GUI tests

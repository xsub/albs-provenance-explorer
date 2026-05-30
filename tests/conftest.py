"""Test-suite environment normalisation.

A few CLI tests (``tests/test_cli_help.py``) assert on Typer/Rich-rendered
``--help`` text with plain substring checks. Rich's output is
environment-sensitive in two ways that break those checks:

* Under ``FORCE_COLOR`` -- which CI runners such as GitHub Actions set -- Rich
  interleaves ANSI escape codes through the text, so ``"--build-id"`` is no
  longer a contiguous substring of the rendered output.
* At a narrow column count it wraps/truncates flag names and descriptions
  (e.g. ``--requirements-subje…``).

Both pass on a normal developer terminal and fail on CI. Pin a deterministic
rendering for the whole session -- a dumb terminal (no ANSI) at a wide column
count (matching ``example--full.sh``'s ``COLUMNS=200``) -- so the help tests
are reproducible everywhere: local, CI, and narrow terminals alike.

This runs at conftest import, before any test module imports the CLI, so the
Rich/Typer consoles read these values when they render.
"""

from __future__ import annotations

import os

os.environ["TERM"] = "dumb"           # disable ANSI styling -> plain text
os.environ["COLUMNS"] = "200"         # wide enough that no flag/description wraps
os.environ.pop("FORCE_COLOR", None)   # a CI-forced colour must not override TERM

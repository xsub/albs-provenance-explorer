from __future__ import annotations

from pathlib import Path


def test_full_demo_wires_in_the_verbose_build_intelligence_module() -> None:
    # The build-intelligence view (ALBS task platforms, artifact matrix, build/
    # signing/processing timing) lives in the demo_verbose Python module, not in
    # bash. example--full.sh is the single comprehensive demo and must invoke that
    # module (step 11) so the logic stays in Python rather than being reimplemented
    # in the shell. A regression guard for the consolidation in D59.
    script = Path("example--full.sh").read_text(encoding="utf-8")
    assert "-m albs_graph.cli.demo_verbose" in script  # invoked via python3 / $PYTHON_BIN

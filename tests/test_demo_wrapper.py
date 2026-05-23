from __future__ import annotations

from pathlib import Path


def test_verbose_demo_shell_wrapper_only_invokes_python_module() -> None:
    script = Path("example--verbose.sh").read_text(encoding="utf-8")

    assert "<<'PY'" not in script
    assert "python3 -m albs_graph.cli.demo_verbose" in script
    assert "command -v" not in script
    assert "if [[" not in script

from __future__ import annotations

from albs_graph.fixtures import build_synthetic_fixture_graph
from albs_graph.gui.render import workbench_graph_to_dot


def test_workbench_dot_uses_dark_theme() -> None:
    dot = workbench_graph_to_dot(build_synthetic_fixture_graph(), dark=True)

    assert 'bgcolor="#171A1F"' in dot
    assert 'fontcolor="#F0F3F7"' in dot


def test_workbench_dot_wraps_long_rpm_labels() -> None:
    dot = workbench_graph_to_dot(build_synthetic_fixture_graph())

    assert "binary rpm\\nsynthetic-core" in dot
    assert ".x86_64.rpm" not in dot

"""Headless smoke test for the PyQt workbench main window.

`gui/qt_app.py` is the largest GUI module and carried no direct tests (the
analysable logic lives in the well-covered `services/` layer). This drives the
real construction + result-handling + slice-rendering + inspector paths once,
headless (``QT_QPA_PLATFORM=offscreen`` is pinned by conftest), so a crash on
those paths is caught and the file is no longer at 0% coverage.

No network and no Graphviz are required: the analysis runs on the bundled
synthetic fixture with an empty pipeline, and the SVG renderer degrades to a
built-in fallback when ``dot`` is absent.
"""

from __future__ import annotations

import pytest
from PyQt5 import QtWidgets

from albs_graph.fixtures import SYNTHETIC_RPM_ID, build_synthetic_fixture_graph
from albs_graph.gui.qt_app import WorkbenchWindow
from albs_graph.pipeline import AnalysisPipeline, RunSpec
from albs_graph.services import AnalysisResult, AnalysisService


@pytest.fixture(scope="module")
def qapp() -> QtWidgets.QApplication:
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def _fixture_result() -> AnalysisResult:
    graph = build_synthetic_fixture_graph()
    return AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze_graph(graph, RunSpec())


def test_workbench_window_constructs_and_handles_a_result(
    qapp: QtWidgets.QApplication,
) -> None:
    window = WorkbenchWindow()
    try:
        result = _fixture_result()
        # Drives _populate_* (artifacts / findings / coverage / evidence /
        # source / query / timeline / recipes) and auto-selects the first
        # artifact, which renders a focused slice.
        window._analysis_finished(result)
        qapp.processEvents()

        assert window.result is result
        assert window.artifact_list.count() > 0
        assert window.current_slice is not None       # a slice was rendered
        assert window.coverage_table.rowCount() > 0    # coverage table populated
        assert window.current_svg                      # an SVG string was produced
    finally:
        window.close()


def test_workbench_node_inspect_and_mode_switches(qapp: QtWidgets.QApplication) -> None:
    window = WorkbenchWindow()
    try:
        window._analysis_finished(_fixture_result())

        # Select the core RPM, then inspect it -- now it is in the current slice,
        # so the inspector binds it as the selected node.
        assert window._select_artifact(SYNTHETIC_RPM_ID) is True
        qapp.processEvents()
        window._show_node(SYNTHETIC_RPM_ID)
        assert window.selected_node_id == SYNTHETIC_RPM_ID
        assert window.summary_table.rowCount() > 0     # inspector summary filled

        # Every investigation mode renders without crashing for this artifact.
        for mode in ("Dependency Evidence", "Security Context", "Node Neighborhood", "Trust Path"):
            window.mode_combo.setCurrentText(mode)
            qapp.processEvents()
            assert window.current_slice is not None
    finally:
        window.close()

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

from pathlib import Path

import pytest
from PyQt5 import QtWidgets

from albs_graph.fixtures import SYNTHETIC_RPM_ID, build_synthetic_fixture_graph
from albs_graph.gui.qt_app import WorkbenchWindow
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.pipeline import AnalysisPipeline, RunSpec
from albs_graph.provenance import universe_from_dot
from albs_graph.services import AnalysisResult, AnalysisService, GraphLoadSpec
from albs_graph.store import save_graph


@pytest.fixture(scope="module")
def qapp() -> QtWidgets.QApplication:
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.fixture(autouse=True)
def _no_modal_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    # Modal message boxes would block a headless run forever; stub them so any
    # error/info path returns immediately.
    for name in ("warning", "information", "critical", "question", "about"):
        monkeypatch.setattr(
            QtWidgets.QMessageBox, name, lambda *args, **kwargs: QtWidgets.QMessageBox.Ok
        )


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
        assert window.security_panel.table.rowCount() > 0  # M3 security panel populated
        assert window.current_svg                      # an SVG string was produced

        # M2 dependency panel: toggling the filters re-runs _populate without
        # crashing (the synthetic fixture has no resolved deps, so 0 rows is OK).
        window.dep_only_conflicts.setChecked(True)
        window.dep_scope_combo.setCurrentIndex(1)
        qapp.processEvents()
        assert window.dependency_table.rowCount() >= 0
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


def test_workbench_errata_toggle_feeds_run_spec(
    qapp: QtWidgets.QApplication, tmp_path: Path
) -> None:
    window = WorkbenchWindow()
    try:
        # A source with no build id -> the build-SBOM autofill is a no-op, so no
        # network or disk discovery runs while we exercise the errata toggle.
        load_spec = GraphLoadSpec(source=tmp_path / "graph.json")

        # Off (default) -> the RunSpec carries no errata source at all.
        spec = window._run_spec(load_spec)
        assert spec.errata_source is None
        assert spec.errata_feed is None
        assert spec.errata_url is None

        # http + an existing feed file -> the offline feed path wins.
        feed = tmp_path / "errata.full.json"
        feed.write_text("[]", encoding="utf-8")
        window._set_errata_source("http")
        window.errata_feed_edit.setText(str(feed))
        spec = window._run_spec(load_spec)
        assert spec.errata_source == "http"
        assert spec.errata_feed == feed
        assert spec.errata_url is None

        # http + a non-path value -> treated as a live feed URL.
        url = "https://errata.almalinux.org/10/errata.full.json"
        window.errata_feed_edit.setText(url)
        spec = window._run_spec(load_spec)
        assert spec.errata_source == "http"
        assert spec.errata_feed is None
        assert spec.errata_url == url

        # dnf -> host updateinfo source, no feed/url needed.
        window._set_errata_source("dnf")
        spec = window._run_spec(load_spec)
        assert spec.errata_source == "dnf"
        assert spec.errata_feed is None
        assert spec.errata_url is None

        # The toggle round-trips through a saved session.
        session = window._current_session()
        assert session.errata_source == "dnf"
        window._set_errata_source("")
        window._apply_session(session)
        assert str(window.errata_combo.currentData() or "") == "dnf"
    finally:
        window.close()


def test_workbench_exports_markdown_and_png(
    qapp: QtWidgets.QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = WorkbenchWindow()
    try:
        window._analysis_finished(_fixture_result())
        qapp.processEvents()

        md_path = tmp_path / "report.md"
        monkeypatch.setattr(
            QtWidgets.QFileDialog,
            "getSaveFileName",
            lambda *args, **kwargs: (str(md_path), ""),
        )
        window.export_markdown_report()
        assert md_path.exists()
        assert "ALBS Provenance Investigation Report" in md_path.read_text(encoding="utf-8")

        png_path = tmp_path / "slice.png"
        monkeypatch.setattr(
            QtWidgets.QFileDialog,
            "getSaveFileName",
            lambda *args, **kwargs: (str(png_path), ""),
        )
        window.export_png()
        assert png_path.exists() and png_path.stat().st_size > 0
    finally:
        window.close()


def test_workbench_session_captures_dependency_and_universe_state(
    qapp: QtWidgets.QApplication, tmp_path: Path
) -> None:
    dot = 'digraph g { "nginx-core" -> "glibc"; }'
    db = tmp_path / "universe.db"
    save_graph(universe_from_dot(dot), db)

    window = WorkbenchWindow()
    try:
        window.dep_scope_combo.setCurrentIndex(window.dep_scope_combo.findData("build"))
        window.dep_only_conflicts.setChecked(True)
        window.universe_panel.open_store(str(db))
        window.universe_panel.focus = "nginx-core"
        window.universe_panel._save_favourite()

        session = window._current_session()
        assert session.dep_scope == "build"
        assert session.dep_only_conflicts is True
        assert session.universe_store == str(db)
        assert session.universe_favourites  # the saved favourite round-trips

        # Restoring a session rebuilds the favourites combo + dependency filters.
        window.dep_only_conflicts.setChecked(False)
        window._set_dep_scope(session.dep_scope)
        window.universe_panel.restore(session.universe_store, session.universe_favourites)
        assert str(window.dep_scope_combo.currentData() or "") == "build"
        assert window.universe_panel.fav_combo.count() >= 2
    finally:
        window.close()


def test_workbench_cpe_verify_run_spec_and_cve_feed_panel(
    qapp: QtWidgets.QApplication, tmp_path: Path
) -> None:
    window = WorkbenchWindow()
    try:
        load_spec = GraphLoadSpec(source=tmp_path / "graph.json")

        # CPE dict: an existing path -> verify_cpe; otherwise -> verify_cpe_url.
        cpe_dict = tmp_path / "cpe.json"
        cpe_dict.write_text("[]", encoding="utf-8")
        window.cpe_dict_edit.setText(str(cpe_dict))
        assert window._run_spec(load_spec).verify_cpe == cpe_dict
        window.cpe_dict_edit.setText("https://example.org/cpe.json")
        spec = window._run_spec(load_spec)
        assert spec.verify_cpe is None
        assert spec.verify_cpe_url == "https://example.org/cpe.json"

        # CVE feed: a result with a resolved CPE + a feed file -> the Security
        # panel's Potential CVEs column populates (live, report-time).
        feed = tmp_path / "cve.json"
        feed.write_text(
            '{"cves":[{"id":"CVE-2024-7777","affected":'
            '[{"vendor":"nginx","product":"nginx","introduced":"1.0.0","fixed":"1.30.0"}]}]}',
            encoding="utf-8",
        )
        graph = ProvenanceGraph()
        graph.add_node(
            Node(
                "rpm:nginx-core:x86_64",
                NodeType.BINARY_RPM,
                "nginx-core",
                {
                    "name": "nginx-core", "arch": "x86_64", "version": "1.20.0",
                    "security_identity": {
                        "cpe": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*",
                        "cpe_status": "verified", "cpe_candidates": [],
                    },
                },
            )
        )
        result = AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze_graph(graph, RunSpec())
        window.cve_feed_edit.setText(str(feed))
        window._analysis_finished(result)
        qapp.processEvents()

        # Find the nginx-core row and read its Potential CVEs cell (column 7).
        table = window.security_panel.table
        potentials = [
            table.item(row, 7).text()
            for row in range(table.rowCount())
            if table.item(row, 0).text() == "nginx-core"
        ]
        assert potentials and "CVE-2024-7777" in potentials[0]
    finally:
        window.close()


def test_workbench_universe_panel_open_search_traverse_paths(
    qapp: QtWidgets.QApplication, tmp_path: Path
) -> None:
    dot = (
        'digraph g { "nginx-core" -> "openssl-libs"; '
        '"nginx-core" -> "glibc"; "openssl-libs" -> "glibc"; }'
    )
    db = tmp_path / "universe.db"
    save_graph(universe_from_dot(dot), db)

    window = WorkbenchWindow()
    try:
        # Open the store (path given -> no file dialog) and auto-search.
        panel = window.universe_panel
        panel.open_store(str(db))
        qapp.processEvents()
        assert panel.store is not None
        assert panel.packages_table.rowCount() > 0

        labels = [
            panel.packages_table.item(row, 1).text()
            for row in range(panel.packages_table.rowCount())
        ]
        panel.packages_table.setCurrentCell(labels.index("nginx-core"), 0)
        qapp.processEvents()
        assert panel.focus == "nginx-core"

        # Walk one-hop dependencies of the focus.
        panel._traverse("dependencies")
        deps = [
            panel.results_table.item(row, 1).text()
            for row in range(panel.results_table.rowCount())
        ]
        assert "glibc" in deps

        # Find dependency paths to glibc (direct + via openssl-libs).
        panel.target_edit.setText("glibc")
        panel._find_paths()
        assert panel.results_table.rowCount() > 0

        # Save then re-apply a favourite query.
        panel._save_favourite()
        assert panel.fav_combo.count() >= 2
        panel._apply_favourite(panel.fav_combo.count() - 1)
        qapp.processEvents()
    finally:
        window.close()


def test_workbench_drives_read_only_interactions(qapp: QtWidgets.QApplication) -> None:
    window = WorkbenchWindow()
    try:
        window._analysis_finished(_fixture_result())
        qapp.processEvents()
        assert window._select_artifact(SYNTHETIC_RPM_ID) is True
        qapp.processEvents()

        # Timeline Tree <-> Gantt view switch.
        window.timeline_view_combo.setCurrentText("Gantt")
        window.timeline_view_combo.setCurrentText("Tree")
        qapp.processEvents()

        # Toggling a graph layer re-renders the current slice.
        if "build" in window.layer_actions:
            window.layer_actions["build"].trigger()
            window.layer_actions["build"].trigger()
            qapp.processEvents()
        assert window.current_slice is not None

        # Graph search + zoom controls.
        window.graph_search_edit.setText("nginx")
        window.search_current_graph()
        window.zoom_in_graph()
        window.zoom_out_graph()
        window.fit_graph()
        window.reset_graph_zoom()
        qapp.processEvents()

        # Run the selected graph query.
        window._run_selected_query()
        qapp.processEvents()
        assert window.query_table.rowCount() >= 0

        # Finding drill-down.
        if window.findings_table.rowCount():
            window._finding_activated(window.findings_table.item(0, 0))
            qapp.processEvents()
            assert window.finding_detail_table.rowCount() >= 0

        # Apply an investigation recipe (index 0 is the "Recipes" placeholder).
        if window.recipe_combo.count() > 1:
            window._recipe_activated(1)
            qapp.processEvents()

        # Inspect an edge of the current slice.
        if window.current_slice is not None and window.current_slice.graph.edges:
            window._show_edge(0, from_slice=True)
            qapp.processEvents()

        # Artifact filter.
        window.artifact_filter.setText("nginx")
        window._filter_artifacts("nginx")
        window.artifact_filter.setText("")
        window._filter_artifacts("")
        qapp.processEvents()
        assert window.result is not None
    finally:
        window.close()


def test_workbench_exports_bundle_and_html(
    qapp: QtWidgets.QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = WorkbenchWindow()
    try:
        window._analysis_finished(_fixture_result())
        qapp.processEvents()
        for filename, export in (
            ("bundle.json", window.export_bundle),
            ("report.html", window.export_html_report),
        ):
            out = tmp_path / filename
            monkeypatch.setattr(
                QtWidgets.QFileDialog, "getSaveFileName", lambda *a, _o=out, **k: (str(_o), "")
            )
            export()
            assert out.exists() and out.stat().st_size > 0
    finally:
        window.close()


def test_workbench_save_session_writes_a_loadable_file(
    qapp: QtWidgets.QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from albs_graph.services import WorkbenchSession

    window = WorkbenchWindow()
    try:
        window._analysis_finished(_fixture_result())
        qapp.processEvents()
        window._select_artifact(SYNTHETIC_RPM_ID)
        window.errata_feed_edit.setText("feed.json")
        window.dep_scope_combo.setCurrentIndex(window.dep_scope_combo.findData("build"))

        session_file = tmp_path / "session.json"
        monkeypatch.setattr(
            QtWidgets.QFileDialog, "getSaveFileName", lambda *a, **k: (str(session_file), "")
        )
        window.save_session()

        assert session_file.exists()
        restored = WorkbenchSession.load(session_file)
        assert restored.errata_feed == "feed.json"
        assert restored.dep_scope == "build"
        assert restored.selected_artifact_id == SYNTHETIC_RPM_ID
    finally:
        window.close()

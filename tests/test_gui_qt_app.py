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

import os
import time
from pathlib import Path

import pytest
from PyQt5 import QtCore, QtWidgets

from albs_graph.adapters.albs import BuildSummary
from albs_graph.fixtures import SYNTHETIC_RPM_ID, build_synthetic_fixture_graph
from albs_graph.gui.hitmap import NodeRegion
from albs_graph.gui.qt_app import ConsoleProcessDialog, GraphSvgWidget, WorkbenchWindow
from albs_graph.model import Node, NodeType, ProvenanceGraph
from albs_graph.pipeline import AnalysisPipeline, RunSpec
from albs_graph.provenance import universe_from_dot
from albs_graph.services import AnalysisResult, AnalysisService, GraphLoadSpec
from albs_graph.store import save_graph


@pytest.fixture(scope="module")
def qapp() -> QtWidgets.QApplication:
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def test_inspect_binary_host_gating(monkeypatch: pytest.MonkeyPatch) -> None:
    # The Inspect Binary action is enabled only on an AlmaLinux / RHEL-family
    # host with rpm; elsewhere (macOS / CI) it greys out.
    from albs_graph.gui import qt_app

    assert qt_app._EL_FAMILY_IDS & qt_app._os_release_ids('ID="almalinux"\nID_LIKE="rhel"\n')
    assert qt_app._EL_FAMILY_IDS & qt_app._os_release_ids("ID=rhel\n")
    assert not (qt_app._EL_FAMILY_IDS & qt_app._os_release_ids("ID=ubuntu\nID_LIKE=debian\n"))
    # No rpm on PATH -> not a host RPM box, regardless of os-release.
    monkeypatch.setattr(qt_app.shutil, "which", lambda _name: None)
    assert qt_app._is_almalinux_family_host() is False


@pytest.fixture(autouse=True)
def _no_modal_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    # Modal message boxes would block a headless run forever; stub them so any
    # error/info path returns immediately.
    for name in ("warning", "information", "critical", "question", "about"):
        monkeypatch.setattr(
            QtWidgets.QMessageBox, name, lambda *args, **kwargs: QtWidgets.QMessageBox.Ok
        )


@pytest.fixture(autouse=True)
def _isolate_cache(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Keep the build-catalog / http-cache writes (D120) out of the real ~/.cache
    # so analysing a build in a test never touches the developer's machine.
    monkeypatch.setenv("ALBS_HTTP_CACHE", str(tmp_path_factory.mktemp("albs-cache")))


@pytest.fixture(autouse=True)
def _isolate_qsettings(tmp_path_factory: pytest.TempPathFactory) -> None:
    # Keep the window-geometry persistence (QSettings, D132) out of the real user
    # preferences by redirecting the IniFormat/UserScope store to a temp dir.
    QtCore.QSettings.setPath(
        QtCore.QSettings.Format.IniFormat,
        QtCore.QSettings.Scope.UserScope,
        str(tmp_path_factory.mktemp("qsettings")),
    )


@pytest.fixture(autouse=True)
def _baseline_host(monkeypatch: pytest.MonkeyPatch) -> None:
    # Deterministic host at window construction: no host tools on PATH, so the
    # CAS / AlmaLinux badges (D125) and the real _is_almalinux_family_host stay
    # absent regardless of the CI box (e.g. the AlmaLinux VPS). Tests that need a
    # host tool / AlmaLinux override these afterwards.
    from albs_graph.gui import qt_app

    monkeypatch.setattr(qt_app.shutil, "which", lambda _name: None)


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

        # M2 dependency panel: toggling the filters re-renders without crashing
        # (the synthetic fixture has no resolved deps, so 0 rows is OK).
        window.dependency_panel.populate(result.graph)
        window.dependency_panel.only_conflicts.setChecked(True)
        window.dependency_panel.scope_combo.setCurrentIndex(1)
        qapp.processEvents()
        assert window.dependency_panel.table.rowCount() >= 0
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


def test_workbench_mismatched_sbom_does_not_block_analysis(
    qapp: QtWidgets.QApplication, tmp_path: Path
) -> None:
    # Regression: a build SBOM for a different build raised a modal that blocked
    # the whole analysis (so e.g. an errata re-run never happened). Now the
    # mismatched SBOM is dropped with a log note and the build is analysed.
    window = WorkbenchWindow()
    try:
        sbom = tmp_path / "build-57810.cyclonedx.json"
        sbom.write_text("{}", encoding="utf-8")
        window.build_id_edit.setText("57812")  # current build...
        window.build_sbom_edit.setText(str(sbom))  # ...SBOM is for 57810
        window._set_errata_source("http")

        spec = window._run_spec(GraphLoadSpec(build_id=57812))

        assert spec.build_sbom is None  # the 57810 SBOM was dropped, not fatal
        assert spec.errata_source == "http"  # the analysis (with errata) proceeds
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
        window.dependency_panel.restore("build", True, False)
        window.universe_panel.open_store(str(db))
        window.universe_panel.focus = "nginx-core"
        window.universe_panel._save_favourite()

        session = window._current_session()
        assert session.dep_scope == "build"
        assert session.dep_only_conflicts is True
        assert session.universe_store == str(db)
        assert session.universe_favourites  # the saved favourite round-trips

        # Restoring a session rebuilds the favourites combo + dependency filters.
        window.dependency_panel.restore("", False, False)
        window.dependency_panel.restore(session.dep_scope, session.dep_only_conflicts, False)
        window.universe_panel.restore(session.universe_store, session.universe_favourites)
        assert str(window.dependency_panel.scope_combo.currentData() or "") == "build"
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


def test_workbench_security_inputs_live_on_a_second_toolbar(
    qapp: QtWidgets.QApplication,
) -> None:
    # Regression: the errata/CPE/CVE feed inputs overflowed the single toolbar
    # into the ">>" extension menu. They now live on a separate toolbar row so
    # the primary inputs above never overflow.
    window = WorkbenchWindow()
    try:
        toolbars = window.findChildren(QtWidgets.QToolBar)
        assert len(toolbars) >= 2  # primary + security-sources rows
        owners = {id(tb): tb for tb in toolbars}
        build_id_tb = id(window.build_id_edit.parent())
        cve_tb = id(window.cve_feed_edit.parent())
        # The CVE feed input is not on the same toolbar as the build-id input.
        assert build_id_tb in owners and cve_tb in owners
        assert build_id_tb != cve_tb
    finally:
        window.close()


def test_workbench_loads_a_real_build_json_into_artifacts(
    qapp: QtWidgets.QApplication,
) -> None:
    # Regression: loading a build JSON did not populate the artifact list. Here
    # a real cached build loads into its actual RPMs (not the synthetic fixture),
    # and "load source" drops a stale build id so it cannot shadow the file.
    fixture = Path(__file__).resolve().parents[1] / "examples/live-build-17812/build-17812.albs.json"
    assert fixture.exists()

    window = WorkbenchWindow()
    try:
        window.source_edit.setText(str(fixture))
        window.build_id_edit.setText("999")  # a stale id the source must override
        window._analyze_source()
        assert window.build_id_edit.text() == ""  # source wins, stale id dropped

        # The analysis runs on a worker thread; wait for it, then deliver the
        # finished signal on the main thread.
        window.thread_pool.waitForDone(10000)
        qapp.processEvents()

        assert window.artifact_list.count() > 0
        labels = [window.artifact_list.item(i).text() for i in range(window.artifact_list.count())]
        assert any("nginx" in label for label in labels)  # real build, not synthetic
        assert not any("synthetic" in label for label in labels)
    finally:
        window.close()


def test_source_badges_reflect_cache_state(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The ALBS/ERRATA/SBOM badges are persistent, clickable QToolButtons; the
    # ALBS badge greys out unless the build's metadata cache is fresh (D114).
    from albs_graph.gui import qt_app

    cache = tmp_path / "build-57810.albs.json"
    cache.write_text('{"id": 57810}', encoding="utf-8")
    assert qt_app._cache_file_state(cache, 300, "57810") == "active"
    aged = time.time() - 10_000
    os.utime(cache, (aged, aged))
    assert qt_app._cache_file_state(cache, 300, "57810") == "stale"  # older than the TTL
    assert qt_app._cache_file_state(cache, 300, "999") == "missing"  # wrong build id
    assert qt_app._cache_file_state(tmp_path / "absent.json", 300, "57810") == "missing"

    window = WorkbenchWindow()
    try:
        assert set(window._source_badges) == {"ALBS", "ERRATA", "SBOM"}
        assert all(isinstance(b, QtWidgets.QToolButton) for b in window._source_badges.values())

        fresh = tmp_path / "build-57810" / "build-57810.albs.json"
        fresh.parent.mkdir(parents=True)
        fresh.write_text('{"id": 57810}', encoding="utf-8")
        monkeypatch.setattr(window, "_workbench_cache_path", lambda _bid: fresh)
        state, uri = window._source_state("ALBS", "57810")
        assert state == "active"
        assert "57810" in uri  # live ALBS build URL on hover
        assert window._source_state("ALBS", None)[0] == "missing"  # nothing to fetch yet
    finally:
        window.close()


def test_source_badge_click_fetches_for_build_id(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Clicking a badge fetches just that resource for the current build id; with
    # no build id it errors rather than hitting the network. Build id + Enter
    # turns every source on for a single sweeping fetch (D114).
    from albs_graph.gui import qt_app

    window = WorkbenchWindow()
    try:
        # Force the non-AlmaLinux errata default (http) so the assertions are
        # host-independent (on an AlmaLinux CI box the default would be dnf).
        monkeypatch.setattr(qt_app, "_is_almalinux_family_host", lambda: False)
        runs: list[bool] = []
        errors: list[str] = []
        monkeypatch.setattr(window, "run_analysis", lambda: runs.append(True))
        monkeypatch.setattr(window, "_show_error", lambda message: errors.append(message))

        window._fetch_source("ERRATA")
        assert runs == [] and errors  # no build id -> guarded, no run

        window.build_id_edit.setText("57810")
        window._fetch_source("ERRATA")
        assert window.errata_combo.currentData() == "http"  # this one source turned on
        assert runs == [True]

        window._fetch_source("ALBS")
        assert window._pending_refresh is True  # forces a metadata refetch
        assert runs == [True, True]

        window.errata_combo.setCurrentIndex(window.errata_combo.findData(""))
        window._fetch_all_sources()  # Enter in the build-id field
        assert window.errata_combo.currentData() == "http"
        # Fetch-all enables the host-available enrichments in addition to errata.
        assert window._deep_fetch is True
        assert runs == [True, True, True]
    finally:
        window.close()


def test_fetch_all_enables_host_enrichments_in_run_spec(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A build-id fetch-all merges the host-available enrichments into the
    # RunSpec (RPM headers always; dnf/sonames/cas gated on the host tool), then
    # clears the one-shot flag so a later plain run stays light.
    from albs_graph.gui import qt_app

    window = WorkbenchWindow()
    try:
        monkeypatch.setattr(qt_app.shutil, "which", lambda name: f"/usr/bin/{name}")
        window.build_id_edit.setText("57810")
        window._deep_fetch = True
        spec = window._run_spec(window._load_spec())
        assert spec.with_rpm_headers and spec.use_dnf and spec.resolve_sonames and spec.use_cas
        assert window._deep_fetch is False  # one-shot, reset after building the spec

        # No host tools -> only the network-light header rung is enabled.
        monkeypatch.setattr(qt_app.shutil, "which", lambda _name: None)
        window._deep_fetch = True
        light = window._run_spec(window._load_spec())
        assert light.with_rpm_headers and not light.use_dnf and not light.use_cas
    finally:
        window.close()


def test_timeline_tree_first_column_does_not_overlap(qapp: QtWidgets.QApplication) -> None:
    # Regression (D124): long "Stage" labels overflowed into "Status". Column 0
    # auto-fits its content and text elides, so columns never overlap.
    window = WorkbenchWindow()
    try:
        tree = window.timeline_panel.tree
        header = tree.header()
        assert (
            header.sectionResizeMode(0)
            == QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        assert tree.textElideMode() == QtCore.Qt.TextElideMode.ElideRight
    finally:
        window.close()


def test_clicking_a_node_reveals_it_in_the_timeline(qapp: QtWidgets.QApplication) -> None:
    # Clicking a graph node selects + scrolls the tree, switches to the Gantt
    # sub-view, records the Gantt scroll, and brings the Timeline tab forward so
    # the scroll is actually visible (D124/D127).
    window = WorkbenchWindow()
    try:
        window._analysis_finished(_fixture_result())
        qapp.processEvents()
        panel = window.timeline_panel

        assert panel.reveal_node("build:albs:123456") is True  # a fixture timeline row
        current = panel.tree.currentItem()
        assert current is not None
        assert str(current.data(0, QtCore.Qt.ItemDataRole.UserRole)) == "build:albs:123456"
        # The Gantt sub-view is shown and the scroll target recorded (re-applied
        # on show/resize so it lands even if the Gantt was hidden at click time).
        assert panel.view_combo.currentText() == "Gantt"
        assert panel.gantt._pending_node == "build:albs:123456"

        assert panel.reveal_node("rpm:not-on-timeline") is False  # no hit, no crash
        # Clicking a timeline node via the wired path brings the Timeline tab up.
        window.output_tabs.setCurrentWidget(window.findings_table)
        window._graph_node_clicked("build:albs:123456")
        assert window.output_tabs.currentWidget() is window.timeline_panel
        window._graph_node_clicked(SYNTHETIC_RPM_ID)  # off-timeline node: safe, no switch
    finally:
        window.close()


def test_timeline_view_combo_is_not_clipped(qapp: QtWidgets.QApplication) -> None:
    # Regression: the Tree/Gantt switch rendered clipped to "Ga" in a narrow
    # dock; it needs a minimum width wide enough for its longest item.
    window = WorkbenchWindow()
    try:
        combo = window.timeline_panel.view_combo
        assert [combo.itemText(i) for i in range(combo.count())] == ["Tree", "Gantt"]
        assert combo.minimumWidth() >= combo.fontMetrics().horizontalAdvance("Gantt")
    finally:
        window.close()


def test_gantt_duration_scale_fits_the_majority_and_flags_clips() -> None:
    # The Gantt time scale is a high percentile of the durations, so a few long
    # tasks cannot squash the short majority into invisible slivers; the long
    # tail is reported as clipped instead (D130).
    from albs_graph.gui.timeline_panel import _duration_scale
    from albs_graph.services import TimelineGanttRow

    def row(duration: float) -> TimelineGanttRow:
        return TimelineGanttRow(0, "build_step", "step", "", "", "", 0.0, duration)

    cap, actual_max, clipped = _duration_scale([row(10.0)] * 9 + [row(1000.0)])
    assert cap == 10.0  # scale fits the short bulk, not the 1000s outlier
    assert actual_max == 1000.0
    assert clipped == 1  # the long task clips

    cap, _actual, clipped = _duration_scale([row(30.0)] * 5)
    assert cap == 30.0 and clipped == 0  # uniform durations: nothing clips

    cap, _actual, clipped = _duration_scale([row(0.0), row(0.0)])
    assert cap == 1.0 and clipped == 0  # no timing: a safe non-zero cap


def test_gantt_elides_long_stage_names(qapp: QtWidgets.QApplication) -> None:
    # A long stage name is right-elided to its budget so it can never overwrite
    # the status column; a short name that fits is left untouched (D130).
    from albs_graph.gui.timeline_panel import _elided_text_item

    scene = QtWidgets.QGraphicsScene()
    long_name = "build_done_stats.packages_processing_with_a_very_long_trailing_name"
    elided = _elided_text_item(scene, long_name, 60)
    assert elided.toPlainText() != long_name
    assert elided.toPlainText().endswith("…")
    assert _elided_text_item(scene, "ok", 200).toPlainText() == "ok"


def test_gantt_columns_do_not_overlap_and_bars_stay_in_band(
    qapp: QtWidgets.QApplication,
) -> None:
    # Regression: long stage names used to bleed into the status column, and the
    # bars overran the canvas. The name items must stay left of the status column
    # and every bar must clip within the timeline band (D130).
    from albs_graph.gui import timeline_panel as tp

    window = WorkbenchWindow()
    try:
        window._analysis_finished(_fixture_result())
        qapp.processEvents()
        gantt = window.timeline_panel.gantt
        gantt._relayout()
        band_right = tp._BARS_LEFT + gantt._timeline_width()
        names = [
            item
            for item in gantt._scene.items()
            if isinstance(item, QtWidgets.QGraphicsTextItem)
            and abs(item.pos().x() - tp._NAME_X) < 0.5
            and item.pos().y() > tp._TOP  # exclude the top-of-axis clamp note
        ]
        assert names  # the fixture timeline produced rows
        for item in names:
            assert item.pos().x() + item.boundingRect().width() <= tp._DETAIL_X + 1
        bars = [
            item
            for item in gantt._scene.items()
            if isinstance(item, QtWidgets.QGraphicsPathItem)
        ]
        assert bars
        for bar in bars:
            assert bar.sceneBoundingRect().right() <= band_right + 1
    finally:
        window.close()


def test_timeline_defaults_to_the_gantt_view(qapp: QtWidgets.QApplication) -> None:
    # The Gantt is the default sub-view, so the graph<->timeline jump lands on it
    # straight away; the Tree stays one click away (D131).
    window = WorkbenchWindow()
    try:
        panel = window.timeline_panel
        assert panel.view_combo.currentText() == "Gantt"
        assert panel.stack.currentWidget() is panel.gantt
    finally:
        window.close()


def test_gantt_clip_note_does_not_overlap_the_axis_labels(
    qapp: QtWidgets.QApplication,
) -> None:
    # Regression (D131): the "scale fitted to … clipped" note shared the top band
    # with the axis tick labels and overwrote "0.00s". It now sits on its own top
    # line, clear of the ticks.
    from albs_graph.gui import timeline_panel as tp
    from albs_graph.services import TimelineGanttRow

    def row(duration: float) -> TimelineGanttRow:
        return TimelineGanttRow(0, "build_step", "step", "", "", "", 0.0, duration)

    view = tp.TimelineGanttView()
    view._rows = [row(10.0)] * 9 + [row(1000.0)]  # forces a clip -> the note shows
    view._relayout()
    texts = [
        item for item in view._scene.items() if isinstance(item, QtWidgets.QGraphicsTextItem)
    ]
    notes = [t for t in texts if t.toPlainText().startswith("scale fitted")]
    ticks = [
        t for t in texts if t.pos().y() < tp._TOP and t.toPlainText().rstrip("+").endswith("s")
    ]
    assert notes and ticks
    note_rect = notes[0].sceneBoundingRect()
    for tick in ticks:
        assert not note_rect.intersects(tick.sceneBoundingRect())


def test_status_bar_shows_a_step_counter_during_analysis(
    qapp: QtWidgets.QApplication,
) -> None:
    # The status bar gets a live step counter from the progress stream (D131), so
    # a long fetch shows movement instead of a frozen "Analyzing…".
    window = WorkbenchWindow()
    try:
        window._analysis_step_count = 0
        window._analysis_progress("Loading ALBS build metadata")
        window._analysis_progress("build SBOM matched 456 RPMs")
        text = window.progress_label.text()
        assert "step 2" in text
        assert "456 RPMs" in text
    finally:
        window.close()


def test_window_geometry_persists_across_instances(qapp: QtWidgets.QApplication) -> None:
    # The window size is saved on close and restored by the next instance (D132).
    # _isolate_qsettings redirects QSettings to a temp dir, so this never touches
    # the real user preferences.
    first = WorkbenchWindow()
    first.resize(1280, 800)
    expected = first.size()
    assert expected != QtCore.QSize(1500, 930)  # the resize actually took effect
    first.close()  # closeEvent persists the geometry
    saved = first._settings.value("geometry")
    assert isinstance(saved, QtCore.QByteArray) and not saved.isEmpty()

    second = WorkbenchWindow()
    try:
        assert second.size() == expected  # restored from the saved geometry
    finally:
        second.close()


def test_timeline_gantt_filter_keeps_only_matching_rows(qapp: QtWidgets.QApplication) -> None:
    # The Gantt filter is a case-insensitive, trimmed substring over the row's
    # label/status/kind/node/detail (D133).
    from albs_graph.gui import timeline_panel as tp
    from albs_graph.services import TimelineGanttRow

    def row(label: str) -> TimelineGanttRow:
        return TimelineGanttRow(0, "build_step", label, "", "", "", 0.0, 10.0)

    view = tp.TimelineGanttView()
    view._rows = [row("compile glibc"), row("link nginx core"), row("sign rpm")]
    view.set_filter("nginx")
    assert [r.label for r in view._visible_rows()] == ["link nginx core"]
    view.set_filter("  GLIBC ")  # case-insensitive + trimmed
    assert [r.label for r in view._visible_rows()] == ["compile glibc"]
    view.set_filter("")
    assert len(view._visible_rows()) == 3


def test_timeline_search_filters_both_views(qapp: QtWidgets.QApplication) -> None:
    # The header search box (left of the Gantt/Tree combo) filters both views to
    # the matching rows; clearing it restores everything (D133).
    window = WorkbenchWindow()
    try:
        window._analysis_finished(_fixture_result())
        qapp.processEvents()
        panel = window.timeline_panel
        total = len(panel.gantt._rows)
        assert total > 0
        # No match: every Gantt row and every top-level tree row is hidden.
        panel.search.setText("zzz-no-such-row")
        assert panel.gantt._visible_rows() == []
        assert all(
            panel.tree.topLevelItem(i).isHidden()
            for i in range(panel.tree.topLevelItemCount())
        )
        # Clearing restores both views.
        panel.search.clear()
        assert len(panel.gantt._visible_rows()) == total
        assert not panel.tree.topLevelItem(0).isHidden()
    finally:
        window.close()


def test_primary_analyze_is_context_sensitive(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The Analyze button fetches all host sources for a live build id, but for a
    # cached source file (no build id) it just (re)analyses offline -- no deep
    # enrichment, no errata override, so a local file never pulls the network.
    from albs_graph.gui import qt_app

    window = WorkbenchWindow()
    try:
        monkeypatch.setattr(qt_app, "_is_almalinux_family_host", lambda: False)  # http default
        runs: list[bool] = []
        monkeypatch.setattr(window, "run_analysis", lambda: runs.append(True))

        window.build_id_edit.setText("57810")
        window._analyze_or_fetch_all()
        assert window._deep_fetch is True  # build id -> fetch-all
        assert window.errata_combo.currentData() == "http"

        window.build_id_edit.clear()
        window.source_edit.setText("/tmp/build-57810.albs.json")
        window.errata_combo.setCurrentIndex(window.errata_combo.findData(""))
        window._deep_fetch = False
        window._analyze_or_fetch_all()
        assert window._deep_fetch is False  # cached file -> plain offline run
        assert window.errata_combo.currentData() == ""  # errata not overridden
        assert runs == [True, True]
    finally:
        window.close()


def test_errata_default_source_is_host_aware(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Errata defaults to dnf on an AlmaLinux-family host (local updateinfo is
    # authoritative) and to the errata.almalinux.org http feed elsewhere.
    from albs_graph.gui import qt_app

    window = WorkbenchWindow()
    try:
        monkeypatch.setattr(qt_app.shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(qt_app, "_is_almalinux_family_host", lambda: True)
        assert window._default_errata_source() == "dnf"

        monkeypatch.setattr(qt_app, "_is_almalinux_family_host", lambda: False)
        assert window._default_errata_source() == "http"  # non-AlmaLinux host

        monkeypatch.setattr(qt_app.shutil, "which", lambda _name: None)
        monkeypatch.setattr(qt_app, "_is_almalinux_family_host", lambda: True)
        assert window._default_errata_source() == "http"  # no dnf binary -> http

        # _select_default_errata applies that default but respects an explicit pick.
        monkeypatch.setattr(qt_app.shutil, "which", lambda name: f"/usr/bin/{name}")
        window.errata_combo.setCurrentIndex(window.errata_combo.findData(""))
        window._select_default_errata()
        assert window.errata_combo.currentData() == "dnf"
        window.errata_combo.setCurrentIndex(window.errata_combo.findData("http"))
        window._select_default_errata()
        assert window.errata_combo.currentData() == "http"  # explicit choice kept
    finally:
        window.close()


def test_errata_both_cross_check_option_feeds_the_run_spec(
    qapp: QtWidgets.QApplication,
) -> None:
    # The "both (cross-check)" errata option is selectable and drives the RunSpec
    # errata_source="both", still passing the feed-field value to the http side.
    window = WorkbenchWindow()
    try:
        index = window.errata_combo.findData("both")
        assert index >= 0  # the cross-check option exists
        window.errata_combo.setCurrentIndex(index)
        window.errata_feed_edit.setText("https://errata.example/9/errata.full.json")
        kwargs = window._errata_run_kwargs()
        assert kwargs["errata_source"] == "both"
        assert kwargs["errata_url"] == "https://errata.example/9/errata.full.json"
        # The ERRATA badge tooltip reflects the cross-check.
        assert "cross-checked" in window._errata_source_uri()
    finally:
        window.close()


def test_refresh_build_list_populates_catalog_and_completer(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Refresh fetches the last-N recent ALBS builds into the cached catalog and
    # feeds the build-id autocomplete (D120/D121). The fetch is stubbed offline.
    from albs_graph.gui import qt_app

    builds = [
        BuildSummary(build_id=57812, packages=("buildah",), platforms=("AlmaLinux-10",),
                     created_at="2026-05-31T10:00:00"),
        BuildSummary(build_id=57810, packages=("nginx",), platforms=("AlmaLinux-9",),
                     created_at="2026-05-30T09:00:00"),
    ]
    captured: dict[str, object] = {}

    def _fake(_base_url, *, limit, progress=None, on_progress=None):
        captured["limit"] = limit
        if on_progress:
            on_progress(len(builds), limit)  # report a page of progress (D123)
        return builds

    monkeypatch.setattr(qt_app, "fetch_recent_builds", _fake)

    window = WorkbenchWindow()
    try:
        window.refresh_build_list(200)  # the configurable last-N
        assert captured["limit"] == 200
        assert window.build_list_limit == 200  # remembered as the new default
        assert window.build_catalog.build_ids() == [57812, 57810]  # cached
        assert not window._refreshing_builds  # the guard is released
        completions = set(window._build_completer.model().stringList())
        assert {"57812", "57810"} <= completions  # autocomplete now offers them
    finally:
        window.close()


def test_build_fetch_progress_shows_counter_and_percent(qapp: QtWidgets.QApplication) -> None:
    # The status bar shows a live counter + percentage while paging (D123).
    window = WorkbenchWindow()
    try:
        window._build_fetch_progress(30, 100)
        assert window.progress_label.text() == "Fetching builds… 30/100 (30%)"
        window._build_fetch_progress(100, 100)
        assert "100/100 (100%)" in window.progress_label.text()
    finally:
        window.close()


def test_browse_builds_picks_a_catalog_id_and_runs(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Browsing the catalog picks a real build id (no sparse-id guessing) and
    # kicks off the analysis for it.
    window = WorkbenchWindow()
    try:
        window.build_catalog.record(
            BuildSummary(build_id=57810, packages=("buildah",), platforms=("AlmaLinux-10",))
        )
        runs: list[bool] = []
        monkeypatch.setattr(window, "_analyze_or_fetch_all", lambda: runs.append(True))
        monkeypatch.setattr(window, "_pick_build", lambda _builds: "57810")  # the list dialog

        window.browse_builds()

        assert window.build_id_edit.text() == "57810"
        assert window.source_edit.text() == ""  # the build id is the explicit choice
        assert runs == [True]
    finally:
        window.close()


def test_build_picker_dialog_describes_and_filters(qapp: QtWidgets.QApplication) -> None:
    # The picker lists each build with a short description and filters in place.
    from albs_graph.gui.qt_app import _BuildPickerDialog, _describe_build

    builds = [
        BuildSummary(build_id=57812, packages=("buildah", "buildah-tests"),
                     platforms=("AlmaLinux-10",), created_at="2026-05-31T15:24:33", owner="eabd"),
        BuildSummary(build_id=57810, packages=("nginx",), platforms=("AlmaLinux-9",)),
    ]
    described = _describe_build(builds[0])
    assert "57812" in described and "buildah +1" in described
    assert "AlmaLinux-10" in described and "2026-05-31 15:24" in described and "eabd" in described

    dialog = _BuildPickerDialog(builds)
    try:
        assert dialog.list.count() == 2
        dialog.filter_edit.setText("nginx")  # filter in place
        visible = [i for i in range(dialog.list.count()) if not dialog.list.item(i).isHidden()]
        assert len(visible) == 1
        assert dialog.list.item(visible[0]).data(QtCore.Qt.ItemDataRole.UserRole) == "57810"
        dialog.accept()
        assert dialog.selected_build_id == "57810"  # the visible/selected row
    finally:
        dialog.deleteLater()


def test_start_dialog_options_and_dispatch(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The launcher offers each entry point and routes the choice to its method.
    from albs_graph.gui.qt_app import _StartDialog

    window = WorkbenchWindow()
    try:
        targets = [
            "load_session", "inspect_build_id_verified", "browse_builds",
            "open_source", "inspect_binary", "_load_synthetic_demo",
        ]
        calls: list[str] = []
        for name in targets:
            monkeypatch.setattr(window, name, lambda n=name: calls.append(n))
        for choice in ("session", "build_id", "browse", "file", "package", "synthetic"):
            window._dispatch_start_choice(choice)
        assert calls == targets
        window._dispatch_start_choice(None)  # cancel -> no-op
        assert len(calls) == len(targets)

        assert len(_StartDialog.OPTIONS) == 6
        gated = _StartDialog(window, package_enabled=False)
        pkg_button = next(
            b for b in gated.findChildren(QtWidgets.QPushButton)
            if b.text().startswith("Inspect by ALBS package")
        )
        assert not pkg_button.isEnabled()  # host RPM tooling only
    finally:
        window.close()


def test_inspect_build_id_dialog_verifies_before_enabling(qapp: QtWidgets.QApplication) -> None:
    # "Inspect" enables only once a verification succeeds; editing re-locks it.
    from albs_graph.gui.qt_app import _InspectBuildIdDialog

    answers = {"57810": (True, "Verified: 57810 nghttp2"), "57809": (False, "not found")}
    dialog = _InspectBuildIdDialog(lambda build_id: answers[build_id])
    try:
        dialog.build_id_edit.setText("57809")
        dialog.verify_now()
        assert dialog.selected_build_id is None and not dialog._ok.isEnabled()

        dialog.build_id_edit.setText("57810")
        dialog.verify_now()
        assert dialog.selected_build_id == "57810" and dialog._ok.isEnabled()

        dialog.build_id_edit.setText("578101")  # editing invalidates the check
        assert dialog.selected_build_id is None and not dialog._ok.isEnabled()
    finally:
        dialog.deleteLater()


def test_verify_build_id_catalog_then_live(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Verification answers from the cached catalog instantly, else live (and
    # records the result); a 404 is reported as not found (D122).
    from albs_graph.gui import qt_app

    window = WorkbenchWindow()
    try:
        window.build_catalog.record(
            BuildSummary(build_id=57810, packages=("buildah",), created_at="2026-05-20T08:00:00")
        )
        ok, desc = window._verify_build_id("57810")
        assert ok and "buildah" in desc  # catalog hit, no network

        monkeypatch.setattr(
            qt_app,
            "fetch_build_summary",
            lambda bid, base, progress=None: BuildSummary(build_id=int(bid), packages=("nginx",)),
        )
        ok2, desc2 = window._verify_build_id("99999")
        assert ok2 and "nginx" in desc2
        assert 99999 in window.build_catalog.build_ids()  # recorded for next time

        def _missing(bid: int, base: str, progress: object = None) -> BuildSummary:
            raise qt_app.BuildNotFoundError("nope")

        monkeypatch.setattr(qt_app, "fetch_build_summary", _missing)
        ok3, desc3 = window._verify_build_id("12345")
        assert not ok3 and "not found" in desc3.lower()
    finally:
        window.close()


def test_source_badges_show_identifiers(qapp: QtWidgets.QApplication) -> None:
    # Badges name their source's identifier: ALBS always shows the build id;
    # ERRATA/SBOM show their value only when present (D122).
    window = WorkbenchWindow()
    try:
        window.build_id_edit.setText("99999")  # no committed example SBOM for it
        window._refresh_source_badges()
        assert window._source_badges["ALBS"].text() == "ALBS: 99999"  # always names the id
        assert window._source_badges["ERRATA"].text() == "ERRATA"  # nothing fetched yet
        assert window._source_badges["SBOM"].text() == "SBOM"  # none discovered
        # The pure text helper: ALBS names the id even while missing (grey).
        assert window._source_badge_text("ALBS", "57810", "missing") == "ALBS: 57810"
        assert window._source_badge_text("ALBS", None, "missing") == "ALBS"
        assert window._source_badge_text("ERRATA", "57810", "missing") == "ERRATA"
        # Baseline host (no cas / not AlmaLinux): no CAS or AlmaLinux badge.
        assert set(window._source_badges) == {"ALBS", "ERRATA", "SBOM"}
        assert window._host_badge is None
    finally:
        window.close()


def test_cas_and_almalinux_badges_appear_on_an_almalinux_host(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On an AlmaLinux host with `cas`, a CAS badge and an AlmaLinux indicator
    # appear, and the ERRATA badge names its source NET / DNF (D125).
    from albs_graph.gui import qt_app

    monkeypatch.setattr(qt_app.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(qt_app, "_is_almalinux_family_host", lambda: True)
    window = WorkbenchWindow()
    try:
        assert "CAS" in window._source_badges  # the cas tool is present
        assert window._host_badge is not None
        assert window._host_badge.text() == "AlmaLinux"  # rightmost host indicator

        window.errata_combo.setCurrentIndex(window.errata_combo.findData("dnf"))
        assert window._errata_source_label() == "DNF"
        window.errata_combo.setCurrentIndex(window.errata_combo.findData("http"))
        assert window._errata_source_label() == "NET"
        window.errata_combo.setCurrentIndex(window.errata_combo.findData("both"))
        assert window._errata_source_label() == "NET+DNF"
    finally:
        window.close()


def test_graph_widget_node_center_maps_svg_to_widget_coords(
    qapp: QtWidgets.QApplication,
) -> None:
    # node_center maps a node's SVG-space centre to widget coords (the inverse of
    # the hit-test), so the graph can be scrolled to a highlighted node (D129).
    widget = GraphSvgWidget()
    try:
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="50"></svg>'
        widget.load(QtCore.QByteArray(svg))
        widget.set_regions((NodeRegion("n", "rect", (20, 10, 40, 30)),), ())  # SVG centre (30,20)
        widget.setFixedSize(200, 100)  # 2x the SVG default size (100x50)
        center = widget.node_center("n")
        assert center is not None
        assert (round(center.x()), round(center.y())) == (60, 40)  # (30,20) scaled x2
        assert widget.node_center("missing") is None
    finally:
        widget.deleteLater()


def test_centering_graph_on_selected_node_is_safe_without_a_render(
    qapp: QtWidgets.QApplication,
) -> None:
    # The deferred centre is a no-op when nothing is selected / no graph fits, and
    # never raises (D129).
    window = WorkbenchWindow()
    try:
        window.selected_node_id = None
        window._do_center_graph_on_selected_node()  # no selection -> returns
        window.selected_node_id = "rpm:missing"
        window._do_center_graph_on_selected_node()  # unknown node -> returns, no crash
    finally:
        window.close()


def test_console_dialog_forces_colour_and_renders_ansi_as_html(
    qapp: QtWidgets.QApplication,
) -> None:
    # The subprocess console dialog forces Rich colour (FORCE_COLOR) and renders
    # the ANSI it emits as coloured HTML rather than escape codes (D128).
    env = QtCore.QProcessEnvironment.systemEnvironment()
    dialog = ConsoleProcessDialog(
        title="t", program="true", arguments=[], cwd=Path("."), environment=env, intro="intro"
    )
    try:
        assert dialog.process.processEnvironment().value("FORCE_COLOR") == "1"
        dialog._append("\x1b[36mcoloured\x1b[0m")
        rendered = dialog.output.toHtml()
        assert "coloured" in rendered
        assert "#56b6c2" in rendered  # the cyan span colour, not the escape code
        assert "\x1b" not in rendered  # no raw escape codes leaked through
    finally:
        dialog.process.kill()
        dialog.deleteLater()


def test_run_analysis_switches_to_the_log_tab(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When a fetch starts, the bottom view switches to Log so the user sees what
    # is happening (D126). The worker is stubbed so nothing hits the network.
    window = WorkbenchWindow()
    try:
        window.build_id_edit.setText("57810")
        monkeypatch.setattr(window.thread_pool, "start", lambda _worker: None)
        window.output_tabs.setCurrentWidget(window.findings_table)  # start elsewhere
        window.run_analysis()
        assert window.output_tabs.currentWidget() is window.log
    finally:
        window.close()


def test_errata_badge_is_active_when_consulted_clean(qapp: QtWidgets.QApplication) -> None:
    # Errata consulted but no advisory matched (confirmed_clean) must read as
    # "checked", not greyed-out "not fetched" (D126).
    graph = ProvenanceGraph()
    graph.add_node(
        Node("rpm:x", NodeType.BINARY_RPM, "x-1-1.x86_64",
             {"name": "x", "errata_status": "confirmed_clean"})
    )
    result = AnalysisService(pipeline=AnalysisPipeline(steps=())).analyze_graph(graph, RunSpec())

    window = WorkbenchWindow()
    try:
        window.result = result
        assert window._errata_consulted() is True
        state, _uri = window._source_state("ERRATA", "57810")
        assert state == "active"  # checked, even though clean
        window.errata_combo.setCurrentIndex(window.errata_combo.findData("http"))
        assert window._source_badge_text("ERRATA", "57810", state) == "ERRATA: NET (clean)"
    finally:
        window.close()


def test_worker_routes_a_missing_build_to_build_not_found(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A sparse-id 404 (BuildNotFoundError) is routed to the calm build_not_found
    # signal carrying the id -- not the red "failed" signal.
    from albs_graph.gui import qt_app

    def _raise(*_args: object, **_kwargs: object) -> None:
        raise qt_app.BuildNotFoundError("Build with build_id=57809 is not found")

    monkeypatch.setattr(qt_app.AnalysisService, "analyze", _raise)
    worker = qt_app.AnalysisWorker(GraphLoadSpec(build_id=57809), RunSpec())
    not_found: list[str] = []
    failed: list[str] = []
    worker.signals.build_not_found.connect(not_found.append)
    worker.signals.failed.connect(failed.append)
    worker.run()
    assert not_found == ["57809"]
    assert failed == []  # not surfaced as a generic failure


def test_build_not_found_is_informational_not_a_failure(
    qapp: QtWidgets.QApplication,
) -> None:
    # The missing-build handler reports "not found" in the status bar (not the
    # red "Analysis failed") and keeps the previous result in place.
    window = WorkbenchWindow()
    try:
        window.build_id_edit.setText("57809")
        window._build_not_found("57809")
        text = window.progress_label.text()
        assert "57809" in text and "not found" in text.lower()
        assert text != "Analysis failed"
    finally:
        window.close()


def test_workbench_inspect_build_id_menu_action(
    qapp: QtWidgets.QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = WorkbenchWindow()
    try:
        window.source_edit.setText("/tmp/stale.json")
        analyses: list[bool] = []
        monkeypatch.setattr(window, "run_analysis", lambda: analyses.append(True))
        monkeypatch.setattr(
            QtWidgets.QInputDialog, "getText", staticmethod(lambda *a, **k: ("57810", True))
        )

        window.prompt_inspect_build_id()

        assert window.build_id_edit.text() == "57810"
        assert window.source_edit.text() == ""  # the build id is the explicit choice
        assert analyses == [True]  # it kicked off an in-app analysis
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
        window.timeline_panel.view_combo.setCurrentText("Gantt")
        window.timeline_panel.view_combo.setCurrentText("Tree")
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
        window.dependency_panel.restore("build", False, False)

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

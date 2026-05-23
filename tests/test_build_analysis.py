from __future__ import annotations

import json
from pathlib import Path

from albs_graph.provenance.build_analysis import analyze_albs_build


def test_build_analysis_extracts_task_step_and_signing_durations() -> None:
    data = json.loads(Path("examples/live-build-17812/build-17812.albs.json").read_text())

    analysis = analyze_albs_build(data)
    tasks = {task.arch: task for task in analysis.task_timings}

    assert analysis.build_id == "17812"
    assert analysis.wall_seconds == 814.155744
    assert set(tasks) == {"x86_64", "aarch64", "ppc64le", "s390x", "i686", "src"}
    assert tasks["x86_64"].wall_seconds == 398.212342
    assert tasks["x86_64"].artifact_counts == {"build_log": 14, "rpm": 19}
    assert {
        step.name: step.seconds for step in tasks["x86_64"].steps
    }["build_node_stats.build_binaries"] == 195.109731

    assert len(analysis.sign_timings) == 1
    sign = analysis.sign_timings[0]
    assert sign.wall_seconds == 255.704401
    assert sign.stats_seconds["sign_packages_time"] == 22.0
    assert sign.stats_seconds["upload_packages_time"] == 187.0


def test_build_analysis_attaches_task_timings_to_each_raw_artifact() -> None:
    data = json.loads(Path("examples/live-build-17812/build-17812.albs.json").read_text())

    analysis = analyze_albs_build(data)
    nginx_core = next(
        artifact
        for artifact in analysis.artifact_timings
        if artifact.artifact_id == "3237140"
    )
    build_logs = [
        artifact
        for artifact in analysis.artifact_timings
        if artifact.build_arch == "x86_64" and artifact.artifact_type == "build_log"
    ]

    assert len(analysis.artifact_timings) == 173
    assert len(build_logs) == 14
    assert nginx_core.name == "nginx-core-1.20.1-16.el9_4.1.x86_64.rpm"
    assert nginx_core.package_name == "nginx-core"
    assert nginx_core.artifact_arch == "x86_64"
    assert nginx_core.task_wall_seconds == 398.212342
    assert nginx_core.task_step_seconds["build_node_stats.build_srpm"] == 33.676429

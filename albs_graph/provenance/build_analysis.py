from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from albs_graph.nevra import rpm_metadata_from_filename


_ARCH_PREFERENCE = ("x86_64", "aarch64", "ppc64le", "s390x", "i686", "src", "noarch")


@dataclass(frozen=True)
class TimingStep:
    name: str
    seconds: float
    started_at: str | None = None
    finished_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "seconds": self.seconds,
        }
        if self.started_at:
            data["started_at"] = self.started_at
        if self.finished_at:
            data["finished_at"] = self.finished_at
        return data


@dataclass(frozen=True)
class TaskTiming:
    task_id: str
    arch: str
    status: Any
    started_at: str | None
    finished_at: str | None
    wall_seconds: float | None
    artifact_counts: dict[str, int]
    steps: tuple[TimingStep, ...]
    test_tasks: int
    test_step_totals: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "task_id": self.task_id,
            "arch": self.arch,
            "status": self.status,
            "artifact_counts": self.artifact_counts,
            "steps": [step.to_dict() for step in self.steps],
            "test_tasks": self.test_tasks,
            "test_step_totals": self.test_step_totals,
        }
        if self.started_at:
            data["started_at"] = self.started_at
        if self.finished_at:
            data["finished_at"] = self.finished_at
        if self.wall_seconds is not None:
            data["wall_seconds"] = self.wall_seconds
        return data


@dataclass(frozen=True)
class SignTaskTiming:
    sign_task_id: str
    status: Any
    started_at: str | None
    finished_at: str | None
    wall_seconds: float | None
    stats_seconds: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "sign_task_id": self.sign_task_id,
            "status": self.status,
            "stats_seconds": self.stats_seconds,
        }
        if self.started_at:
            data["started_at"] = self.started_at
        if self.finished_at:
            data["finished_at"] = self.finished_at
        if self.wall_seconds is not None:
            data["wall_seconds"] = self.wall_seconds
        return data


@dataclass(frozen=True)
class ArtifactProcessingTiming:
    artifact_id: str | None
    name: str
    artifact_type: str
    build_task_id: str
    build_arch: str
    artifact_arch: str | None
    package_name: str | None
    task_wall_seconds: float | None
    task_step_seconds: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "artifact_type": self.artifact_type,
            "build_task_id": self.build_task_id,
            "build_arch": self.build_arch,
            "task_step_seconds": self.task_step_seconds,
        }
        optional = {
            "artifact_id": self.artifact_id,
            "artifact_arch": self.artifact_arch,
            "package_name": self.package_name,
            "task_wall_seconds": self.task_wall_seconds,
        }
        return data | {key: value for key, value in optional.items() if value is not None}


@dataclass(frozen=True)
class BuildAnalysis:
    build_id: str
    created_at: str | None
    finished_at: str | None
    wall_seconds: float | None
    task_timings: tuple[TaskTiming, ...]
    sign_timings: tuple[SignTaskTiming, ...]
    artifact_timings: tuple[ArtifactProcessingTiming, ...]
    totals: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "build_id": self.build_id,
            "task_timings": [task.to_dict() for task in self.task_timings],
            "sign_timings": [sign.to_dict() for sign in self.sign_timings],
            "artifact_timings": [artifact.to_dict() for artifact in self.artifact_timings],
            "totals": self.totals,
        }
        if self.created_at:
            data["created_at"] = self.created_at
        if self.finished_at:
            data["finished_at"] = self.finished_at
        if self.wall_seconds is not None:
            data["wall_seconds"] = self.wall_seconds
        return data


def analyze_albs_build(data: dict[str, Any]) -> BuildAnalysis:
    task_timings = tuple(_task_timing(task) for task in data.get("tasks", []) or [])
    sign_timings = tuple(
        _sign_task_timing(sign_task) for sign_task in data.get("sign_tasks", []) or []
    )
    task_by_id = {task.task_id: task for task in task_timings}
    artifact_timings = tuple(
        _artifact_processing_timing(task, artifact, task_by_id[str(task.get("id"))])
        for task in data.get("tasks", []) or []
        for artifact in task.get("artifacts", []) or []
        if str(task.get("id")) in task_by_id
    )
    return BuildAnalysis(
        build_id=str(data.get("build_id") or data.get("id") or "unknown"),
        created_at=_text(data.get("created_at")),
        finished_at=_text(data.get("finished_at")),
        wall_seconds=_duration_between(data.get("created_at"), data.get("finished_at")),
        task_timings=tuple(sorted(task_timings, key=lambda task: _arch_sort_key(task.arch))),
        sign_timings=sign_timings,
        artifact_timings=tuple(
            sorted(
                artifact_timings,
                key=lambda artifact: (
                    _arch_sort_key(artifact.build_arch),
                    artifact.artifact_type,
                    artifact.name,
                ),
            )
        ),
        totals=_totals(task_timings, sign_timings, artifact_timings),
    )


def _task_timing(task: dict[str, Any]) -> TaskTiming:
    statistics = [
        stat.get("statistics", {})
        for stat in task.get("performance_stats", []) or []
        if isinstance(stat, dict)
    ]
    steps = tuple(
        sorted(
            (step for stat in statistics for step in _iter_timing_steps(stat)),
            key=lambda step: step.name,
        )
    )
    test_totals = _test_step_totals(task.get("test_tasks", []))
    return TaskTiming(
        task_id=str(task.get("id")),
        arch=str(task.get("arch") or "unknown"),
        status=task.get("status"),
        started_at=_text(task.get("started_at")),
        finished_at=_text(task.get("finished_at")),
        wall_seconds=_duration_between(task.get("started_at"), task.get("finished_at")),
        artifact_counts=dict(
            Counter(str(item.get("type") or "unknown") for item in task.get("artifacts", []) or [])
        ),
        steps=steps,
        test_tasks=len(task.get("test_tasks", []) or []),
        test_step_totals=test_totals,
    )


def _sign_task_timing(sign_task: dict[str, Any]) -> SignTaskTiming:
    stats = sign_task.get("stats") or {}
    return SignTaskTiming(
        sign_task_id=str(sign_task.get("id")),
        status=sign_task.get("status"),
        started_at=_text(sign_task.get("started_at")),
        finished_at=_text(sign_task.get("finished_at")),
        wall_seconds=_duration_between(sign_task.get("started_at"), sign_task.get("finished_at")),
        stats_seconds={
            str(key): float(value)
            for key, value in stats.items()
            if isinstance(value, (int, float))
        },
    )


def _artifact_processing_timing(
    task: dict[str, Any],
    artifact: dict[str, Any],
    task_timing: TaskTiming,
) -> ArtifactProcessingTiming:
    name = str(artifact.get("name") or "")
    rpm_metadata = _rpm_metadata_from_filename(name) if name.endswith(".rpm") else {}
    return ArtifactProcessingTiming(
        artifact_id=_text(artifact.get("id")),
        name=name,
        artifact_type=str(artifact.get("type") or "unknown"),
        build_task_id=str(task.get("id")),
        build_arch=str(task.get("arch") or "unknown"),
        artifact_arch=_text(rpm_metadata.get("arch")),
        package_name=_text(rpm_metadata.get("name")),
        task_wall_seconds=task_timing.wall_seconds,
        task_step_seconds={step.name: step.seconds for step in task_timing.steps},
    )


def _iter_timing_steps(data: dict[str, Any], prefix: str = "") -> Iterable[TimingStep]:
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        step_name = f"{prefix}.{key}" if prefix else str(key)
        if "delta" in value:
            seconds = _delta_seconds(value.get("delta"))
            if seconds is not None:
                yield TimingStep(
                    step_name,
                    seconds,
                    started_at=_text(value.get("start_ts")),
                    finished_at=_text(value.get("finish_ts") or value.get("end_ts")),
                )
                continue
        yield from _iter_timing_steps(value, step_name)


def _test_step_totals(test_tasks: list[dict[str, Any]]) -> dict[str, float]:
    totals: dict[str, float] = defaultdict(float)
    for test_task in test_tasks:
        for perf in test_task.get("performance_stats", []) or []:
            statistics = perf.get("statistics", {}) if isinstance(perf, dict) else {}
            for step in _iter_timing_steps(statistics):
                totals[step.name] += step.seconds
    return {key: round(value, 6) for key, value in sorted(totals.items())}


def _totals(
    task_timings: tuple[TaskTiming, ...],
    sign_timings: tuple[SignTaskTiming, ...],
    artifact_timings: tuple[ArtifactProcessingTiming, ...],
) -> dict[str, Any]:
    step_totals: dict[str, float] = defaultdict(float)
    for task in task_timings:
        for step in task.steps:
            step_totals[step.name] += step.seconds

    sign_step_totals: dict[str, float] = defaultdict(float)
    for sign in sign_timings:
        for name, seconds in sign.stats_seconds.items():
            sign_step_totals[name] += seconds

    artifact_types = Counter(artifact.artifact_type for artifact in artifact_timings)
    artifact_arches = Counter(
        artifact.artifact_arch or "non_rpm" for artifact in artifact_timings
    )
    return {
        "build_task_count": len(task_timings),
        "sign_task_count": len(sign_timings),
        "artifact_count": len(artifact_timings),
        "artifact_types": dict(sorted(artifact_types.items())),
        "artifact_arches": dict(sorted(artifact_arches.items())),
        "aggregate_build_task_wall_seconds": round(
            sum(task.wall_seconds or 0 for task in task_timings), 6
        ),
        "critical_build_task_wall_seconds": round(
            max((task.wall_seconds or 0 for task in task_timings), default=0), 6
        ),
        "aggregate_sign_task_wall_seconds": round(
            sum(sign.wall_seconds or 0 for sign in sign_timings), 6
        ),
        "build_step_totals_seconds": {
            key: round(value, 6) for key, value in sorted(step_totals.items())
        },
        "sign_step_totals_seconds": {
            key: round(value, 6) for key, value in sorted(sign_step_totals.items())
        },
    }


def _duration_between(start: Any, finish: Any) -> float | None:
    start_dt = _parse_datetime(start)
    finish_dt = _parse_datetime(finish)
    if not start_dt or not finish_dt:
        return None
    return round((finish_dt - start_dt).total_seconds(), 6)


def _parse_datetime(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.fromisoformat(text.replace(" ", "T"))
        except ValueError:
            return None


def _delta_seconds(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    text = _text(value)
    if not text:
        return None
    parts = text.split(":")
    if len(parts) != 3:
        return None
    try:
        hours = int(parts[0])
        minutes = int(parts[1])
        seconds = float(parts[2])
    except ValueError:
        return None
    return round(hours * 3600 + minutes * 60 + seconds, 6)


def _rpm_metadata_from_filename(filename: str) -> dict[str, str | None]:
    # Canonical NEVRA parsing now lives in albs_graph.nevra (shared with the ALBS
    # adapter, which had a byte-identical copy of this).
    return rpm_metadata_from_filename(filename)


def _arch_sort_key(value: str) -> tuple[int, str]:
    try:
        return (_ARCH_PREFERENCE.index(value), value)
    except ValueError:
        return (len(_ARCH_PREFERENCE), value)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

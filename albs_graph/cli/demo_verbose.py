from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from albs_graph.adapters.albs import fetch_build_metadata, graph_from_build_metadata
from albs_graph.model import Node, ProvenanceGraph
from albs_graph.provenance.build_analysis import analyze_albs_build
from albs_graph.provenance.inventory import (
    rpm_artifact_inventory,
    summarize_artifacts_by_build_arch,
)
from albs_graph.provenance.trust import (
    find_binary_rpm,
    focused_trust_graph,
    select_default_binary_rpm,
    trust_path,
)
from albs_graph.render import graph_to_dot, graph_to_json, graph_to_svg


_ARCH_PREFERENCE = ("x86_64", "aarch64", "ppc64le", "s390x", "i686")
console = Console()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    run_demo(
        build_id=args.build_id,
        rpm_name=args.rpm.strip(),
        arch=args.arch.strip() or None,
        out_dir=args.out_dir,
        live_dir=args.live_dir,
        cache_file=args.cache,
        cache_ttl=args.cache_ttl,
        verify_git=_truthy(args.verify_git),
    )
    return 0


def run_demo(
    *,
    build_id: int,
    rpm_name: str,
    arch: str | None,
    out_dir: Path,
    live_dir: Path,
    cache_file: Path,
    cache_ttl: int,
    verify_git: bool,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    live_dir.mkdir(parents=True, exist_ok=True)

    _print_header(
        build_id=build_id,
        rpm_name=rpm_name,
        arch=arch,
        cache_file=cache_file,
        cache_ttl=cache_ttl,
        verify_git=verify_git,
    )

    metadata = fetch_build_metadata(
        build_id,
        cache_path=cache_file,
        cache_ttl_seconds=cache_ttl,
        progress=step,
    )
    step(f"Source package: {metadata.package} (from ALBS {metadata.package_source})")

    step("Building full provenance graph from ALBS metadata")
    graph = graph_from_build_metadata(metadata)
    cas_count = len(graph.find_by_type("cas_attestation"))
    step(f"Full graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges, {cas_count} CAS attestations")
    build_arches = _task_arches(metadata.raw)
    if build_arches:
        step(f"ALBS build task platforms: {', '.join(build_arches)}")
    if _has_source_task(metadata.raw):
        step("ALBS source build task: src")

    _render_artifact_inventory(build_id, graph, out_dir)
    _render_processing_analysis(build_id, metadata.raw, out_dir)

    if verify_git:
        _verify_git_source(metadata.source_repository, metadata.commit)

    step("Rendering full graph as JSON/DOT/SVG")
    full_json = graph_to_json(graph)
    full_dot = graph_to_dot(graph)
    full_svg = graph_to_svg(graph)
    _write(live_dir / f"build-{build_id}.json", full_json, "full graph json")
    _write(live_dir / f"build-{build_id}.dot", full_dot, "full graph dot")
    _write(live_dir / f"build-{build_id}.svg", full_svg, "full graph svg")
    _write(out_dir / f"build-{build_id}-full.json", full_json, "demo full graph json")
    _write(out_dir / f"build-{build_id}-full.svg", full_svg, "demo full graph svg")

    rpm_node = _select_focused_rpm(graph, rpm_name=rpm_name, arch=arch, build_arches=build_arches)
    step(f"Selected RPM node: {rpm_node.id}")
    step("Analyzing source-to-artifact trust path")
    report = trust_path(graph, rpm_node.id)
    _print_trust_report(report, rpm_node.label)

    step("Building focused trust graph")
    focused = focused_trust_graph(graph, rpm_node.id)
    focused_cas_count = len(focused.find_by_type("cas_attestation"))
    step(
        f"Focused graph: {len(focused.nodes)} nodes, {len(focused.edges)} edges, "
        f"{focused_cas_count} CAS attestations"
    )

    selected_name = str(rpm_node.metadata.get("name") or rpm_node.label.removesuffix(".rpm"))
    selected_arch = str(rpm_node.metadata.get("arch") or "unknown")
    selected_slug = f"{selected_name}-{selected_arch}"

    step("Rendering focused trust graph as JSON/DOT/SVG")
    _write(out_dir / f"{selected_slug}-trust.json", graph_to_json(focused), "focused graph json")
    _write(out_dir / f"{selected_slug}-trust.dot", graph_to_dot(focused), "focused graph dot")
    _write(out_dir / f"{selected_slug}-trust.svg", graph_to_svg(focused), "focused graph svg")

    console.print("==> Done")
    console.print(f"Metadata cache: {cache_file}")
    console.print(f"Full graph:     {out_dir / f'build-{build_id}-full.svg'}")
    console.print(f"Focused graph:  {out_dir / f'{selected_slug}-trust.svg'}")


def step(message: str) -> None:
    console.print(f"[cyan]step[/cyan] {message}")


def _write(path: Path, content: str, label: str) -> None:
    step(f"Writing {label} output to {path}")
    path.write_text(content, encoding="utf-8")


def _print_header(
    *,
    build_id: int,
    rpm_name: str,
    arch: str | None,
    cache_file: Path,
    cache_ttl: int,
    verify_git: bool,
) -> None:
    if shutil.which("albs-graph"):
        tool = "albs-graph installed; using Python orchestration for single-pass demo"
    else:
        tool = "python -m albs_graph.cli.main compatible; using Python orchestration for single-pass demo"
    console.print(f"==> ALBS graph tool: {tool}")
    console.print(f"==> Build: {build_id}")
    if rpm_name or arch:
        suffix = f".{arch}" if arch else ""
        console.print(f"==> Focused RPM selector: {rpm_name or '<derived>'}{suffix}")
    else:
        console.print("==> Focused RPM selector: <none; representative artifact selected after ALBS metadata>")
    console.print(f"==> Raw ALBS metadata cache: {cache_file}")
    console.print(f"==> Cache TTL: {cache_ttl}s")
    console.print(f"==> Verify git source commit: {int(verify_git)}")


def _render_artifact_inventory(build_id: int, graph: ProvenanceGraph, out_dir: Path) -> None:
    inventory = rpm_artifact_inventory(graph)
    artifact_summaries = summarize_artifacts_by_build_arch(inventory)
    if not artifact_summaries:
        return

    matrix = Table(title="ALBS RPM artifact matrix")
    matrix.add_column("Build task arch")
    matrix.add_column("Artifacts", justify="right")
    matrix.add_column("Artifact arches")
    matrix.add_column("Packages")
    for summary in artifact_summaries:
        arches = ", ".join(
            f"{artifact_arch}={count}"
            for artifact_arch, count in summary.artifact_arches.items()
        )
        package_names = list(summary.packages)
        visible = ", ".join(package_names[:8])
        if len(package_names) > 8:
            visible = f"{visible}, +{len(package_names) - 8} more"
        matrix.add_row(summary.build_arch, str(summary.total_artifacts), arches, visible)
    console.print(matrix)
    step(
        "Artifact inventory rows include each ALBS task artifact, including repeated "
        "SRPM/noarch outputs per build task"
    )
    _write(
        out_dir / f"build-{build_id}-artifact-inventory.json",
        json.dumps([item.to_dict() for item in inventory], indent=2, sort_keys=True) + "\n",
        "artifact inventory json",
    )


def _render_processing_analysis(build_id: int, raw: dict[str, object], out_dir: Path) -> None:
    analysis = analyze_albs_build(raw)
    if analysis.task_timings:
        timeline = Table(title="ALBS processing timeline")
        timeline.add_column("Build task arch")
        timeline.add_column("Wall", justify="right")
        timeline.add_column("Artifacts")
        timeline.add_column("build_srpm", justify="right")
        timeline.add_column("build_binaries", justify="right")
        timeline.add_column("upload", justify="right")
        timeline.add_column("packages_processing", justify="right")
        timeline.add_column("logs_processing", justify="right")
        for task in analysis.task_timings:
            artifacts = ", ".join(
                f"{kind}={count}" for kind, count in sorted(task.artifact_counts.items())
            )
            timeline.add_row(
                task.arch,
                _format_seconds(task.wall_seconds),
                artifacts,
                _format_seconds(_step_seconds(task, "build_node_stats.build_srpm")),
                _format_seconds(_step_seconds(task, "build_node_stats.build_binaries")),
                _format_seconds(_step_seconds(task, "build_node_stats.upload")),
                _format_seconds(_step_seconds(task, "build_done_stats.packages_processing")),
                _format_seconds(_step_seconds(task, "build_done_stats.logs_processing")),
            )
        console.print(timeline)
        totals = analysis.totals
        step(
            "Build timing totals: "
            f"wall={_format_seconds(analysis.wall_seconds)}, "
            f"aggregate task wall={_format_seconds(totals.get('aggregate_build_task_wall_seconds'))}, "
            f"critical task wall={_format_seconds(totals.get('critical_build_task_wall_seconds'))}"
        )
    if analysis.sign_timings:
        signing = Table(title="ALBS signing/notarization timing")
        signing.add_column("Sign task")
        signing.add_column("Wall", justify="right")
        signing.add_column("sign", justify="right")
        signing.add_column("notarize", justify="right")
        signing.add_column("upload", justify="right")
        signing.add_column("web", justify="right")
        for sign in analysis.sign_timings:
            signing.add_row(
                sign.sign_task_id,
                _format_seconds(sign.wall_seconds),
                _format_seconds(sign.stats_seconds.get("sign_packages_time")),
                _format_seconds(sign.stats_seconds.get("notarization_packages_time")),
                _format_seconds(sign.stats_seconds.get("upload_packages_time")),
                _format_seconds(sign.stats_seconds.get("web_server_processing_time")),
            )
        console.print(signing)
    _write(
        out_dir / f"build-{build_id}-processing-analysis.json",
        json.dumps(analysis.to_dict(), indent=2, sort_keys=True) + "\n",
        "processing analysis json",
    )


def _verify_git_source(repo_url: str, commit: str) -> None:
    step(f"Verifying git source commit {commit} in {repo_url}")
    if shutil.which("git") is None:
        raise SystemExit("VERIFY_GIT=1 requested, but git is not available in PATH")
    with tempfile.TemporaryDirectory(prefix="albs-git-check-") as tmpdir:
        subprocess.run(["git", "init", "-q", tmpdir], check=True)
        subprocess.run(["git", "-C", tmpdir, "remote", "add", "origin", repo_url], check=True)
        fetch = subprocess.run(
            ["git", "-C", tmpdir, "fetch", "--depth=1", "origin", commit],
            text=True,
            capture_output=True,
            check=False,
        )
        if fetch.returncode != 0:
            detail = (fetch.stderr or fetch.stdout).strip()
            raise SystemExit(f"git commit verification failed for {commit}: {detail}")
        subprocess.run(["git", "-C", tmpdir, "cat-file", "-e", f"{commit}^{{commit}}"], check=True)
    step("Git source commit verification: ok")


def _select_focused_rpm(
    graph: ProvenanceGraph,
    *,
    rpm_name: str,
    arch: str | None,
    build_arches: list[str],
) -> Node:
    if rpm_name:
        suffix = f".{arch}" if arch else ""
        step(f"Resolving binary RPM selector: {rpm_name}{suffix}")
        return find_binary_rpm(graph, rpm_name, arch=arch)
    if arch:
        step(f"No RPM name provided; selecting binary RPM from ALBS graph for arch {arch}")
        return select_default_binary_rpm(graph, arch=arch)

    representative_arch = _preferred_representative_arch(build_arches)
    if representative_arch:
        step(
            "No RPM selector provided; full build is multi-platform; "
            f"selecting representative focused artifact for arch {representative_arch}"
        )
        return select_default_binary_rpm(graph, arch=representative_arch)

    step("No RPM selector provided; selecting representative focused artifact from ALBS graph")
    return select_default_binary_rpm(graph, arch=None)


def _print_trust_report(report: dict[str, Any], label: str) -> None:
    table = Table(title=f"Trust path: {label}")
    table.add_column("Check")
    table.add_column("Result")
    checks = report["checks"]
    if not isinstance(checks, dict):
        raise ValueError("trust report checks must be a dictionary")
    for name, value in checks.items():
        table.add_row(str(name), "ok" if value else "missing")
    console.print(table)
    console.print(f"Provenance complete: {report['provenance_complete']}")
    console.print(f"Security context complete: {report['security_context_complete']}")
    console.print(f"Complete: {report['complete']}")
    missing_provenance = report["missing_provenance"]
    if missing_provenance:
        console.print(f"Missing provenance: {', '.join(str(item) for item in missing_provenance)}")
    missing_security_context = report["missing_security_context"]
    if missing_security_context:
        console.print(
            f"Missing security context: {', '.join(str(item) for item in missing_security_context)}"
        )
    console.print("Path:")
    path = report["path"]
    if not isinstance(path, list):
        raise ValueError("trust report path must be a list")
    for node_id in path:
        console.print(f"  {node_id}")


def _task_arches(raw: dict[str, object]) -> list[str]:
    tasks = raw.get("tasks")
    if not isinstance(tasks, list):
        return []
    arches = {
        str(task.get("arch"))
        for task in tasks
        if isinstance(task, dict) and task.get("arch") and task.get("arch") != "src"
    }
    return _ordered_arches(arches)


def _has_source_task(raw: dict[str, object]) -> bool:
    tasks = raw.get("tasks")
    if not isinstance(tasks, list):
        return False
    return any(isinstance(task, dict) and task.get("arch") == "src" for task in tasks)


def _preferred_representative_arch(arches: list[str]) -> str | None:
    for candidate in _ARCH_PREFERENCE:
        if candidate in arches:
            return candidate
    return arches[0] if arches else None


def _ordered_arches(values: set[str]) -> list[str]:
    return sorted(values, key=_arch_sort_key)


def _arch_sort_key(value: str) -> tuple[int, str]:
    try:
        return (_ARCH_PREFERENCE.index(value), value)
    except ValueError:
        return (len(_ARCH_PREFERENCE), value)


def _format_seconds(value: float | int | None) -> str:
    if value is None:
        return "-"
    seconds = float(value)
    if seconds >= 60:
        return f"{seconds / 60:.1f}m"
    return f"{seconds:.1f}s"


def _step_seconds(task: object, name: str) -> float | None:
    steps = {step.name: step.seconds for step in getattr(task, "steps", ())}
    return steps.get(name)


def _truthy(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    return value.lower() in {"1", "true", "yes", "on"}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the verbose ALBS provenance demo.")
    parser.add_argument("--build-id", type=int, required=True)
    parser.add_argument("--rpm", default="")
    parser.add_argument("--arch", default="")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--live-dir", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--cache-ttl", type=int, default=300)
    parser.add_argument("--verify-git", default="0")
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())

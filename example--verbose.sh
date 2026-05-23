#!/usr/bin/env bash
set -euo pipefail

BUILD_ID="${BUILD_ID:-17812}"
RPM_NAME="${RPM_NAME:-}"
ARCH="${ARCH:-}"
OUT_DIR="${OUT_DIR:-examples/demo-build-$BUILD_ID}"
LIVE_DIR="${LIVE_DIR:-examples/live-build-17812}"
CACHE_FILE="${CACHE_FILE:-$LIVE_DIR/build-$BUILD_ID.albs.json}"
CACHE_TTL="${CACHE_TTL:-300}"
VERIFY_GIT="${VERIFY_GIT:-0}"

mkdir -p "$OUT_DIR" "$LIVE_DIR"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  printf 'ERROR: python3 or python is required to run this demo.\n' >&2
  exit 1
fi

if command -v albs-graph >/dev/null 2>&1; then
  ALBS_GRAPH_TOOL="albs-graph installed; using Python orchestration for single-pass demo"
else
  ALBS_GRAPH_TOOL="python -m albs_graph.cli.main compatible; using Python orchestration for single-pass demo"
fi

printf '==> ALBS graph tool: %s\n' "$ALBS_GRAPH_TOOL"
printf '==> Build: %s\n' "$BUILD_ID"
if [[ -n "$RPM_NAME" || -n "$ARCH" ]]; then
  printf '==> Focused RPM selector: %s%s%s\n' "${RPM_NAME:-<derived>}" "$([[ -n "$ARCH" ]] && printf .)" "$ARCH"
else
  printf '==> Focused RPM selector: <none; representative artifact selected after ALBS metadata>\n'
fi
printf '==> Raw ALBS metadata cache: %s\n' "$CACHE_FILE"
printf '==> Cache TTL: %ss\n' "$CACHE_TTL"
printf '==> Verify git source commit: %s\n' "$VERIFY_GIT"

BUILD_ID="$BUILD_ID" \
RPM_NAME="$RPM_NAME" \
ARCH="$ARCH" \
OUT_DIR="$OUT_DIR" \
LIVE_DIR="$LIVE_DIR" \
CACHE_FILE="$CACHE_FILE" \
CACHE_TTL="$CACHE_TTL" \
VERIFY_GIT="$VERIFY_GIT" \
"$PYTHON_BIN" <<'PY'
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from rich.console import Console
from rich.table import Table

from albs_graph.adapters.albs import fetch_build_metadata, graph_from_build_metadata
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

build_id = int(os.environ["BUILD_ID"])
rpm_name = os.environ["RPM_NAME"].strip()
arch = os.environ["ARCH"].strip() or None
out_dir = Path(os.environ["OUT_DIR"])
live_dir = Path(os.environ["LIVE_DIR"])
cache_file = Path(os.environ["CACHE_FILE"])
cache_ttl = int(os.environ["CACHE_TTL"])
verify_git = os.environ["VERIFY_GIT"].lower() in {"1", "true", "yes", "on"}
console = Console()
arch_preference = ("x86_64", "aarch64", "ppc64le", "s390x", "i686")


def step(message: str) -> None:
    console.print(f"[cyan]step[/cyan] {message}")


def write(path: Path, content: str, label: str) -> None:
    step(f"Writing {label} output to {path}")
    path.write_text(content, encoding="utf-8")


def arch_sort_key(value: str) -> tuple[int, str]:
    try:
        return (arch_preference.index(value), value)
    except ValueError:
        return (len(arch_preference), value)


def ordered_arches(values: set[str]) -> list[str]:
    return sorted(values, key=arch_sort_key)


def format_seconds(value: float | int | None) -> str:
    if value is None:
        return "-"
    seconds = float(value)
    if seconds >= 60:
        return f"{seconds / 60:.1f}m"
    return f"{seconds:.1f}s"


def step_seconds(task: object, name: str) -> float | None:
    steps = {step.name: step.seconds for step in getattr(task, "steps", ())}
    return steps.get(name)


def task_arches(raw: dict[str, object]) -> list[str]:
    tasks = raw.get("tasks")
    if not isinstance(tasks, list):
        return []
    arches = {
        str(task.get("arch"))
        for task in tasks
        if isinstance(task, dict) and task.get("arch") and task.get("arch") != "src"
    }
    return ordered_arches(arches)


def has_source_task(raw: dict[str, object]) -> bool:
    tasks = raw.get("tasks")
    if not isinstance(tasks, list):
        return False
    return any(isinstance(task, dict) and task.get("arch") == "src" for task in tasks)


def preferred_representative_arch(arches: list[str]) -> str | None:
    for candidate in arch_preference:
        if candidate in arches:
            return candidate
    return arches[0] if arches else None


out_dir.mkdir(parents=True, exist_ok=True)
live_dir.mkdir(parents=True, exist_ok=True)

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
build_arches = task_arches(metadata.raw)
if build_arches:
    step(f"ALBS build task platforms: {', '.join(build_arches)}")
if has_source_task(metadata.raw):
    step("ALBS source build task: src")
inventory = rpm_artifact_inventory(graph)
artifact_summaries = summarize_artifacts_by_build_arch(inventory)
if artifact_summaries:
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
        matrix.add_row(
            summary.build_arch,
            str(summary.total_artifacts),
            arches,
            visible,
        )
    console.print(matrix)
    step(
        "Artifact inventory rows include each ALBS task artifact, including repeated "
        "SRPM/noarch outputs per build task"
    )
    write(
        out_dir / f"build-{build_id}-artifact-inventory.json",
        json.dumps([item.to_dict() for item in inventory], indent=2, sort_keys=True) + "\n",
        "artifact inventory json",
    )

analysis = analyze_albs_build(metadata.raw)
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
            format_seconds(task.wall_seconds),
            artifacts,
            format_seconds(step_seconds(task, "build_node_stats.build_srpm")),
            format_seconds(step_seconds(task, "build_node_stats.build_binaries")),
            format_seconds(step_seconds(task, "build_node_stats.upload")),
            format_seconds(step_seconds(task, "build_done_stats.packages_processing")),
            format_seconds(step_seconds(task, "build_done_stats.logs_processing")),
        )
    console.print(timeline)
    totals = analysis.totals
    step(
        "Build timing totals: "
        f"wall={format_seconds(analysis.wall_seconds)}, "
        f"aggregate task wall={format_seconds(totals.get('aggregate_build_task_wall_seconds'))}, "
        f"critical task wall={format_seconds(totals.get('critical_build_task_wall_seconds'))}"
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
            format_seconds(sign.wall_seconds),
            format_seconds(sign.stats_seconds.get("sign_packages_time")),
            format_seconds(sign.stats_seconds.get("notarization_packages_time")),
            format_seconds(sign.stats_seconds.get("upload_packages_time")),
            format_seconds(sign.stats_seconds.get("web_server_processing_time")),
        )
    console.print(signing)
write(
    out_dir / f"build-{build_id}-processing-analysis.json",
    json.dumps(analysis.to_dict(), indent=2, sort_keys=True) + "\n",
    "processing analysis json",
)

if verify_git:
    repo_url = metadata.source_repository
    commit = metadata.commit
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

step("Rendering full graph as JSON/DOT/SVG")
full_json = graph_to_json(graph)
full_dot = graph_to_dot(graph)
full_svg = graph_to_svg(graph)
write(live_dir / f"build-{build_id}.json", full_json, "full graph json")
write(live_dir / f"build-{build_id}.dot", full_dot, "full graph dot")
write(live_dir / f"build-{build_id}.svg", full_svg, "full graph svg")
write(out_dir / f"build-{build_id}-full.json", full_json, "demo full graph json")
write(out_dir / f"build-{build_id}-full.svg", full_svg, "demo full graph svg")

if rpm_name:
    suffix = f".{arch}" if arch else ""
    step(f"Resolving binary RPM selector: {rpm_name}{suffix}")
    rpm_node = find_binary_rpm(graph, rpm_name, arch=arch)
else:
    if arch:
        step(f"No RPM name provided; selecting binary RPM from ALBS graph for arch {arch}")
    else:
        representative_arch = preferred_representative_arch(build_arches)
        if representative_arch:
            arch = representative_arch
            step(
                "No RPM selector provided; full build is multi-platform; "
                f"selecting representative focused artifact for arch {arch}"
            )
        else:
            step(
                "No RPM selector provided; selecting representative focused artifact "
                "from ALBS graph"
            )
    rpm_node = select_default_binary_rpm(graph, arch=arch)
step(f"Selected RPM node: {rpm_node.id}")
step("Analyzing source-to-artifact trust path")
report = trust_path(graph, rpm_node.id)

table = Table(title=f"Trust path: {rpm_node.label}")
table.add_column("Check")
table.add_column("Result")
for name, value in report["checks"].items():
    table.add_row(name, "ok" if value else "missing")
console.print(table)
console.print(f"Provenance complete: {report['provenance_complete']}")
console.print(f"Security context complete: {report['security_context_complete']}")
console.print(f"Complete: {report['complete']}")
if report["missing_provenance"]:
    console.print(f"Missing provenance: {', '.join(report['missing_provenance'])}")
if report["missing_security_context"]:
    console.print(f"Missing security context: {', '.join(report['missing_security_context'])}")
console.print("Path:")
for node_id in report["path"]:
    console.print(f"  {node_id}")

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
write(out_dir / f"{selected_slug}-trust.json", graph_to_json(focused), "focused graph json")
write(out_dir / f"{selected_slug}-trust.dot", graph_to_dot(focused), "focused graph dot")
write(out_dir / f"{selected_slug}-trust.svg", graph_to_svg(focused), "focused graph svg")

console.print("==> Done")
console.print(f"Metadata cache: {cache_file}")
console.print(f"Full graph:     {out_dir / f'build-{build_id}-full.svg'}")
console.print(f"Focused graph:  {out_dir / f'{selected_slug}-trust.svg'}")
PY

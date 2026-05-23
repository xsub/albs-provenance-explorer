#!/usr/bin/env bash
set -euo pipefail

BUILD_ID="${BUILD_ID:-17812}"
RPM_NAME="${RPM_NAME:-nginx-core}"
ARCH="${ARCH:-x86_64}"
OUT_DIR="${OUT_DIR:-examples/demo-nginx-core}"
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
printf '==> RPM: %s.%s\n' "$RPM_NAME" "$ARCH"
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

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from rich.console import Console
from rich.table import Table

from albs_graph.adapters.albs import fetch_build_metadata, graph_from_build_metadata
from albs_graph.provenance.trust import find_binary_rpm, focused_trust_graph, trust_path
from albs_graph.render import graph_to_dot, graph_to_json, graph_to_svg

build_id = int(os.environ["BUILD_ID"])
rpm_name = os.environ["RPM_NAME"]
arch = os.environ["ARCH"]
out_dir = Path(os.environ["OUT_DIR"])
live_dir = Path(os.environ["LIVE_DIR"])
cache_file = Path(os.environ["CACHE_FILE"])
cache_ttl = int(os.environ["CACHE_TTL"])
verify_git = os.environ["VERIFY_GIT"].lower() in {"1", "true", "yes", "on"}
console = Console()


def step(message: str) -> None:
    console.print(f"[cyan]step[/cyan] {message}")


def write(path: Path, content: str, label: str) -> None:
    step(f"Writing {label} output to {path}")
    path.write_text(content, encoding="utf-8")


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

step(f"Resolving binary RPM selector: {rpm_name}.{arch}")
rpm_node = find_binary_rpm(graph, rpm_name, arch=arch)
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

step("Rendering focused trust graph as JSON/DOT/SVG")
write(out_dir / f"{rpm_name}-{arch}-trust.json", graph_to_json(focused), "focused graph json")
write(out_dir / f"{rpm_name}-{arch}-trust.dot", graph_to_dot(focused), "focused graph dot")
write(out_dir / f"{rpm_name}-{arch}-trust.svg", graph_to_svg(focused), "focused graph svg")

console.print("==> Done")
console.print(f"Metadata cache: {cache_file}")
console.print(f"Full graph:     {out_dir / f'build-{build_id}-full.svg'}")
console.print(f"Focused graph:  {out_dir / f'{rpm_name}-{arch}-trust.svg'}")
PY

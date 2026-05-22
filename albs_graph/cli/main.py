from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable, Optional

import typer
from rich.console import Console
from rich.table import Table

from albs_graph.adapters import RpmQueryError, fetch_build_metadata, graph_from_local_rpm
from albs_graph.adapters.albs import graph_from_build_metadata, load_mock_build
from albs_graph.adapters.sbom import import_sbom
from albs_graph.mock_data import build_mock_package_graph
from albs_graph.model import NodeType, ProvenanceGraph
from albs_graph.provenance.trust import find_binary_rpm, focused_trust_graph, trust_path
from albs_graph.render import SvgRenderError, graph_to_dot, graph_to_json, graph_to_svg

app = typer.Typer(
    name="albs-graph",
    help="CLI-first provenance graph explorer for ALBS, RPM lineage, SBOMs and trust paths.",
    no_args_is_help=True,
)
console = Console()
verbose_console = Console(stderr=True)


@app.command()
def mock(
    package: str = typer.Argument("openssl", help="Mock package to build."),
    output_format: str = typer.Option(
        "summary",
        "--format",
        "-f",
        help="summary, json, dot or svg.",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write output to a file."),
) -> None:
    graph = build_mock_package_graph(package)
    _emit_graph(graph, output_format, output)


@app.command("fetch-build")
def fetch_build(
    build_id: int = typer.Argument(..., help="ALBS build id."),
    output_format: str = typer.Option("json", "--format", "-f", help="json, dot or svg."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    base_url: str = typer.Option("https://build.almalinux.org", "--base-url"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print step-by-step progress to stderr."
    ),
) -> None:
    metadata = fetch_build_metadata(build_id, base_url=base_url, progress=_progress(verbose))
    _log_step(verbose, "Building provenance graph from ALBS metadata")
    graph = graph_from_build_metadata(metadata)
    _log_graph_stats(verbose, graph)
    _emit_graph(graph, output_format, output, verbose=verbose)


@app.command("fetch")
def fetch(
    build_id: int = typer.Option(..., "--build-id", "-b", help="ALBS build id."),
    output_format: str = typer.Option("json", "--format", "-f", help="json, dot or svg."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    base_url: str = typer.Option("https://build.almalinux.org", "--base-url"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print step-by-step progress to stderr."
    ),
) -> None:
    metadata = fetch_build_metadata(build_id, base_url=base_url, progress=_progress(verbose))
    _log_step(verbose, "Building provenance graph from ALBS metadata")
    graph = graph_from_build_metadata(metadata)
    _log_graph_stats(verbose, graph)
    _emit_graph(graph, output_format, output, verbose=verbose)


@app.command("inspect-rpm")
def inspect_rpm(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Local RPM path."),
    output_format: str = typer.Option("json", "--format", "-f", help="json or dot."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    graph = graph_from_local_rpm(path)
    _emit_graph(graph, output_format, output)


@app.command("import-sbom")
def import_sbom_command(
    path: Path = typer.Argument(
        ..., exists=True, dir_okay=False, help="SPDX JSON or CycloneDX JSON SBOM."
    ),
    output_format: str = typer.Option("json", "--format", "-f", help="json or dot."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    graph = import_sbom(path)
    _emit_graph(graph, output_format, output)


@app.command("trust-path")
def trust_path_command(
    package: Optional[str] = typer.Argument(None, help="Binary RPM node id or package name."),
    rpm: Optional[str] = typer.Option(None, "--rpm", help="Binary RPM name or node id."),
    arch: Optional[str] = typer.Option(
        None, "--arch", help="RPM architecture, for example x86_64."
    ),
    build_id: Optional[int] = typer.Option(
        None, "--build-id", "-b", help="Fetch a live ALBS build id."
    ),
    output_format: str = typer.Option(
        "summary", "--format", "-f", help="summary, json, dot or svg."
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    include_tests: bool = typer.Option(
        False, "--include-tests", help="Include test task nodes in rendered graph output."
    ),
    base_url: str = typer.Option("https://build.almalinux.org", "--base-url"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print step-by-step progress to stderr."
    ),
    source: Optional[Path] = typer.Option(
        None,
        "--source",
        "-s",
        help="Optional mock ALBS build JSON. Defaults to built-in openssl graph.",
    ),
) -> None:
    if build_id is not None:
        metadata = fetch_build_metadata(build_id, base_url=base_url, progress=_progress(verbose))
        _log_step(verbose, "Building provenance graph from ALBS metadata")
        graph = graph_from_build_metadata(metadata)
    else:
        if source:
            _log_step(verbose, f"Loading mock ALBS build metadata from {source}")
            graph = load_mock_build(source)
        else:
            _log_step(verbose, "Building built-in OpenSSL mock provenance graph")
            graph = build_mock_package_graph("openssl")
    _log_graph_stats(verbose, graph)

    rpm_selector = rpm or package or "openssl-libs"
    _log_step(verbose, f"Resolving binary RPM selector: {rpm_selector}")
    rpm_node = find_binary_rpm(graph, rpm_selector, arch=arch)
    _log_step(verbose, f"Selected RPM node: {rpm_node.id}")
    _log_step(verbose, "Analyzing source-to-artifact trust path")
    report = trust_path(graph, rpm_node.id)

    if output_format.lower() != "summary" or output:
        _log_step(verbose, "Building focused trust graph")
        focused = focused_trust_graph(graph, rpm_node.id, include_tests=include_tests)
        _log_graph_stats(verbose, focused, label="Focused graph")
        _emit_graph(focused, output_format, output, verbose=verbose)
        return

    table = Table(title=f"Trust path: {rpm_node.label}")
    table.add_column("Check")
    table.add_column("Result")
    for name, value in report["checks"].items():
        table.add_row(name, "ok" if value else "missing")
    console.print(table)
    console.print(f"Complete: {report['complete']}")
    if report["missing"]:
        console.print(f"Missing: {', '.join(report['missing'])}")
    console.print("Path:")
    for node_id in report["path"]:
        console.print(f"  {node_id}")


@app.command()
def render(
    package: str = typer.Argument("openssl", help="Mock package to render."),
    output_format: str = typer.Option("svg", "--format", "-f", help="svg, dot or json."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    graph = build_mock_package_graph(package)
    _emit_graph(graph, output_format, output)


@app.command()
def inspect(
    package: str = typer.Argument("openssl", help="Mock package to inspect."),
) -> None:
    graph = build_mock_package_graph(package)
    table = Table(title=f"ALBS provenance graph: {package}")
    table.add_column("Type")
    table.add_column("Count", justify="right")
    for node_type in NodeType:
        count = len(graph.find_by_type(node_type))
        if count:
            table.add_row(str(node_type), str(count))
    console.print(table)
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        report = graph.trust_path_report(node.id)
        console.print(f"{node.label}: trust path complete={report.complete}")


def main(argv: list[str] | None = None) -> int:
    try:
        app(args=argv, standalone_mode=False)
    except (RpmQueryError, FileNotFoundError, ValueError, SvgRenderError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 2
    except typer.Exit as exc:
        return int(exc.exit_code)
    return 0


def _emit_graph(
    graph: ProvenanceGraph,
    output_format: str,
    output: Path | None,
    *,
    verbose: bool = False,
) -> None:
    normalized = output_format.lower()
    _log_step(verbose, f"Rendering {normalized} output")
    if normalized == "summary":
        content = _summary(graph)
    elif normalized == "json":
        content = graph_to_json(graph)
    elif normalized == "dot":
        content = graph_to_dot(graph)
    elif normalized == "svg":
        content = graph_to_svg(graph)
    else:
        raise ValueError(f"unsupported format: {output_format}")

    if output:
        _log_step(verbose, f"Writing {normalized} output to {output}")
        output.write_text(content, encoding="utf-8")
    else:
        _log_step(verbose, f"Writing {normalized} output to stdout")
        sys.stdout.write(content)


def _progress(verbose: bool) -> Callable[[str], None] | None:
    if not verbose:
        return None
    return lambda message: _log_step(True, message)


def _log_step(verbose: bool, message: str) -> None:
    if verbose:
        verbose_console.print(f"[cyan]step[/cyan] {message}")


def _log_graph_stats(verbose: bool, graph: ProvenanceGraph, label: str = "Graph") -> None:
    if verbose:
        cas_count = len(graph.find_by_type(NodeType.CAS_ATTESTATION))
        verbose_console.print(
            f"[cyan]step[/cyan] {label}: {len(graph.nodes)} nodes, {len(graph.edges)} edges, {cas_count} CAS attestations"
        )


def _summary(graph: ProvenanceGraph) -> str:
    lines: list[str] = []
    for rpm in graph.find_by_type(NodeType.BINARY_RPM):
        report = graph.trust_path_report(rpm.id)
        lines.append(f"Package artifact: {rpm.label}")
        lines.append(f"Trust path complete: {report.complete}")
        for name, value in report.checks.items():
            lines.append(f"  - {name}: {value}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())

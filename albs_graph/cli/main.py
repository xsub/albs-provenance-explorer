from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable, Optional

import click
import typer
from rich.console import Console
from rich.table import Table

from albs_graph.adapters import RpmQueryError, fetch_build_metadata, graph_from_local_rpm
from albs_graph.adapters.albs import graph_from_build_metadata, load_synthetic_build_fixture
from albs_graph.adapters.sbom import import_sbom
from albs_graph.fixtures import build_synthetic_package_graph
from albs_graph.model import NodeType, ProvenanceGraph
from albs_graph.provenance.trust import find_binary_rpm, focused_trust_graph, trust_path
from albs_graph.render import SvgRenderError, graph_to_dot, graph_to_json, graph_to_svg

app = typer.Typer(
    name="albs-graph",
    help="CLI-first provenance graph explorer for ALBS, RPM lineage, SBOMs and trust paths.",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)
console = Console()
verbose_console = Console(stderr=True)


@app.command(
    "fixture",
    help="Build a synthetic package fixture graph for local development and tests.",
    short_help="Build a synthetic fixture graph.",
    no_args_is_help=True,
)
def fixture(
    package: str = typer.Argument(..., help="Synthetic package fixture to build."),
    output_format: str = typer.Option(
        "summary",
        "--format",
        "-f",
        help="summary, json, dot or svg.",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write output to a file."),
) -> None:
    graph = build_synthetic_package_graph(package)
    _emit_graph(graph, output_format, output)


@app.command(
    "fetch-build",
    help="Fetch an ALBS build by positional build id and export a provenance graph.",
    short_help="Fetch an ALBS build graph.",
    no_args_is_help=True,
)
def fetch_build(
    build_id: int = typer.Argument(..., help="ALBS build id."),
    output_format: str = typer.Option("json", "--format", "-f", help="json, dot or svg."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    base_url: str = typer.Option("https://build.almalinux.org", "--base-url"),
    cache: Optional[Path] = typer.Option(
        None, "--cache", help="Read/write raw ALBS API metadata cache JSON."
    ),
    cache_ttl: int = typer.Option(300, "--cache-ttl", help="Cache freshness window in seconds."),
    refresh_cache: bool = typer.Option(
        False, "--refresh-cache", help="Ignore an existing ALBS metadata cache and fetch again."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print step-by-step progress to stderr."
    ),
) -> None:
    metadata = fetch_build_metadata(
        build_id,
        base_url=base_url,
        progress=_progress(verbose),
        cache_path=cache,
        refresh_cache=refresh_cache,
        cache_ttl_seconds=cache_ttl,
    )
    _log_step(verbose, "Building provenance graph from ALBS metadata")
    graph = graph_from_build_metadata(metadata)
    _log_graph_stats(verbose, graph)
    _emit_graph(graph, output_format, output, verbose=verbose)


@app.command(
    "fetch",
    help="Fetch an ALBS build by --build-id and export JSON, DOT or SVG.",
    short_help="Fetch an ALBS build by --build-id.",
    no_args_is_help=True,
)
def fetch(
    build_id: int = typer.Option(..., "--build-id", "-b", help="ALBS build id."),
    output_format: str = typer.Option("json", "--format", "-f", help="json, dot or svg."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    base_url: str = typer.Option("https://build.almalinux.org", "--base-url"),
    cache: Optional[Path] = typer.Option(
        None, "--cache", help="Read/write raw ALBS API metadata cache JSON."
    ),
    cache_ttl: int = typer.Option(300, "--cache-ttl", help="Cache freshness window in seconds."),
    refresh_cache: bool = typer.Option(
        False, "--refresh-cache", help="Ignore an existing ALBS metadata cache and fetch again."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print step-by-step progress to stderr."
    ),
) -> None:
    metadata = fetch_build_metadata(
        build_id,
        base_url=base_url,
        progress=_progress(verbose),
        cache_path=cache,
        refresh_cache=refresh_cache,
        cache_ttl_seconds=cache_ttl,
    )
    _log_step(verbose, "Building provenance graph from ALBS metadata")
    graph = graph_from_build_metadata(metadata)
    _log_graph_stats(verbose, graph)
    _emit_graph(graph, output_format, output, verbose=verbose)


@app.command(
    "inspect-rpm",
    help="Inspect a local RPM and emit package, provide and require graph facts.",
    short_help="Inspect a local RPM.",
    no_args_is_help=True,
)
def inspect_rpm(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Local RPM path."),
    output_format: str = typer.Option("json", "--format", "-f", help="json or dot."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    graph = graph_from_local_rpm(path)
    _emit_graph(graph, output_format, output)


@app.command(
    "import-sbom",
    help="Import SPDX JSON or CycloneDX JSON as SBOM evidence nodes and edges.",
    short_help="Import SPDX or CycloneDX SBOM.",
    no_args_is_help=True,
)
def import_sbom_command(
    path: Path = typer.Argument(
        ..., exists=True, dir_okay=False, help="SPDX JSON or CycloneDX JSON SBOM."
    ),
    output_format: str = typer.Option("json", "--format", "-f", help="json or dot."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    graph = import_sbom(path)
    _emit_graph(graph, output_format, output)


@app.command(
    "trust-path",
    help="Show or render the focused source-to-artifact trust path for one binary RPM.",
    short_help="Show a focused RPM trust path.",
    no_args_is_help=True,
)
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
    cache: Optional[Path] = typer.Option(
        None, "--cache", help="Read/write raw ALBS API metadata cache JSON when using --build-id."
    ),
    cache_ttl: int = typer.Option(300, "--cache-ttl", help="Cache freshness window in seconds."),
    refresh_cache: bool = typer.Option(
        False, "--refresh-cache", help="Ignore an existing ALBS metadata cache and fetch again."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print step-by-step progress to stderr."
    ),
    source: Optional[Path] = typer.Option(
        None,
        "--source",
        "-s",
        help="Optional synthetic ALBS build metadata JSON.",
    ),
) -> None:
    if build_id is not None:
        metadata = fetch_build_metadata(
            build_id,
            base_url=base_url,
            progress=_progress(verbose),
            cache_path=cache,
            refresh_cache=refresh_cache,
            cache_ttl_seconds=cache_ttl,
        )
        _log_step(verbose, "Building provenance graph from ALBS metadata")
        graph = graph_from_build_metadata(metadata)
    elif source:
        _log_step(verbose, f"Loading synthetic ALBS build metadata from {source}")
        graph = load_synthetic_build_fixture(source)
    else:
        raise ValueError("trust-path requires --build-id or --source")
    _log_graph_stats(verbose, graph)

    rpm_selector = rpm or package
    if rpm_selector is None:
        raise ValueError("trust-path requires --rpm or a binary RPM node/package argument")
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
    console.print(f"Provenance complete: {report['provenance_complete']}")
    console.print(f"Security context complete: {report['security_context_complete']}")
    console.print(f"Complete: {report['complete']}")
    if report["missing_provenance"]:
        console.print(f"Missing provenance: {', '.join(report['missing_provenance'])}")
    if report["missing_security_context"]:
        console.print(
            f"Missing security context: {', '.join(report['missing_security_context'])}"
        )
    console.print("Path:")
    for node_id in report["path"]:
        console.print(f"  {node_id}")


@app.command(
    "render-fixture",
    help="Render a synthetic package fixture graph as SVG, DOT or JSON.",
    short_help="Render a synthetic fixture graph.",
    no_args_is_help=True,
)
def render_fixture(
    package: str = typer.Argument(..., help="Synthetic package fixture to render."),
    output_format: str = typer.Option("svg", "--format", "-f", help="svg, dot or json."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    graph = build_synthetic_package_graph(package)
    _emit_graph(graph, output_format, output)


@app.command(
    "inspect-fixture",
    help="Inspect synthetic fixture graph counts and trust-path coverage.",
    short_help="Inspect a synthetic fixture graph.",
    no_args_is_help=True,
)
def inspect_fixture(
    package: str = typer.Argument(..., help="Synthetic package fixture to inspect."),
) -> None:
    graph = build_synthetic_package_graph(package)
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
        console.print(
            f"{node.label}: provenance complete={report.provenance_complete}, "
            f"security context complete={report.security_context_complete}"
        )


def main(argv: list[str] | None = None) -> int:
    try:
        app(args=argv, standalone_mode=False)
    except click.ClickException as exc:
        exc.show()
        return int(exc.exit_code)
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
        lines.append(f"Provenance complete: {report.provenance_complete}")
        lines.append(f"Security context complete: {report.security_context_complete}")
        lines.append(f"Trust path complete: {report.complete}")
        for name, value in report.checks.items():
            lines.append(f"  - {name}: {value}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

from pathlib import Path
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from albs_graph.adapters import RpmQueryError, fetch_build_metadata, graph_from_local_rpm
from albs_graph.adapters.albs import graph_from_build_metadata, load_mock_build
from albs_graph.adapters.sbom import import_sbom
from albs_graph.mock_data import build_mock_package_graph
from albs_graph.model import NodeType, ProvenanceGraph
from albs_graph.provenance.trust import trust_path
from albs_graph.render import SvgRenderError, graph_to_dot, graph_to_json, graph_to_svg

app = typer.Typer(
    name="albs-graph",
    help="CLI-first provenance graph explorer for ALBS, RPM lineage, SBOMs and trust paths.",
    no_args_is_help=True,
)
console = Console()


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
) -> None:
    metadata = fetch_build_metadata(build_id, base_url=base_url)
    graph = graph_from_build_metadata(metadata)
    _emit_graph(graph, output_format, output)


@app.command("fetch")
def fetch(
    build_id: int = typer.Option(..., "--build-id", "-b", help="ALBS build id."),
    output_format: str = typer.Option("json", "--format", "-f", help="json, dot or svg."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    base_url: str = typer.Option("https://build.almalinux.org", "--base-url"),
) -> None:
    metadata = fetch_build_metadata(build_id, base_url=base_url)
    graph = graph_from_build_metadata(metadata)
    _emit_graph(graph, output_format, output)


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
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="SPDX JSON or CycloneDX JSON SBOM."),
    output_format: str = typer.Option("json", "--format", "-f", help="json or dot."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    graph = import_sbom(path)
    _emit_graph(graph, output_format, output)


@app.command("trust-path")
def trust_path_command(
    package: str = typer.Argument("openssl-libs", help="Binary RPM node id or package name."),
    source: Optional[Path] = typer.Option(
        None,
        "--source",
        "-s",
        help="Optional mock ALBS build JSON. Defaults to built-in openssl graph.",
    ),
) -> None:
    graph = load_mock_build(source) if source else build_mock_package_graph("openssl")
    report = trust_path(graph, package)
    table = Table(title=f"Trust path: {package}")
    table.add_column("Check")
    table.add_column("Result")
    for name, value in report["checks"].items():
        table.add_row(name, "ok" if value else "missing")
    console.print(table)
    console.print(f"Complete: {report['complete']}")
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


def _emit_graph(graph: ProvenanceGraph, output_format: str, output: Path | None) -> None:
    normalized = output_format.lower()
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
        output.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)


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

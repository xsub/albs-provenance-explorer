from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Callable, Optional

import click
import typer
from rich.console import Console
from rich.table import Table

from albs_graph.adapters import (
    RpmQueryError,
    SourceCheckoutError,
    SourceEvidenceSummary,
    attach_source_evidence,
    checkout_git_source,
    fetch_build_metadata,
    graph_from_local_rpm,
)
from albs_graph.adapters.albs import graph_from_build_metadata, load_synthetic_build_fixture
from albs_graph.adapters.cas import verify_graph_cas
from albs_graph.adapters.dnf import (
    build_soname_index,
    collect_soname_names,
    enrich_graph_with_dnf,
    resolve_soname_claims,
)
from albs_graph.adapters.errata import attach_errata_file
from albs_graph.adapters.pylang import attach_python_requirements
from albs_graph.adapters.rpm_payload import enrich_graph_with_rpm_payloads
from albs_graph.adapters.rpm_remote import enrich_graph_with_rpm_headers
from albs_graph.adapters.rpmgraph import (
    RpmgraphUnavailable,
    enrich_graph_with_rpmgraph,
    run_repograph,
)
from albs_graph.adapters.sbom import attach_cyclonedx_sbom_claims, import_sbom
from albs_graph.fixtures import build_synthetic_package_graph
from albs_graph.model import NodeType, ProvenanceGraph
from albs_graph.provenance.coverage import coverage_report
from albs_graph.provenance.identify import identify_file
from albs_graph.provenance.reconcile import reconcile_dependency_claims
from albs_graph.provenance.universe import (
    build_arch_universe,
    dependencies_of,
    dependency_paths,
    dependents_of,
    neighborhood_subgraph,
    path_subgraph,
)
from albs_graph.provenance.trust import (
    find_binary_rpm,
    focused_trust_graph,
    make_binary_rpm_selector,
    select_default_binary_rpm,
    trust_path,
)
from albs_graph.render import SvgRenderError, graph_to_dot, graph_to_json, graph_to_svg
from albs_graph.store import load_graph, save_graph, sql_dependencies, sql_dependents

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
    _log_package_metadata(verbose, metadata.package, metadata.package_source)
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
    _log_package_metadata(verbose, metadata.package, metadata.package_source)
    _log_step(verbose, "Building provenance graph from ALBS metadata")
    graph = graph_from_build_metadata(metadata)
    _log_graph_stats(verbose, graph)
    _emit_graph(graph, output_format, output, verbose=verbose)


@app.command(
    "checkout-source",
    help="Checkout the exact git source commit referenced by an ALBS build.",
    short_help="Checkout ALBS git source.",
    no_args_is_help=True,
)
def checkout_source(
    build_id: int = typer.Option(..., "--build-id", "-b", help="ALBS build id."),
    destination: Path = typer.Option(..., "--dest", "-d", help="Destination checkout directory."),
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
    _log_package_metadata(verbose, metadata.package, metadata.package_source)
    _log_step(
        verbose,
        f"Checking out {metadata.source_repository} at commit {metadata.commit}",
    )
    checkout_git_source(metadata, destination)
    console.print(f"Checked out {metadata.package} source at {metadata.commit} to {destination}")


@app.command(
    "source-evidence",
    help="Attach source tree evidence discovered from an ALBS-referenced checkout.",
    short_help="Analyze source evidence for an ALBS build.",
    no_args_is_help=True,
)
def source_evidence(
    source_dir: Path = typer.Argument(..., exists=True, file_okay=False, help="Source checkout."),
    build_id: int = typer.Option(..., "--build-id", "-b", help="ALBS build id."),
    output_format: str = typer.Option(
        "summary", "--format", "-f", help="summary, json, dot or svg."
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    base_url: str = typer.Option("https://build.almalinux.org", "--base-url"),
    cache: Optional[Path] = typer.Option(
        None, "--cache", help="Read/write raw ALBS API metadata cache JSON."
    ),
    cache_ttl: int = typer.Option(300, "--cache-ttl", help="Cache freshness window in seconds."),
    refresh_cache: bool = typer.Option(
        False, "--refresh-cache", help="Ignore an existing ALBS metadata cache and fetch again."
    ),
    file_inventory: bool = typer.Option(
        True,
        "--file-inventory/--no-file-inventory",
        help="Include every source file as a hashed graph node.",
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
    _log_package_metadata(verbose, metadata.package, metadata.package_source)
    _log_step(verbose, "Building provenance graph from ALBS metadata")
    graph = graph_from_build_metadata(metadata)
    _log_step(verbose, f"Scanning source evidence from {source_dir}")
    summary = attach_source_evidence(
        graph,
        metadata,
        source_dir,
        include_file_inventory=file_inventory,
    )
    _log_step(
        verbose,
        (
            "Source evidence: "
            f"{summary.files} files, {summary.manifests} manifests, "
            f"{summary.spec_files} spec files, {summary.dependency_specs} dependencies"
        ),
    )
    if output_format.lower() == "summary" and not output:
        _print_source_evidence_summary(summary)
        return
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
    "coverage",
    help="Reconcile dependency evidence and report five-axis provenance coverage.",
    short_help="Report multi-axis coverage.",
    no_args_is_help=True,
)
def coverage_command(
    build_id: Optional[int] = typer.Option(
        None, "--build-id", "-b", help="Fetch a live ALBS build id."
    ),
    source: Optional[Path] = typer.Option(
        None, "--source", "-s", help="Cached ALBS build metadata JSON."
    ),
    with_rpm_headers: bool = typer.Option(
        False,
        "--with-rpm-headers",
        help="Range-read public RPM headers to add dynamic-linkage claims (network).",
    ),
    with_rpm_payloads: bool = typer.Option(
        False,
        "--with-rpm-payloads",
        help="Download full RPM payloads and parse ELF objects (rung 4; network).",
    ),
    use_cas: bool = typer.Option(
        False,
        "--use-cas",
        help="Verify CAS attestation hashes with the 'cas' CLI if present (opt-in; "
        "never required, degrades to 'unavailable' when cas is missing).",
    ),
    sbom: Optional[Path] = typer.Option(
        None, "--sbom", help="CycloneDX JSON SBOM file to attach as dependency claims."
    ),
    sbom_subject: Optional[str] = typer.Option(
        None,
        "--sbom-subject",
        help="Binary RPM name/node id the SBOM describes (defaults to a representative RPM).",
    ),
    requirements: Optional[Path] = typer.Option(
        None, "--requirements", help="Python requirements.txt to attach as PyPI dependency claims."
    ),
    requirements_subject: Optional[str] = typer.Option(
        None, "--requirements-subject", help="Binary RPM the requirements belong to."
    ),
    errata: Optional[Path] = typer.Option(
        None, "--errata", help="Errata JSON (id, type, severity, cves) to attach as security context."
    ),
    errata_subject: Optional[str] = typer.Option(
        None, "--errata-subject", help="Binary RPM the errata applies to."
    ),
    repograph_dot: Optional[Path] = typer.Option(
        None,
        "--repograph-dot",
        help="Ingest a `dnf repograph` / `rpmgraph` dot file as resolved RPM dependency claims.",
    ),
    repograph: Optional[str] = typer.Option(
        None,
        "--repograph",
        help="Run `dnf repograph <repo>` live (AlmaLinux host only) and ingest it.",
    ),
    use_dnf: bool = typer.Option(
        False,
        "--use-dnf",
        help="Resolve dependencies per package with `dnf repoquery` (AlmaLinux host; "
        "adds versioned RUNTIME + weak OPTIONAL claims). Degrades to no-op if dnf is absent.",
    ),
    resolve_sonames: bool = typer.Option(
        False,
        "--resolve-sonames",
        help="Map soname claims to providing packages via `dnf --whatprovides` so they "
        "reconcile with package claims (AlmaLinux host).",
    ),
    provides_map: Optional[Path] = typer.Option(
        None,
        "--provides-map",
        help="JSON {soname: provider-NEVRA} to resolve sonames offline (no dnf needed).",
    ),
    package: Optional[str] = typer.Option(
        None, "--package", help="Only enrich binary RPMs with this package name."
    ),
    arch: Optional[str] = typer.Option(
        None, "--arch", help="Only enrich this arch (default: x86_64 + noarch)."
    ),
    all_archs: bool = typer.Option(
        False, "--all-archs", help="Enrich every architecture, not just x86_64 + noarch."
    ),
    all_packages: bool = typer.Option(
        False, "--all-packages", help="Enrich every package (default; pairs with --all-archs)."
    ),
    limit: Optional[int] = typer.Option(
        None, "--limit", help="Max binary RPMs to fetch/analyze during enrichment."
    ),
    output_format: str = typer.Option("summary", "--format", "-f", help="summary or json."),
    base_url: str = typer.Option("https://build.almalinux.org", "--base-url"),
    cache: Optional[Path] = typer.Option(None, "--cache", help="ALBS metadata cache JSON."),
    cache_ttl: int = typer.Option(300, "--cache-ttl", help="Cache freshness window in seconds."),
    refresh_cache: bool = typer.Option(False, "--refresh-cache", help="Ignore an existing cache."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print progress to stderr."),
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
        graph = graph_from_build_metadata(metadata)
    elif source:
        _log_step(verbose, f"Loading ALBS build metadata from {source}")
        graph = load_synthetic_build_fixture(source)
    else:
        raise ValueError("coverage requires --build-id or --source")
    _log_graph_stats(verbose, graph)
    selector = make_binary_rpm_selector(package=package, arch=arch, all_archs=all_archs)
    _ = all_packages  # default behavior; flag documents intent and pairs with --all-archs

    rpmgraph_result = None
    dot_text: str | None = None
    if repograph_dot is not None:
        _log_step(verbose, f"Ingesting dnf repograph/rpmgraph dot from {repograph_dot}")
        dot_text = repograph_dot.read_text(encoding="utf-8")
    elif repograph is not None:
        _log_step(verbose, f"Running dnf repograph {repograph}")
        try:
            dot_text = run_repograph(repograph)
        except RpmgraphUnavailable as exc:
            console.print(f"[yellow]repograph unavailable:[/yellow] {exc}")
    if dot_text is not None:
        rpmgraph_result = enrich_graph_with_rpmgraph(
            graph, dot_text, evidence="repograph", node_selector=selector
        )

    dnf_result = None
    if use_dnf:
        _log_step(verbose, "Resolving dependencies per package with dnf repoquery")
        dnf_result = enrich_graph_with_dnf(
            graph, node_selector=selector, limit=limit, on_progress=_progress(verbose)
        )

    sbom_result = None
    if sbom is not None:
        subject_node = (
            find_binary_rpm(graph, sbom_subject, arch=arch)
            if sbom_subject
            else select_default_binary_rpm(graph, arch=arch)
        )
        _log_step(verbose, f"Attaching CycloneDX SBOM {sbom} to {subject_node.id}")
        sbom_result = attach_cyclonedx_sbom_claims(graph, subject_node.id, sbom)

    python_result = None
    if requirements is not None:
        req_subject = (
            find_binary_rpm(graph, requirements_subject, arch=arch)
            if requirements_subject
            else select_default_binary_rpm(graph, arch=arch)
        )
        _log_step(verbose, f"Attaching Python requirements {requirements} to {req_subject.id}")
        python_result = attach_python_requirements(graph, req_subject.id, requirements)

    errata_id = None
    if errata is not None:
        errata_node_subject = (
            find_binary_rpm(graph, errata_subject, arch=arch)
            if errata_subject
            else select_default_binary_rpm(graph, arch=arch)
        )
        _log_step(verbose, f"Attaching errata {errata} to {errata_node_subject.id}")
        errata_id = attach_errata_file(graph, errata_node_subject.id, errata)

    enrichment = None
    if with_rpm_headers:
        _log_step(verbose, "Range-reading RPM headers for dynamic-linkage claims")
        enrichment = enrich_graph_with_rpm_headers(
            graph, limit=limit, on_progress=_progress(verbose), node_selector=selector
        )

    payload_result = None
    if with_rpm_payloads:
        _log_step(verbose, "Downloading RPM payloads and parsing ELF objects (rung 4)")
        payload_result = enrich_graph_with_rpm_payloads(
            graph, limit=limit, on_progress=_progress(verbose), node_selector=selector
        )

    soname_result = None
    if provides_map is not None or resolve_sonames:
        if provides_map is not None:
            _log_step(verbose, f"Resolving sonames from provides map {provides_map}")
            index = json.loads(provides_map.read_text(encoding="utf-8"))
        else:
            _log_step(verbose, "Resolving sonames to packages via dnf --whatprovides")
            index = build_soname_index(collect_soname_names(graph))
        soname_result = resolve_soname_claims(graph, index)

    cas_report = None
    if use_cas:
        _log_step(verbose, "Verifying CAS attestation hashes (opt-in)")
        cas_report = verify_graph_cas(graph, use_cas=True)

    _log_step(verbose, "Reconciling dependency claims")
    reconciliation = reconcile_dependency_claims(graph)
    report = coverage_report(graph)

    if output_format.lower() == "json":
        payload: dict[str, object] = {
            "coverage": report.to_dict(),
            "reconciliation": reconciliation.to_dict(),
        }
        if enrichment is not None:
            payload["rpm_header_enrichment"] = enrichment.to_dict()
        if payload_result is not None:
            payload["rpm_payload_enrichment"] = payload_result.to_dict()
        if sbom_result is not None:
            payload["sbom"] = sbom_result.to_dict()
        if cas_report is not None:
            payload["cas"] = cas_report.to_dict()
        if rpmgraph_result is not None:
            payload["repograph"] = rpmgraph_result.to_dict()
        if dnf_result is not None:
            payload["dnf"] = dnf_result.to_dict()
        if soname_result is not None:
            payload["soname_resolution"] = soname_result.to_dict()
        if python_result is not None:
            payload["python"] = python_result.to_dict()
        if errata_id is not None:
            payload["errata"] = errata_id
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return

    table = Table(title="Provenance coverage (five axes)")
    table.add_column("Axis")
    table.add_column("Covered", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Fraction", justify="right")
    for axis in report.axes():
        table.add_row(axis.name, str(axis.covered), str(axis.total), f"{axis.fraction:.2f}")
    console.print(table)
    if rpmgraph_result is not None:
        console.print(
            f"repograph: {rpmgraph_result.claims_added} resolved RPM dep claims "
            f"from {rpmgraph_result.matched_edges} matched edges "
            f"({rpmgraph_result.edges} total)"
        )
    if dnf_result is not None:
        if not dnf_result.available:
            console.print(
                f"dnf: unavailable; {dnf_result.packages_seen} packages skipped "
                "(install dnf or run on an AlmaLinux host)"
            )
        else:
            console.print(
                f"dnf repoquery: {dnf_result.resolved_claims} runtime + "
                f"{dnf_result.weak_claims} weak resolved claims across "
                f"{dnf_result.packages_queried} packages"
            )
    if soname_result is not None:
        console.print(
            f"soname resolution: {soname_result.resolved}/{soname_result.sonames} sonames "
            f"mapped to packages, {soname_result.claims_added} provider claims added"
        )
    if sbom_result is not None:
        console.print(
            f"SBOM: {sbom_result.claims_added} component claims "
            f"from {sbom_result.components} components"
        )
    if python_result is not None:
        console.print(
            f"Python: {python_result.claims_added} PyPI claims from "
            f"{python_result.requirements} requirements"
        )
    if errata_id is not None:
        console.print(f"Errata: attached {errata_id} (security context)")
    if enrichment is not None:
        console.print(
            f"RPM header enrichment: {enrichment.headers_fetched}/{enrichment.artifacts_seen} "
            f"headers fetched, {enrichment.claims_added} dynamic-linkage claims added"
        )
    if payload_result is not None:
        console.print(
            f"RPM payload analysis: {payload_result.payloads_read}/{payload_result.artifacts_seen} "
            f"payloads, {payload_result.elf_objects} ELF objects, "
            f"{payload_result.soname_claims} NEEDED claims, "
            f"{payload_result.static_objects} static objects"
        )
    if cas_report is not None:
        if not cas_report.available:
            console.print(
                f"CAS: unavailable (cas CLI not found); {cas_report.attestations} attestations "
                "reported, not verified"
            )
        else:
            console.print(
                f"CAS: {cas_report.verified} verified, {cas_report.failed} failed, "
                f"{cas_report.unavailable} unavailable of {cas_report.attestations} attestations"
            )
    console.print(
        f"Reconciled dependencies: {reconciliation.resolutions}; "
        f"conflicts: {reconciliation.conflict_count}"
    )
    for conflict in reconciliation.conflicts[:20]:
        versions = ", ".join(conflict.versions) or "n/a"
        console.print(f"  [{conflict.kind}] {conflict.coordinate}: versions={versions}")


@app.command(
    "identify",
    help="Trace every element behind a file (creation + installation lineage).",
    short_help="Trace a file's provenance.",
    no_args_is_help=True,
)
def identify_command(
    filepath: str = typer.Argument(..., help="File path, e.g. /usr/sbin/nginx."),
    build_id: Optional[int] = typer.Option(None, "--build-id", "-b", help="Fetch a live ALBS build."),
    source: Optional[Path] = typer.Option(None, "--source", "-s", help="Cached ALBS metadata JSON."),
    owner: Optional[str] = typer.Option(
        None, "--owner", help="Owning package name (skips host rpm -qf lookup)."
    ),
    arch: Optional[str] = typer.Option(None, "--arch", help="Disambiguate by architecture."),
    output_format: str = typer.Option("summary", "--format", "-f", help="summary or json."),
    base_url: str = typer.Option("https://build.almalinux.org", "--base-url"),
    cache: Optional[Path] = typer.Option(None, "--cache", help="ALBS metadata cache JSON."),
    cache_ttl: int = typer.Option(300, "--cache-ttl", help="Cache freshness window in seconds."),
    refresh_cache: bool = typer.Option(False, "--refresh-cache", help="Ignore an existing cache."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print progress to stderr."),
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
        graph = graph_from_build_metadata(metadata)
    elif source:
        graph = load_synthetic_build_fixture(source)
    else:
        raise ValueError("identify requires --build-id or --source")

    report = identify_file(graph, filepath, owner_package=owner, arch=arch)

    if output_format.lower() == "json":
        sys.stdout.write(json.dumps(report.to_dict(), indent=2) + "\n")
        return

    if not report.found:
        console.print(f"[yellow]{filepath}[/yellow]: {report.detail}")
        return
    table = Table(title=f"Provenance of {filepath}  (package: {report.package})")
    table.add_column("Role")
    table.add_column("Element")
    for element in report.elements:
        table.add_row(element.role, element.label)
    console.print(table)
    console.print(f"Provenance complete: {report.provenance_complete}")
    console.print(f"Security context complete: {report.security_context_complete}")
    if report.dependencies:
        shown = ", ".join(report.dependencies[:15])
        more = f" (+{len(report.dependencies) - 15} more)" if len(report.dependencies) > 15 else ""
        console.print(f"Dependencies ({len(report.dependencies)}): {shown}{more}")


@app.command(
    "trust-path",
    help="Show or render the focused source-to-artifact trust path for one binary RPM.",
    short_help="Show a focused RPM trust path.",
    no_args_is_help=True,
)
def trust_path_command(
    package: Optional[str] = typer.Argument(
        None,
        help="Optional binary RPM node id or package name. Defaults to an ALBS-derived artifact.",
    ),
    rpm: Optional[str] = typer.Option(
        None,
        "--rpm",
        help="Optional binary RPM name or node id. Omit to select from ALBS build metadata.",
    ),
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
        _log_package_metadata(verbose, metadata.package, metadata.package_source)
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
        _log_step(verbose, "No RPM selector provided; selecting representative binary RPM")
        rpm_node = select_default_binary_rpm(graph, arch=arch)
    else:
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
    "universe",
    help="Build and traverse a cross-package dependency universe (e.g. who links libc).",
    short_help="Build/traverse the dependency universe.",
    no_args_is_help=True,
)
def universe_command(
    repograph_dot: list[Path] = typer.Option(
        [], "--repograph-dot", help="repo dot(s); repeatable to merge baseos+appstream+crb."
    ),
    source: list[Path] = typer.Option(
        [], "--source", "-s", help="ALBS metadata JSON(s); repeatable, merged into the universe."
    ),
    arch: Optional[str] = typer.Option(None, "--arch", help="Restrict the universe to an arch."),
    dependents_of_cap: Optional[str] = typer.Option(
        None, "--dependents-of", help="List everything that requires this capability/package."
    ),
    dependencies_of_node: Optional[str] = typer.Option(
        None, "--dependencies-of", help="List a node's direct dependencies."
    ),
    path_from: Optional[str] = typer.Option(None, "--path-from", help="Traverse from this node..."),
    path_to: Optional[str] = typer.Option(None, "--path-to", help="...to this capability/package."),
    db: Optional[Path] = typer.Option(
        None, "--db", help="Query/load a persisted universe SQLite store instead of building."
    ),
    save: Optional[Path] = typer.Option(
        None, "--save", help="Persist the built universe to a SQLite store (low-footprint)."
    ),
    output_format: str = typer.Option("summary", "--format", "-f", help="summary, json, dot, svg."),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    # A graphical format renders the focused subgraph for a query; otherwise the
    # query result is printed as text.
    render = output_format.lower() in {"json", "dot", "svg"}

    # SQL fast path: one-hop text queries run directly against the store without
    # loading the whole universe into memory.
    if db is not None and not render:
        if dependents_of_cap:
            names = sql_dependents(db, dependents_of_cap)
            console.print(f"{len(names)} dependents of {dependents_of_cap}:")
            for name in names:
                console.print(f"  {name}")
            return
        if dependencies_of_node:
            names = sql_dependencies(db, dependencies_of_node)
            console.print(f"{len(names)} dependencies of {dependencies_of_node}:")
            for name in names:
                console.print(f"  {name}")
            return

    if db is not None:
        graph = load_graph(db)
    elif repograph_dot or source:
        graph = build_arch_universe(
            dots=[path.read_text(encoding="utf-8") for path in repograph_dot],
            graphs=[load_synthetic_build_fixture(path) for path in source],
            arch=arch,
        )
        if save is not None:
            stats = save_graph(graph, save)
            console.print(f"Saved universe to {save}: {stats.nodes} nodes, {stats.edges} edges")
    else:
        raise ValueError("universe requires --repograph-dot, --source, or --db")

    if dependents_of_cap:
        if render:
            _emit_graph(neighborhood_subgraph(graph, dependents_of_cap, incoming=True), output_format, output)
            return
        names = dependents_of(graph, dependents_of_cap)
        console.print(f"{len(names)} dependents of {dependents_of_cap}:")
        for name in names:
            console.print(f"  {name}")
        return
    if dependencies_of_node:
        node_id = _resolve_universe_node(graph, dependencies_of_node)
        if render:
            _emit_graph(neighborhood_subgraph(graph, node_id, incoming=False), output_format, output)
            return
        names = dependencies_of(graph, node_id)
        console.print(f"{len(names)} dependencies of {dependencies_of_node}:")
        for name in names:
            console.print(f"  {name}")
        return
    if path_from and path_to:
        paths = dependency_paths(graph, _resolve_universe_node(graph, path_from), path_to)
        if render:
            _emit_graph(path_subgraph(graph, paths), output_format, output)
            return
        console.print(f"{len(paths)} path(s) from {path_from} to {path_to}:")
        for chain in paths:
            console.print("  " + " -> ".join(graph.nodes[node_id].label for node_id in chain))
        return

    if output_format.lower() == "summary":
        console.print(
            f"Universe: {len(graph.nodes)} nodes, {len(graph.edges)} edges "
            f"({len(graph.find_by_type(NodeType.BINARY_RPM))} packages)"
        )
        return
    _emit_graph(graph, output_format, output)


def _resolve_universe_node(graph: ProvenanceGraph, selector: str) -> str:
    if selector in graph.nodes:
        return selector
    for prefix in ("pkg:", "cap:rpm:", "cap:"):
        if f"{prefix}{selector}" in graph.nodes:
            return f"{prefix}{selector}"
    for node in graph.nodes.values():
        if str(node.metadata.get("name") or "") == selector:
            return node.id
    return selector


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
    except (
        RpmQueryError,
        SourceCheckoutError,
        FileNotFoundError,
        ValueError,
        SvgRenderError,
    ) as exc:
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


def _log_package_metadata(verbose: bool, package: str, source: str) -> None:
    _log_step(verbose, f"Source package: {package} (from ALBS {source})")


def _log_graph_stats(verbose: bool, graph: ProvenanceGraph, label: str = "Graph") -> None:
    if verbose:
        cas_count = len(graph.find_by_type(NodeType.CAS_ATTESTATION))
        verbose_console.print(
            f"[cyan]step[/cyan] {label}: {len(graph.nodes)} nodes, {len(graph.edges)} edges, {cas_count} CAS attestations"
        )


def _print_source_evidence_summary(summary: SourceEvidenceSummary) -> None:
    table = Table(title="Source Evidence")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for key in (
        "files",
        "manifests",
        "spec_files",
        "dependency_specs",
        "source_refs",
        "patch_refs",
    ):
        table.add_row(key, str(getattr(summary, key)))
    ecosystems = ", ".join(summary.ecosystems) or "none"
    table.add_row("ecosystems", ecosystems)
    console.print(table)


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

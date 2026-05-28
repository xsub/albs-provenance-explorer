"""Analysis pipeline: declarative enrichment orchestration.

Commands like ``coverage`` (and, later, ``identify`` / ``trust-path`` / ``vuln`` /
``license``) all do the same thing: load a graph, run a chosen subset of
enrichments in a fixed order, reconcile, then render. That orchestration used to
be re-encoded inline in each command function -- long, untested, and easy to
drift between commands.

This module factors it out:

* :class:`RunSpec` -- the resolved inputs for one run (which enrichments, with
  what options). Built from CLI args; nothing Typer- or filesystem-specific
  leaks deeper.
* :class:`EnrichmentStep` -- one optional enrichment (a thin wrapper over an
  ``enrich_graph_with_*`` / ``attach_*`` adapter call + its guard). ``DEFAULT_STEPS``
  is the ordered registry, in the exact historical ``coverage`` order, so
  behaviour is preserved; a caller can pass a custom subset.
* :class:`AnalysisPipeline` -- runs the applicable steps against a
  :class:`RecordingGraph`, reconciles, and returns a :class:`PipelineResult`
  (the enriched graph, each step's result, the reconciliation, and the cumulative
  :class:`EvidencePatch`). With ``dry_run=True`` it runs against a copy, so the
  source graph is untouched.

Rendering stays in the commands: the pipeline stops at "enriched graph + per-step
results + reconciliation", and a command fetches each step's result by name.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from albs_graph.adapters.cas import verify_graph_cas
from albs_graph.adapters.dnf import (
    build_soname_index,
    collect_soname_names,
    enrich_graph_with_dnf,
    resolve_soname_claims,
)
from albs_graph.adapters.errata import attach_errata_file
from albs_graph.adapters.pylang import attach_python_imports, attach_python_requirements
from albs_graph.adapters.rpm_payload import enrich_graph_with_rpm_payloads
from albs_graph.adapters.rpm_remote import enrich_graph_with_rpm_headers
from albs_graph.adapters.rpmgraph import enrich_graph_with_rpmgraph
from albs_graph.adapters.rpmsig import verify_graph_signatures
from albs_graph.adapters.sbom import attach_cyclonedx_sbom_claims, enrich_graph_with_build_sbom
from albs_graph.model import EvidencePatch, Node, ProvenanceGraph, RecordingGraph
from albs_graph.provenance.reconcile import ReconciliationReport, reconcile_dependency_claims
from albs_graph.provenance.trust import (
    find_binary_rpm,
    make_binary_rpm_selector,
    select_default_binary_rpm,
)
from albs_graph.security.cpe import CpeDictionary, verify_graph_cpe

Progress = Callable[[str], None] | None
NodeSelector = Callable[[Node], bool]


@dataclass(frozen=True)
class RunSpec:
    """Resolved inputs for one analysis run (built from CLI args)."""

    package: str | None = None
    arch: str | None = None
    all_archs: bool = False
    limit: int | None = None
    build_sbom: Path | None = None
    repograph_dot_text: str | None = None  # already read from a file / a live run
    use_dnf: bool = False
    sbom: Path | None = None
    sbom_subject: str | None = None
    requirements: Path | None = None
    requirements_subject: str | None = None
    imports: Path | None = None
    imports_subject: str | None = None
    module_map: Path | None = None
    errata: Path | None = None
    errata_subject: str | None = None
    verify_cpe: Path | None = None
    with_rpm_headers: bool = False
    with_rpm_payloads: bool = False
    resolve_sonames: bool = False
    provides_map: Path | None = None
    use_cas: bool = False
    verify_signatures: bool = False
    # Network performance knobs for HeadersStep + PayloadStep.
    max_concurrency: int = 4
    http_cache: bool = True       # header cache (tiny); default on
    cache_payloads: bool = False  # payload cache (5-50 MB each); opt-in


@dataclass(frozen=True)
class EnrichmentContext:
    """What a step needs: the (recording) graph, the spec, a selector, progress."""

    graph: ProvenanceGraph
    spec: RunSpec
    selector: NodeSelector
    on_progress: Progress

    def log(self, message: str) -> None:
        if self.on_progress:
            self.on_progress(message)

    def subject(self, name: str | None) -> Node:
        """The binary RPM a subject-scoped attach step targets."""

        if name:
            return find_binary_rpm(self.graph, name, arch=self.spec.arch)
        return select_default_binary_rpm(self.graph, arch=self.spec.arch)


class EnrichmentStep(Protocol):
    """One optional enrichment: a guard plus an adapter call."""

    @property
    def name(self) -> str: ...

    def applies(self, spec: RunSpec) -> bool: ...

    def run(self, ctx: EnrichmentContext) -> Any: ...


@dataclass(frozen=True)
class BuildSbomStep:
    name: str = "build_sbom"

    def applies(self, spec: RunSpec) -> bool:
        return spec.build_sbom is not None

    def run(self, ctx: EnrichmentContext) -> Any:
        assert ctx.spec.build_sbom is not None  # guaranteed by applies()
        ctx.log(f"Enriching the build's RPMs from build SBOM {ctx.spec.build_sbom}")
        # No selector: a build SBOM describes every RPM (identity is measured
        # across all binaries, not just the subject).
        return enrich_graph_with_build_sbom(
            ctx.graph, ctx.spec.build_sbom, on_progress=ctx.on_progress
        )


@dataclass(frozen=True)
class RepographStep:
    name: str = "repograph"

    def applies(self, spec: RunSpec) -> bool:
        return spec.repograph_dot_text is not None

    def run(self, ctx: EnrichmentContext) -> Any:
        assert ctx.spec.repograph_dot_text is not None  # guaranteed by applies()
        return enrich_graph_with_rpmgraph(
            ctx.graph, ctx.spec.repograph_dot_text, evidence="repograph", node_selector=ctx.selector
        )


@dataclass(frozen=True)
class DnfStep:
    name: str = "dnf"

    def applies(self, spec: RunSpec) -> bool:
        return spec.use_dnf

    def run(self, ctx: EnrichmentContext) -> Any:
        ctx.log("Resolving dependencies per package with dnf repoquery")
        return enrich_graph_with_dnf(
            ctx.graph, node_selector=ctx.selector, limit=ctx.spec.limit, on_progress=ctx.on_progress
        )


@dataclass(frozen=True)
class SbomStep:
    name: str = "sbom"

    def applies(self, spec: RunSpec) -> bool:
        return spec.sbom is not None

    def run(self, ctx: EnrichmentContext) -> Any:
        assert ctx.spec.sbom is not None  # guaranteed by applies()
        subject = ctx.subject(ctx.spec.sbom_subject)
        ctx.log(f"Attaching CycloneDX SBOM {ctx.spec.sbom} to {subject.id}")
        return attach_cyclonedx_sbom_claims(ctx.graph, subject.id, ctx.spec.sbom)


@dataclass(frozen=True)
class RequirementsStep:
    name: str = "python"

    def applies(self, spec: RunSpec) -> bool:
        return spec.requirements is not None

    def run(self, ctx: EnrichmentContext) -> Any:
        assert ctx.spec.requirements is not None  # guaranteed by applies()
        subject = ctx.subject(ctx.spec.requirements_subject)
        ctx.log(f"Attaching Python requirements {ctx.spec.requirements} to {subject.id}")
        return attach_python_requirements(ctx.graph, subject.id, ctx.spec.requirements)


@dataclass(frozen=True)
class ImportsStep:
    name: str = "python_imports"

    def applies(self, spec: RunSpec) -> bool:
        return spec.imports is not None

    def run(self, ctx: EnrichmentContext) -> Any:
        assert ctx.spec.imports is not None  # guaranteed by applies()
        subject = ctx.subject(ctx.spec.imports_subject)
        mapping = (
            json.loads(ctx.spec.module_map.read_text(encoding="utf-8"))
            if ctx.spec.module_map
            else None
        )
        ctx.log(f"Scanning Python imports in {ctx.spec.imports} for {subject.id}")
        return attach_python_imports(ctx.graph, subject.id, ctx.spec.imports, mapping=mapping)


@dataclass(frozen=True)
class ErrataStep:
    name: str = "errata"

    def applies(self, spec: RunSpec) -> bool:
        return spec.errata is not None

    def run(self, ctx: EnrichmentContext) -> Any:
        assert ctx.spec.errata is not None  # guaranteed by applies()
        subject = ctx.subject(ctx.spec.errata_subject)
        ctx.log(f"Attaching errata {ctx.spec.errata} to {subject.id}")
        return attach_errata_file(ctx.graph, subject.id, ctx.spec.errata)


@dataclass(frozen=True)
class VerifyCpeStep:
    name: str = "verify_cpe"

    def applies(self, spec: RunSpec) -> bool:
        return spec.verify_cpe is not None

    def run(self, ctx: EnrichmentContext) -> Any:
        assert ctx.spec.verify_cpe is not None  # guaranteed by applies()
        ctx.log(f"Verifying CPE candidates against {ctx.spec.verify_cpe}")
        return verify_graph_cpe(
            ctx.graph, CpeDictionary.from_file(ctx.spec.verify_cpe), node_selector=ctx.selector
        )


@dataclass(frozen=True)
class HeadersStep:
    name: str = "rpm_headers"

    def applies(self, spec: RunSpec) -> bool:
        return spec.with_rpm_headers

    def run(self, ctx: EnrichmentContext) -> Any:
        ctx.log("Range-reading RPM headers for dynamic-linkage claims")
        return enrich_graph_with_rpm_headers(
            ctx.graph,
            limit=ctx.spec.limit,
            on_progress=ctx.on_progress,
            node_selector=ctx.selector,
            http_cache=ctx.spec.http_cache,
            max_concurrency=ctx.spec.max_concurrency,
        )


@dataclass(frozen=True)
class PayloadStep:
    name: str = "rpm_payloads"

    def applies(self, spec: RunSpec) -> bool:
        return spec.with_rpm_payloads

    def run(self, ctx: EnrichmentContext) -> Any:
        ctx.log("Downloading RPM payloads and parsing ELF objects (rung 4)")
        return enrich_graph_with_rpm_payloads(
            ctx.graph,
            limit=ctx.spec.limit,
            on_progress=ctx.on_progress,
            node_selector=ctx.selector,
            cache_payloads=ctx.spec.cache_payloads,
            max_concurrency=ctx.spec.max_concurrency,
        )


@dataclass(frozen=True)
class SonameStep:
    name: str = "soname"

    def applies(self, spec: RunSpec) -> bool:
        return spec.provides_map is not None or spec.resolve_sonames

    def run(self, ctx: EnrichmentContext) -> Any:
        if ctx.spec.provides_map is not None:
            ctx.log(f"Resolving sonames from provides map {ctx.spec.provides_map}")
            index = json.loads(ctx.spec.provides_map.read_text(encoding="utf-8"))
        else:
            ctx.log("Resolving sonames to packages via dnf --whatprovides")
            index = build_soname_index(collect_soname_names(ctx.graph))
        return resolve_soname_claims(ctx.graph, index)


@dataclass(frozen=True)
class CasStep:
    name: str = "cas"

    def applies(self, spec: RunSpec) -> bool:
        return spec.use_cas

    def run(self, ctx: EnrichmentContext) -> Any:
        ctx.log("Verifying CAS attestation hashes (opt-in)")
        return verify_graph_cas(ctx.graph, use_cas=True)


@dataclass(frozen=True)
class SignatureStep:
    name: str = "signatures"

    def applies(self, spec: RunSpec) -> bool:
        return spec.verify_signatures

    def run(self, ctx: EnrichmentContext) -> Any:
        ctx.log("Verifying RPM GPG signatures (download + rpmkeys --checksig)")
        return verify_graph_signatures(ctx.graph, node_selector=ctx.selector, limit=ctx.spec.limit)


# The historical coverage order, preserved so behaviour is unchanged. build_sbom
# runs before verify_cpe (a vendor CPE must not be overwritten by a later check);
# everything else only adds claims that the final reconcile groups regardless.
DEFAULT_STEPS: tuple[EnrichmentStep, ...] = (
    BuildSbomStep(),
    RepographStep(),
    DnfStep(),
    SbomStep(),
    RequirementsStep(),
    ImportsStep(),
    ErrataStep(),
    VerifyCpeStep(),
    HeadersStep(),
    PayloadStep(),
    SonameStep(),
    CasStep(),
    SignatureStep(),
)


@dataclass(frozen=True)
class StepResult:
    name: str
    result: Any


@dataclass
class PipelineResult:
    graph: ProvenanceGraph
    reconciliation: ReconciliationReport
    steps: list[StepResult] = field(default_factory=list)
    patch: EvidencePatch | None = None

    def result(self, name: str) -> Any | None:
        """The result object a step produced, or None if it did not run."""

        for step in self.steps:
            if step.name == name:
                return step.result
        return None


class AnalysisPipeline:
    def __init__(self, steps: tuple[EnrichmentStep, ...] = DEFAULT_STEPS) -> None:
        self.steps = steps

    def run(
        self,
        spec: RunSpec,
        graph: ProvenanceGraph,
        *,
        on_progress: Progress = None,
        dry_run: bool = False,
    ) -> PipelineResult:
        """Run the applicable steps, reconcile, and return the result.

        Always records into an :class:`EvidencePatch`; with ``dry_run=True`` it
        operates on a copy, so the source graph is left untouched.
        """

        target = graph.copy() if dry_run else graph
        recorder = RecordingGraph(target)
        selector = make_binary_rpm_selector(
            package=spec.package, arch=spec.arch, all_archs=spec.all_archs
        )
        ctx = EnrichmentContext(
            graph=recorder, spec=spec, selector=selector, on_progress=on_progress
        )
        results: list[StepResult] = []
        for step in self.steps:
            if step.applies(spec):
                results.append(StepResult(step.name, step.run(ctx)))
        if on_progress:
            on_progress("Reconciling dependency claims")
        reconciliation = reconcile_dependency_claims(recorder)
        return PipelineResult(
            graph=target, reconciliation=reconciliation, steps=results, patch=recorder.patch
        )

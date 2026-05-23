# albs-provenance-explorer

`albs-provenance-explorer` is a Python PoC for provenance-aware graph exploration over AlmaLinux Build System (ALBS), RPM, SBOM and errata data.

It is a read-only intelligence layer. It does not replace ALBS, rebuild packages, or act as a generic dependency visualizer. The goal is to preserve Enterprise Linux supply-chain lineage from source package through Codenotary CAS source and artifact attestations, build tasks, RPM artifacts, signatures, repository release context, SBOMs and security advisories.

## Why Provenance Matters

A dependency graph that only says `package A requires package B` is insufficient for Enterprise Linux security maintenance.

ELS and RHEL-compatible distributions often ship backported fixes. A version string may look older than upstream while still containing a security patch. Useful dependency intelligence needs release context, errata linkage, build provenance and artifact lineage, not only package-manager relationships.

This project treats ALBS as the provenance backbone:

```text
source package
  -> git repository
  -> exact git commit
  -> Codenotary CAS source attestation
  -> ALBS build task
  -> build environment
  -> SRPM / binary RPM
  -> Codenotary CAS artifact attestation
  -> signature
  -> repository release
  -> SBOM
  -> errata / CVE
```


## Demo: nginx-core Trust Path

This demo uses public ALBS build `17812`, an AlmaLinux 9 `nginx` build, and focuses the graph down to one binary RPM artifact: `nginx-core-1.20.1-16.el9_4.1.x86_64.rpm`.

The full build graph is useful for analysis, but it is too dense for review. The focused trust graph keeps the source-to-artifact lineage and release evidence visible without rendering every package from every architecture.

```bash
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format svg -o examples/demo-nginx-core/nginx-core-x86_64-trust.svg
```

Console trust-path report from an AlmaLinux host, using a five-minute ALBS metadata cache and optional git source commit verification:

```bash
VERIFY_GIT=1 ./example--verbose.sh
```

![nginx-core trust-path console report](examples/demo-nginx-core/trust-path-console.svg)

Full text output is kept in [`examples/demo-nginx-core/trust-path-console.txt`](examples/demo-nginx-core/trust-path-console.txt).

Focused provenance graph, 13 nodes / 13 edges:

![nginx-core focused trust graph](examples/demo-nginx-core/nginx-core-x86_64-trust.svg)

<details>
<summary>Full ALBS build graph for build 17812, 289 nodes / 484 edges</summary>

![full ALBS build 17812 provenance graph](examples/demo-nginx-core/build-17812-full.svg)

</details>

## Scope

Implemented in this PoC:

- provenance graph core with canonical ALBS/RPM node and edge types
- normalized dependency fact model for ecosystem, scope, linkage, resolution state and context
- synthetic ALBS fixture ingestion for tests
- resilient build metadata adapter shape for `build.almalinux.org`
- RPM metadata inspection adapter with normalized `requires`/`provides` dependency facts
- SPDX JSON and CycloneDX JSON SBOM graph import with Package URL based ecosystem identity
- errata/CVE attachment model
- trust-path analysis for binary RPM artifacts
- JSON, DOT and SVG rendering
- CLI commands for live ALBS build fetches, RPM inspection, SBOM import, synthetic fixtures and trust-path reports

Intentionally out of scope for the first pass:

- full package-manager resolution for Pip, Poetry, Maven, Gradle, npm, Cargo or Go
- SAT/backtracking resolution and large-scale job orchestration
- write access to ALBS
- a web platform
- Kubernetes or service deployment
- replacing distro build or signing infrastructure

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

Graphviz is required for SVG rendering:

```bash
dot -V
```

## CLI

List available commands and options:

```bash
albs-graph --help
albs-graph fetch --help
albs-graph trust-path --help
```

If the console script is not installed in the active virtual environment, use the module entrypoint:

```bash
python -m albs_graph.cli.main --help
```

Fetch and parse an ALBS build page:

```bash
albs-graph fetch-build 12345 --format json
```

Show step-by-step fetch, CAS extraction and render progress on stderr:

```bash
albs-graph fetch --build-id 17812 --cache examples/live-build-17812/build-17812.albs.json --format json --verbose -o build-17812.json
albs-graph trust-path --build-id 17812 --cache examples/live-build-17812/build-17812.albs.json --rpm nginx-core --arch x86_64 --format svg --verbose -o nginx-core_x86_64-trust.svg
```

Regenerate the nginx-core demo artifacts in one verbose run. The script fetches ALBS metadata once into a local cache and reuses it for JSON, DOT and SVG renders while the cache is fresh. Cache freshness defaults to 5 minutes and can be changed with `--cache-ttl`:

```bash
./example--verbose.sh
```

On an AlmaLinux host, install `cas` if missing and verify the source and RPM artifact CAS hashes from the cached ALBS metadata:

```bash
./example--almalinux.sh
```

Inspect local RPM metadata:

```bash
albs-graph inspect-rpm ./bash.rpm --format json
```

Import an SBOM:

```bash
albs-graph import-sbom sbom.json --format dot
```

Show a focused trust graph for one RPM artifact from a live ALBS build:

```bash
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format svg -o nginx-core-x86_64-trust.svg
```

## Model

Canonical node types include:

`source_package`, `git_repository`, `git_commit`, `cas_attestation`, `build_task`, `build_environment`, `srpm`, `binary_rpm`, `signature`, `repository_release`, `errata`, `cve`, `sbom`, `external_package`, `dependency_spec`.

Canonical edge types include:

`stored_in`, `points_to`, `authenticated_by`, `built_by`, `produces`, `tested_by`, `signed_as`, `released_to`, `described_by`, `fixes`, `affected_by`, `derived_from`, `declares_dependency`, `requires_runtime`, `requires_buildtime`, `provides`.

Runtime package relationships such as `requires_runtime` exist, but they are deliberately secondary. RPM dependencies are facts inside the graph, not the graph's organizing principle.

## Dependency Intelligence Model

This PoC is not a full unified dependency resolver yet. It now establishes the data contract such a resolver would need:

- package identity: ecosystem, namespace, name, version, PURL and qualifiers
- dependency semantics: requested constraint, scope, linkage and resolution state
- context: OS, architecture, distro, language version, extras, profiles and feature flags
- evidence source: RPM metadata, SBOM component, lockfile or future package-manager adapter

That distinction matters. Pip markers, Poetry extras, Maven scopes, Gradle configurations, npm optional dependencies, Cargo features and Go module constraints do not mean the same thing. The graph stores dependency facts in a normalized shape while preserving ecosystem-specific raw metadata for auditability.

Current adapters populate this model from RPM `requires`/`provides` and SPDX/CycloneDX components. Future resolver adapters can add package-manager-specific resolution outputs without changing the ALBS provenance graph contract.

## Unified Graph Strategy

The system separates three concerns that are often conflated in dependency graph tools:

- provenance backbone: ALBS source, build, artifact, signature, release and CAS evidence
- dependency facts: normalized package identities, scopes, constraints, contexts and observed components
- resolver implementations: ecosystem-specific logic that can later mimic Pip, Poetry, Maven, Gradle, npm, Cargo or Go

The current code implements the first two layers for the Enterprise Linux/RPM case and SBOM evidence. It deliberately does not claim to solve package-manager resolution yet. That next layer would consume project manifests and lockfiles, run ecosystem-specific resolution strategies, and emit the same normalized dependency facts back into this graph.

## Trust Semantics

Trust-path reports separate source-to-artifact provenance from security context completeness:

- provenance checks cover ALBS build linkage, signature, release context and source/artifact CAS evidence
- security-context checks cover attached SBOM and errata/CVE linkage

`complete` is only true when both categories are complete. This keeps the live `nginx-core` demo honest: the ALBS provenance path is present, while SBOM and errata context remain explicit missing evidence until those inputs are attached.

## SBOM And CAS Attestation

The SBOM adapter imports SPDX JSON and CycloneDX JSON as provenance evidence using `sbom` nodes and `described_by` edges. ALBS source and RPM artifact trust evidence is modeled as `cas_attestation` nodes connected with `authenticated_by` edges, matching the Codenotary CAS/BOM shape used by AlmaLinux SBOM integration.

For live ALBS builds, the adapter preserves `alma_commit_cas_hash` on the source commit path and artifact `cas_hash` values on SRPM/RPM outputs. These fields are modeled as CAS evidence reported by ALBS. They are not marked as externally verified unless an explicit verification step records that fact.

## Layout

```text
albs_graph/
  model/        node, edge and graph core
  dependency/   normalized dependency facts, context and coverage summaries
  adapters/     ALBS, RPM, SBOM and errata ingestion
  provenance/   trust-path and lineage analysis
  render/       JSON, DOT and SVG output
  cli/          Typer CLI commands
  examples/     synthetic build metadata fixture
tests/
```

## Development

```bash
pytest
```

The tests focus on graph correctness, trust-path semantics, SBOM import and render output. The code favors explicit models and small adapters so future ingestion work can add real ALBS/SBOM sources without changing the graph contract.

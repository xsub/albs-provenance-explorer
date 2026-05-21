# albs-provenance-explorer

`albs-provenance-explorer` is a Python PoC for provenance-aware graph exploration over AlmaLinux Build System (ALBS), RPM, SBOM and errata data.

It is a read-only intelligence layer. It does not replace ALBS, rebuild packages, or act as a generic dependency visualizer. The goal is to preserve Enterprise Linux supply-chain lineage from source package through notarized refs, build tasks, RPM artifacts, signatures, repository release context, SBOMs and security advisories.

## Why Provenance Matters

A dependency graph that only says `package A requires package B` is insufficient for Enterprise Linux security maintenance.

ELS and RHEL-compatible distributions often ship backported fixes. A version string may look older than upstream while still containing a security patch. Useful dependency intelligence needs release context, errata linkage, build provenance and artifact lineage, not only package-manager relationships.

This project treats ALBS as the provenance backbone:

```text
source package
  -> git repository
  -> exact git commit
  -> immudb-notarized ref
  -> ALBS build task
  -> build environment
  -> SRPM / binary RPM
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

Console trust-path report:

![nginx-core trust-path console report](examples/demo-nginx-core/trust-path-console.png)

Focused provenance graph, 11 nodes / 11 edges:

![nginx-core focused trust graph](examples/demo-nginx-core/nginx-core-x86_64-trust.svg)

<details>
<summary>Full ALBS build graph for build 17812, 205 nodes / 388 edges</summary>

![full ALBS build 17812 provenance graph](examples/demo-nginx-core/build-17812-full.svg)

</details>

## Scope

Implemented in this PoC:

- provenance graph core with canonical ALBS/RPM node and edge types
- mock ALBS build ingestion
- resilient build metadata adapter shape for `build.almalinux.org`
- RPM metadata inspection adapter
- SPDX JSON and CycloneDX JSON SBOM graph import
- errata/CVE attachment model
- trust-path analysis for binary RPM artifacts
- JSON, DOT and SVG rendering
- CLI commands for mock graphs, build fetches, RPM inspection, SBOM import and trust-path reports

Intentionally out of scope for the first pass:

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

Build the built-in OpenSSL provenance graph:

```bash
albs-graph mock openssl
```

Export JSON:

```bash
albs-graph mock openssl --format json -o examples/openssl_graph.json
```

Export DOT:

```bash
albs-graph mock openssl --format dot -o examples/openssl_graph.dot
```

Render SVG:

```bash
albs-graph render openssl --format svg -o examples/openssl_graph.svg
```

Fetch and parse an ALBS build page:

```bash
albs-graph fetch-build 12345 --format json
```

Inspect local RPM metadata:

```bash
albs-graph inspect-rpm ./bash.rpm --format json
```

Import an SBOM:

```bash
albs-graph import-sbom sbom.json --format dot
```

Show a trust path:

```bash
albs-graph trust-path openssl-libs
```

Show a focused trust graph for one RPM artifact from a live ALBS build:

```bash
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format svg -o nginx-core-x86_64-trust.svg
```

## Model

Canonical node types include:

`source_package`, `git_repository`, `git_commit`, `notarized_ref`, `build_task`, `build_environment`, `srpm`, `binary_rpm`, `signature`, `repository_release`, `errata`, `cve`, `sbom`.

Canonical edge types include:

`stored_in`, `points_to`, `notarized_as`, `built_by`, `produces`, `tested_by`, `signed_as`, `released_to`, `described_by`, `fixes`, `affected_by`, `derived_from`.

Runtime package relationships such as `requires_runtime` exist, but they are deliberately secondary. RPM dependencies are facts inside the graph, not the graph's organizing principle.

## SBOM And Notarization

The SBOM adapter imports SPDX JSON and CycloneDX JSON as provenance evidence using `sbom` nodes and `described_by` edges. The mock ALBS graph models immudb notarization as a `notarized_ref` node between an exact git commit and the ALBS build task, making the trust chain inspectable rather than implicit.

The PoC does not perform real immudb verification yet. It preserves the graph semantics required for that verification step to be added cleanly.

## Layout

```text
albs_graph/
  model/        node, edge and graph core
  adapters/     ALBS, RPM, SBOM and errata ingestion
  provenance/   trust-path and lineage analysis
  render/       JSON, DOT and SVG output
  cli/          Typer CLI commands
  examples/     mock build metadata
tests/
```

## Development

```bash
pytest
```

The tests focus on graph correctness, trust-path semantics, SBOM import and render output. The code favors explicit models and small adapters so future ingestion work can add real ALBS/SBOM sources without changing the graph contract.

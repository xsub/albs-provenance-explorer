# albs-provenance-explorer

`albs-provenance-explorer` is a read-only Python PoC that builds a provenance-aware graph over AlmaLinux Build System (ALBS), RPM, SBOM, CAS and errata data.

It traces Enterprise Linux supply-chain lineage from source package to shipped artifact and layers a conflict-aware dependency model on top. Release context, errata linkage and build provenance sit next to the raw package relationships, so backported security fixes stay visible - a version that looks older than upstream can still carry the patch.

ALBS is the provenance backbone:

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

The same demo also exports build-level intelligence from the ALBS metadata:

- `96` RPM artifact rows across `x86_64`, `aarch64`, `ppc64le`, `s390x`, `i686` and `src` build tasks
- `18` common binary package names are shared by all binary build task platforms
- each binary build task emits `19` RPM rows: `16` arch-specific RPMs, `2` `noarch` RPMs and `1` SRPM
- processing analysis covers `173` raw artifacts total: `96` RPM artifacts and `77` build-log/config artifacts
- build timing summary: `13.6m` wall time, `37.7m` aggregate task wall time, `8.1m` critical task wall time
- signing/notarization timing summary: `4.3m` wall time, including package signing, CAS notarization, upload and web-server processing

Machine-readable exports are kept in [`examples/demo-nginx-core/build-17812-artifact-inventory.json`](examples/demo-nginx-core/build-17812-artifact-inventory.json) and [`examples/demo-nginx-core/build-17812-processing-analysis.json`](examples/demo-nginx-core/build-17812-processing-analysis.json).

```bash
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format svg -o examples/demo-nginx-core/nginx-core-x86_64-trust.svg
```

Console trust-path report from an AlmaLinux host, using a five-minute ALBS metadata cache and optional git source commit verification:

```bash
RPM_NAME=nginx-core ARCH=x86_64 OUT_DIR=examples/demo-nginx-core VERIFY_GIT=1 ./example--verbose.sh
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

Status is tracked in three honest buckets. "Couldn't resolve" is a deliverable here: the coverage report always names the unresolved residue rather than claiming 100%.

### Implemented

- provenance graph core with canonical ALBS/RPM node and edge types, plus the source-to-artifact trust path for binary RPMs
- normalized, conflict-aware dependency **claim/reconcile** model: one claim per evidence source, reconciled into a verdict without discarding the losing claims, surfaced through a five-axis coverage report (`resolution`, `linkage`, `identity`, `provenance`, `security_context`)
- live `build.almalinux.org` metadata adapter (on-disk cache + TTL), artifact inventory and processing-timeline analysis
- RPM header reads over HTTP Range (rung 3): `DT_NEEDED` sonames become dynamic-linkage claims without downloading the payload
- full payload ELF analysis (rung 4): a dependency-free ELF parser recovers `DT_NEEDED`, RPATH/RUNPATH, dynamic-vs-static, `dlopen`, toolchain, and a static Go module BOM from `.go.buildinfo`
- soname → providing-package resolution, and deep `dnf repoquery` extraction (versioned runtime deps, weak deps as optional, conflicts/obsoletes, `--whatprovides`)
- AlmaLinux-native RPM resolution (rung 5): `dnf repograph` / `rpmgraph` dot ingest emits resolved RPM dependency claims
- real native resolvers for **Go** (`go list -m all`) and **Cargo** (`cargo metadata`) behind the typed resolver contract
- Python language evidence: `requirements.txt` plus import scanning produce PyPI claims (pinned versions count toward resolution)
- dependency **universe**: repo-wide graph build, traversal (`dependents_of` / `dependencies_of` / `dependency_paths`), cross-repo merge, and focused-subgraph visualization
- low-footprint SQLite persistence: build once, query later; one-hop queries run in SQL without loading the whole graph (stdlib only, no graph DB)
- SPDX/CycloneDX SBOM import, errata/CVE attachment, CPE verification against a supplied dictionary (with the AlmaLinux distro-backport flag), GPG signature verification (`rpmkeys --checksig`), and optional CAS verification (`--use-cas`)
- consumer reports: `vuln` applicability (with `--cve-feed` rpmvercmp range matching), `license` rollup, and `slsa` in-toto / SLSA provenance export
- PURL / CPE / CAS identities kept strictly separate; JSON, DOT and SVG rendering; a CLI covering all of the above

### Partial

- Python dependencies are recorded from `requirements.txt` and import scanning, but without a real pip/uv resolver - no transitive closure or environment-marker evaluation
- CPE verification and CVE-feed matching consume **supplied** dictionary/feed files; there is no live NVD or errata fetch yet
- vault URL reconstruction is a heuristic over known AlmaLinux repo layouts, not an exhaustive mirror map
- SQLite is a deliberately lightweight persistence layer for the PoC, not the final production graph platform

### Future

- real resolvers for **pip/uv**, **Poetry**, **Maven/Gradle** and **npm** behind the existing contract
- sandboxed resolver execution; registry snapshot / cache invalidation (yanks, deletions) rather than age-based TTL
- parallel and cached header/payload/SBOM fetches; incremental re-reconciliation
- a heavier backend (Postgres recursive CTEs or a dedicated graph store) only if the SQLite store is outgrown

Permanent non-goals: implementing our own SAT/backtracking solver (we delegate to native tools), write access to ALBS, a web platform, Kubernetes or service deployment, and replacing distro build or signing infrastructure.

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
albs-graph trust-path --build-id 17812 --cache examples/live-build-17812/build-17812.albs.json --format svg --verbose -o build-17812-derived-trust.svg
```

Regenerate demo artifacts in one verbose run. The script fetches ALBS metadata once into a local cache, reports all ALBS build task platforms present in the build, prints an RPM artifact matrix, prints build/signing timing summaries, and reuses that metadata for JSON, DOT and SVG renders while the cache is fresh. Cache freshness defaults to 5 minutes and can be changed with `CACHE_TTL`:

```bash
./example--verbose.sh
```

<details>
<summary>Sample verbose run (`bash -x`) on an AlmaLinux host, host name sanitized</summary>

```text
[almalinux@host albs-provenance-explorer]$ bash -x example--verbose.sh
+ set -euo pipefail
+ BUILD_ID=17812
+ RPM_NAME=
+ ARCH=
+ OUT_DIR=examples/demo-build-17812
+ LIVE_DIR=examples/live-build-17812
+ CACHE_FILE=examples/live-build-17812/build-17812.albs.json
+ CACHE_TTL=300
+ VERIFY_GIT=0
+ python3 -m albs_graph.cli.demo_verbose --build-id 17812 --rpm '' --arch '' --out-dir examples/demo-build-17812 --live-dir examples/live-build-17812 --cache examples/live-build-17812/build-17812.albs.json --cache-ttl 300 --verify-git 0
==> ALBS graph tool: albs-graph installed; using Python orchestration for single-pass demo
==> Build: 17812
==> Focused RPM selector: <none; representative artifact selected after ALBS metadata>
==> Raw ALBS metadata cache: examples/live-build-17812/build-17812.albs.json
==> Cache TTL: 300s
==> Verify git source commit: 0
step Fetching ALBS build metadata from https://build.almalinux.org/api/v1/builds/17812/
step Writing ALBS build metadata cache to examples/live-build-17812/build-17812.albs.json
step Parsing ALBS API JSON response
step Source package: nginx (from ALBS srpm_artifact)
step Building full provenance graph from ALBS metadata
step Full graph: 289 nodes, 484 edges, 85 CAS attestations
step ALBS build task platforms: x86_64, aarch64, ppc64le, s390x, i686
step ALBS source build task: src
step Common RPM package set applies to build task platforms: x86_64, aarch64, ppc64le, s390x, i686
            Common RPM package set
┏━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  # ┃ Packages                              ┃
┡━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  1 │ nginx                                 │
│  2 │ nginx-all-modules                     │
│  3 │ nginx-core                            │
│  4 │ nginx-core-debuginfo                  │
│  5 │ nginx-debuginfo                       │
│  6 │ nginx-debugsource                     │
│  7 │ nginx-filesystem                      │
│  8 │ nginx-mod-devel                       │
│  9 │ nginx-mod-http-image-filter           │
│ 10 │ nginx-mod-http-image-filter-debuginfo │
│ 11 │ nginx-mod-http-perl                   │
│ 12 │ nginx-mod-http-perl-debuginfo         │
│ 13 │ nginx-mod-http-xslt-filter            │
│ 14 │ nginx-mod-http-xslt-filter-debuginfo  │
│ 15 │ nginx-mod-mail                        │
│ 16 │ nginx-mod-mail-debuginfo              │
│ 17 │ nginx-mod-stream                      │
│ 18 │ nginx-mod-stream-debuginfo            │
└────┴───────────────────────────────────────┘
                           ALBS RPM artifact matrix
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Build task arch ┃ Artifacts ┃ Artifact arches             ┃ Package set    ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ x86_64          │        19 │ x86_64=16, noarch=2, src=1  │ common         │
│ aarch64         │        19 │ aarch64=16, noarch=2, src=1 │ common         │
│ ppc64le         │        19 │ ppc64le=16, noarch=2, src=1 │ common         │
│ s390x           │        19 │ s390x=16, noarch=2, src=1   │ common         │
│ i686            │        19 │ i686=16, noarch=2, src=1    │ common         │
│ src             │         1 │ src=1                       │ source package │
│                 │           │                             │ nginx          │
└─────────────────┴───────────┴─────────────────────────────┴────────────────┘
step Artifact inventory rows include each ALBS task artifact, including repeated SRPM/noarch outputs per build task
step Writing artifact inventory json output to examples/demo-build-17812/build-17812-artifact-inventory.json
                                                    ALBS processing timeline
┏━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Build task arch ┃ Wall ┃ Artifacts            ┃ build_srpm ┃ build_binaries ┃ upload ┃ packages_processing ┃ logs_processing ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ x86_64          │ 6.6m │ build_log=14, rpm=19 │      33.7s │           3.3m │   1.8m │               29.0s │           14.3s │
│ aarch64         │ 8.1m │ build_log=14, rpm=19 │       1.5m │           3.8m │   1.8m │               28.1s │           13.6s │
│ ppc64le         │ 6.2m │ build_log=14, rpm=19 │       1.1m │           1.7m │   2.2m │               28.6s │           17.1s │
│ s390x           │ 5.0m │ build_log=14, rpm=19 │      46.0s │           1.2m │   1.9m │               32.0s │           15.3s │
│ i686            │ 7.1m │ build_log=14, rpm=19 │       2.5m │           1.9m │   1.8m │               29.3s │           13.8s │
│ src             │ 4.8m │ build_log=7, rpm=1   │       3.7m │              - │  28.6s │               12.3s │           12.6s │
└─────────────────┴──────┴──────────────────────┴────────────┴────────────────┴────────┴─────────────────────┴─────────────────┘
step Build timing totals: wall=13.6m, aggregate task wall=37.7m, critical task wall=8.1m
            ALBS signing/notarization timing
┏━━━━━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━━━━━━┳━━━━━━━━┳━━━━━━━┓
┃ Sign task ┃ Wall ┃  sign ┃ notarize ┃ upload ┃   web ┃
┡━━━━━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━━━━━━╇━━━━━━━━╇━━━━━━━┩
│ 11754     │ 4.3m │ 22.0s │     7.0s │   3.1m │ 29.0s │
└───────────┴──────┴───────┴──────────┴────────┴───────┘
step Writing processing analysis json output to examples/demo-build-17812/build-17812-processing-analysis.json
step Rendering full graph as JSON/DOT/SVG
step Writing full graph json output to examples/live-build-17812/build-17812.json
step Writing full graph dot output to examples/live-build-17812/build-17812.dot
step Writing full graph svg output to examples/live-build-17812/build-17812.svg
step Writing demo full graph json output to examples/demo-build-17812/build-17812-full.json
step Writing demo full graph svg output to examples/demo-build-17812/build-17812-full.svg
step No RPM selector provided; full build is multi-platform; selecting representative focused artifact for arch x86_64
step Selected RPM node: rpm:3237133:nginx-1.20.1-16.el9_4.1.x86_64.rpm
step Analyzing source-to-artifact trust path
               Trust path:
    nginx-1.20.1-16.el9_4.1.x86_64.rpm
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Check                        ┃ Result  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ has_build_task               │ ok      │
│ has_signature                │ ok      │
│ has_release                  │ ok      │
│ has_source_cas_attestation   │ ok      │
│ has_artifact_cas_attestation │ ok      │
│ has_sbom                     │ missing │
│ has_errata_link              │ missing │
└──────────────────────────────┴─────────┘
Provenance complete: True
Security context complete: False
Complete: False
Missing security context: has_sbom, has_errata_link
Path:
  src:nginx
  git:https://git.almalinux.org/rpms/nginx.git
  commit:nginx:911945c71710c83cf6f760447c32d8d6cae737dc
  cas:source:nginx:911945c71710c83cf6f760447c32d8d6cae737dc
  build:albs-task:188077
  rpm:3237133:nginx-1.20.1-16.el9_4.1.x86_64.rpm
step Building focused trust graph
step Focused graph: 13 nodes, 13 edges, 3 CAS attestations
step Rendering focused trust graph as JSON/DOT/SVG
step Writing focused graph json output to examples/demo-build-17812/nginx-x86_64-trust.json
step Writing focused graph dot output to examples/demo-build-17812/nginx-x86_64-trust.dot
step Writing focused graph svg output to examples/demo-build-17812/nginx-x86_64-trust.svg
==> Done
Metadata cache: examples/live-build-17812/build-17812.albs.json
Full graph:     examples/demo-build-17812/build-17812-full.svg
Focused graph:  examples/demo-build-17812/nginx-x86_64-trust.svg
[almalinux@host albs-provenance-explorer]$
```

</details>

The numbered `Common RPM package set` counts package names, while the per-architecture `Artifacts` column counts ALBS artifact rows. For build `17812`, each binary platform has `18` common package names but `19` RPM artifact rows because ALBS also records the repeated SRPM evidence row: `16` arch-specific RPMs, `2` `noarch` RPMs and `1` SRPM. If a future build has architecture-specific differences, the `Package set` column reports `delta` with `+package` and `-package` entries instead of `common`.

The shell wrapper is thin - it only passes parameters into `python3 -m albs_graph.cli.demo_verbose`; fetching, graph construction, inventory, timing analysis and rendering all live in Python modules.

ALBS builds usually produce many artifacts per build task architecture: binary RPMs, subpackages, modules, `debuginfo`, `debugsource`, repeated SRPM evidence, `noarch` outputs and build logs/configuration artifacts. The verbose demo writes this as `build-<id>-artifact-inventory.json` in the demo output directory.

The same raw build metadata includes task `performance_stats`, test-task performance stats and signing stats. The demo turns those fields into `build-<id>-processing-analysis.json`, including per-task step durations, aggregate build/signing totals and per-artifact processing context inherited from the ALBS task that produced each artifact.

If no focused RPM selector is provided, the full graph and artifact inventory still contain every ALBS task and artifact architecture; only the small trust-path graph chooses one representative artifact, preferring `x86_64` when available. Use `RPM_NAME` and `ARCH` to make that focus explicit:

```bash
RPM_NAME=nginx-core ARCH=x86_64 ./example--verbose.sh
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
albs-graph trust-path --build-id 17812
albs-graph trust-path --build-id 17812 --arch x86_64
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format svg -o nginx-core-x86_64-trust.svg
```

Checkout and analyze source evidence referenced by an ALBS build:

```bash
albs-graph checkout-source --build-id 17812 --dest sources/build-17812
albs-graph source-evidence sources/build-17812 --build-id 17812 --format json -o build-17812-source-evidence.json
```

`source-evidence` starts from ALBS build metadata, attaches a hashed source-file inventory, parses RPM `.spec` files for `BuildRequires`, `Requires`, `Source` and `Patch`, and records detected ecosystem manifests such as `package.json`, `Cargo.toml`, `go.mod`, `pyproject.toml`, `pom.xml` and Gradle build files. Manifest *detection* is evidence, not resolution; the separate `resolve` command runs native resolvers (Go and Cargo today) that consume those manifests and emit resolved dependency facts.

## Coverage, enrichment and analysis

The commands above build and inspect the provenance backbone; these realize the five coverage axes and the cost ladder, and project the graph for each consumer. All take either a live `--build-id` or a cached `--source` metadata JSON (shown here as `CACHE`).

Five-axis coverage, then climb the cost ladder: rung 3 reads RPM headers over HTTP Range, rung 4 downloads full payloads and parses ELF (both network):

```bash
albs-graph coverage --source examples/live-build-17812/build-17812.albs.json
albs-graph coverage --source CACHE --with-rpm-headers --arch x86_64 --limit 5
albs-graph coverage --source CACHE --with-rpm-payloads --package nginx-core --arch x86_64
```

AlmaLinux-native resolution (rung 5; needs `dnf`/`rpmgraph` on the host, otherwise a graceful no-op):

```bash
albs-graph coverage --source CACHE --use-dnf --package nginx-core --arch x86_64
albs-graph coverage --source CACHE --repograph appstream --arch x86_64
albs-graph coverage --source CACHE --repograph-dot appstream.dot
albs-graph coverage --source CACHE --resolve-sonames --arch x86_64
```

Attach evidence and run real verification (these move the `security_context` and `identity` axes):

```bash
albs-graph coverage --source CACHE --sbom sbom.json --sbom-subject nginx-core
albs-graph coverage --source CACHE --requirements requirements.txt
albs-graph coverage --source CACHE --errata errata.json --verify-cpe cpe-dict.json
albs-graph coverage --source CACHE --verify-signatures --arch x86_64
albs-graph coverage --source CACHE --use-cas
```

Trace any installed file back through its full lineage (source -> commit -> build -> RPM -> signature -> release -> deps):

```bash
albs-graph identify /usr/sbin/nginx --source CACHE
```

Build a repo-wide dependency **universe**, persist it to a low-footprint SQLite store, and traverse it (one-hop queries run in SQL without loading the whole graph):

```bash
albs-graph universe --repograph-dot appstream.dot --repograph-dot baseos.dot --save universe.db
albs-graph universe --db universe.db --dependents-of libcrypto.so.3
albs-graph universe --db universe.db --path-from nginx-core --path-to glibc --format svg -o path.svg
```

Resolve a language manifest with its native tool (Go `go list -m all`, Cargo `cargo metadata`) behind the resolver contract:

```bash
albs-graph resolve --ecosystem go --manifest ./go.mod
albs-graph resolve --ecosystem cargo --manifest ./Cargo.toml --source CACHE --subject mypkg
```

Consumer reports projected from the same graph: vulnerability applicability, license rollup, and SLSA/in-toto provenance:

```bash
albs-graph vuln --source CACHE --errata errata.json --verify-cpe cpe-dict.json --cve-feed cve-feed.json
albs-graph license --source CACHE --sbom-subject nginx-core
albs-graph slsa nginx-core --source CACHE -o nginx-core.intoto.json
```

## Model

Canonical node types include:

`source_package`, `git_repository`, `git_commit`, `cas_attestation`, `build_task`, `build_environment`, `srpm`, `binary_rpm`, `signature`, `repository_release`, `errata`, `cve`, `sbom`, `external_package`, `dependency_spec`, `source_tree`, `source_file`, `source_manifest`.

Canonical edge types include:

`stored_in`, `points_to`, `authenticated_by`, `built_by`, `produces`, `tested_by`, `signed_as`, `released_to`, `described_by`, `fixes`, `affected_by`, `derived_from`, `declares_dependency`, `requires_runtime`, `requires_buildtime`, `provides`, `contains`, `references`.

Provenance edges (`built_by`, `produces`, `signed_as`, `released_to`, `authenticated_by`, `derived_from`) are primary; runtime relationships like `requires_runtime` are facts the graph carries alongside them.

## Dependency Intelligence Model

The dependency model is a typed contract with real resolvers behind it for RPM (`dnf`/`rpmgraph`), Go and Cargo, and the same contract ready for the rest. It carries:

- package identity: ecosystem, namespace, name, version, PURL and qualifiers
- dependency semantics: requested constraint, scope, linkage and resolution state
- context: OS, architecture, distro, language version, extras, profiles and feature flags
- evidence source: RPM metadata, SBOM component, lockfile or future package-manager adapter

Pip markers, Poetry extras, Maven scopes, Gradle configurations, npm optional dependencies, Cargo features and Go module constraints carry different meanings, so the graph stores each dependency fact in a normalized shape while preserving its ecosystem-specific raw metadata for auditability.

Current adapters populate this model from RPM `requires`/`provides`, RPM header and payload ELF facts, `dnf repoquery`/`repograph`/`rpmgraph` output, native Go/Cargo resolvers, Python requirements and imports, SPDX/CycloneDX components and source `.spec` declarations. Source manifest detection records ecosystem evidence wherever a corresponding file (`package.json`, `pom.xml`, Gradle build files, and so on) exists in the source tree. Remaining resolver adapters (pip/uv, Poetry, Maven/Gradle, npm) plug into the same contract without changing the ALBS provenance graph.

## Identity Model: PURL vs CPE vs ALBS/CAS

The graph keeps package identity, security matching identity and provenance evidence separate:

- PURL identifies package coordinates for SRPM/RPM and SBOM components. Live ALBS RPM artifacts now carry `pkg:rpm/almalinux/...` Package URLs with `arch`, `distro` and available version/release qualifiers, following the [Package URL](https://github.com/package-url/purl-spec) shape (`scheme:type/namespace/name@version?qualifiers`).
- CPE is security-applicability identity. The graph stores `cpe: null` plus unverified `cpe_candidates` (derived from RPM name/version) and asserts an official [CPE](https://cpe.mitre.org/specification/) dictionary match only once `coverage --verify-cpe` confirms one against a supplied dictionary, flagging AlmaLinux backports along the way.
- ALBS/CAS identity is provenance evidence. CAS nodes preserve build and notarization attributes such as `build_id`, `source_type`, `alma_commit_sbom_hash`, `git_url`, `git_ref`, `git_commit`, `build_arch`, RPM header fields, `build_host`, `built_by` and `sbom_api_ver`, matching the [AlmaLinux SBOM/Codenotary RFE](https://github.com/AlmaLinux/build-system-rfes/blob/master/SBOM/SBOM.md) fields where ALBS exposes them.

PURL answers "which package coordinate is this?", CPE answers "which security product record might apply?", and ALBS/CAS answers "what build/source/artifact evidence produced this thing?".

## Unified Graph Strategy

The system separates three concerns that are often conflated in dependency graph tools:

- provenance backbone: ALBS source, build, artifact, signature, release and CAS evidence
- dependency facts: normalized package identities, scopes, constraints, contexts and observed components
- resolver implementations: ecosystem-specific logic behind a typed contract - implemented for RPM (`dnf`/`rpmgraph`), Go and Cargo; Pip, Poetry, Maven, Gradle and npm still to come

The current code implements the provenance layer, RPM/SBOM/header/ELF evidence, source evidence discovery, and real resolution for the Enterprise Linux (RPM) case plus Go and Cargo. The remaining resolver layer consumes the detected project manifests and lockfiles for the other ecosystems, runs their native resolution strategies behind the same contract, and emits resolved dependency facts back into this graph.

## Trust Semantics

Trust-path reports separate source-to-artifact provenance from security context completeness:

- provenance checks cover ALBS build linkage, signature, release context and source/artifact CAS evidence
- security-context checks cover attached SBOM and errata/CVE linkage

`complete` is only true when both categories are complete. This keeps the live `nginx-core` demo honest: the ALBS provenance path is present, while SBOM and errata context remain explicit missing evidence until those inputs are attached.

## SBOM And CAS Attestation

The SBOM adapter imports SPDX JSON and CycloneDX JSON as provenance evidence using `sbom` nodes and `described_by` edges. ALBS source and RPM artifact trust evidence is modeled as `cas_attestation` nodes connected with `authenticated_by` edges, matching the Codenotary CAS/BOM shape used by AlmaLinux SBOM integration.

For live ALBS builds, the adapter preserves `alma_commit_cas_hash` on the source commit path and artifact `cas_hash` values on SRPM/RPM outputs. These fields are CAS evidence as reported by ALBS; a verification step marks them externally verified when it succeeds - `coverage --use-cas` for CAS hashes, or `coverage --verify-signatures` for GPG signatures.

## Layout

```text
albs_graph/
  model/        node, edge and graph core (canonical vocabulary)
  dependency/   normalized dependency-claim model, resolver contract, native resolvers
  adapters/     ingestion: ALBS, RPM header/payload (ELF), SBOM, errata, dnf, repograph, CAS, Python
  security/     PURL/CPE identity, CPE verification, CVE-feed matching
  provenance/   reconcile, five-axis coverage, trust path, identify, universe, vuln, license, slsa
  render/       JSON, DOT and SVG output
  store.py      low-footprint SQLite persistence for the universe
  cli/          Typer CLI commands
  examples/     synthetic build metadata fixture
tests/
```

## Development

```bash
pytest
```

The tests focus on graph correctness, trust-path semantics, SBOM import and render output. The code favors explicit models and small adapters so future ingestion work can add real ALBS/SBOM sources without changing the graph contract.

# Test guide

The suite has **475 tests** across `tests/`. They are **fully offline** — no test
touches the network or a host RPM tool: network adapters are exercised through
injected fetchers / a hand-built RPM byte structure, `dnf` / `rpmkeys` through
injected runners, and the PyQt GUI headless under `QT_QPA_PLATFORM=offscreen`.

```bash
pytest                                   # whole suite
pytest tests/test_trust.py               # one file
pytest tests/test_trust.py::test_x       # one test
QT_QPA_PLATFORM=offscreen pytest         # required for the GUI tests
```

The per-file counts below are a map, not a contract; the only cross-checked
figure is the **475** total (`scripts/check-test-count.sh`).

---

## Graph model & primitives

| File | Cases | Covers |
| --- | --: | --- |
| `test_graph_model.py` | 6 | `Node`/`Edge`/`ProvenanceGraph`: typed lookups (`find_by_type`), `incoming`/`outgoing`, metadata merge, the `trust_path_report` checks + errata three-state. |
| `test_nevra.py` | 12 | `RpmNevra` parsing/formatting from NEVRA tokens and filenames (epoch/version/release/arch, `.elN`). |
| `test_selectors.py` | 4 | `make_binary_rpm_selector` package/arch scoping (default x86_64+noarch, `--arch`, `--all-archs`). |
| `test_patch.py` | 6 | Backport/patch-version reasoning used by the distro-backport caveat. |

## ALBS ingestion, source & build analysis

| File | Cases | Covers |
| --- | --: | --- |
| `test_albs_metadata.py` | 8 | Parsing `build.almalinux.org` API JSON into the provenance backbone (source pkg, git commit, CAS, tasks, artifacts). |
| `test_albs_cache.py` | 9 | The on-disk metadata cache: TTL freshness, build-id guard against cache reuse, HTML-fallback handling, and a 404 reported plainly (D111). |
| `test_build_catalog.py` | 8 | The cached build-number catalog (D120/D121/D122): parsing the ALBS builds-list endpoint into `BuildSummary` (packages from git/SRPM refs), the injected-requests fetch, the last-N paging (`fetch_recent_builds`), the per-build `fetch_build_summary` verify (+ 404), and the JSON `BuildCatalog` (upsert-by-id, record, missing/corrupt tolerance). |
| `test_artifact_inventory.py` | 4 | The per-build artifact matrix (RPMs × arch × type). |
| `test_build_analysis.py` | 2 | Per-task build/sign/processing timing derived from raw ALBS metadata (the timeline). |
| `test_multi_build.py` | 2 | The pipeline is not build-specific — works across several build ids / packages / arches. |
| `test_source_evidence.py` | 3 | Checking out the exact git commit and summarising the source tree (spec + manifests). |
| `test_source_imports.py` | 13 | Per-language import/include extraction (Python/Go/Rust/C/JS/Java/Ruby) as declared-dependency claims. |
| `test_pylang.py` | 6 | The Python `requirements.txt` parser + single-file import scanner. |

## RPM analysis (headers, payload, ELF, signatures, repograph)

| File | Cases | Covers |
| --- | --: | --- |
| `test_rpm_header.py` | 13 | Range-fetching + parsing RPM headers (no payload) into dynamic-linkage claims, via a fake range fetcher; the Summary/Description/URL tags (D140). |
| `test_package_info.py` | 4 | On-demand package info (D140): the `dnf repoquery --info` parser + the dnf-first / RPM-header-fallback `fetch_package_info` (injected runner + header), offline-degraded. |
| `test_rpm_payload.py` | 7 | Downloading + unpacking the cpio payload and ELF analysis (rung 4); `payload_contents` file lists. |
| `test_elf.py` | 5 | The ELF parser: `DT_NEEDED`/RPATH/RUNPATH/dlopen, Go `.go.buildinfo`, Rust/Go toolchain detection. |
| `test_rpmsig.py` | 6 | `rpmkeys --checksig` GPG verification via an injected runner (verified/nokey/failed/unavailable). |
| `test_rpmgraph.py` | 8 | Parsing `dnf repograph` dot output into a whole-repo dependency graph. |

## Native tooling (dnf, sonames)

| File | Cases | Covers |
| --- | --: | --- |
| `test_dnf.py` | 8 | `dnf repoquery` (requires/recommends/provides) + `--whatprovides`, via an injected runner; graceful when dnf is absent. |
| `test_soname_resolution.py` | 6 | Resolving `DT_NEEDED` sonames to providing packages. |

## Dependency model, reconciliation & resolvers

| File | Cases | Covers |
| --- | --: | --- |
| `test_dependency_model.py` | 5 | The normalized `DependencySpec` (ecosystem/scope/linkage/resolution-state) + node/edge metadata. |
| `test_reconcile.py` | 20 | Grouping claims into `DEPENDENCY_RESOLUTION` verdicts (consensus/compatible/conflict), `CORROBORATES`/`CONFLICTS_WITH` edges, version drift, cross-distro. |
| `test_reconcile_rules.py` | 10 | The `Agreement` / `ConflictKind` / `ContextIssue` rule engine in isolation. |
| `test_native_resolvers.py` | 17 | The Go/Cargo/PyPI/Maven/npm resolvers behind `resolver_for` (injected runners; UNRESOLVABLE on failure). |
| `test_resolver_contract.py` | 3 | The resolver protocol contract every resolver adapter must satisfy. |

## SBOM

| File | Cases | Covers |
| --- | --: | --- |
| `test_sbom.py` | 6 | SPDX/CycloneDX import; a build SBOM's vendor CPE attached to every matched RPM. |
| `test_sbom_claims.py` | 5 | SBOM components turned into dependency claims. |
| `test_sbom_discovery.py` | 11 | `discover_build_sbom` (D78): the `build-<id>.cyclonedx.json` file-convention fallback. |

## Security identity & live feeds (CPE / CVE / errata)

| File | Cases | Covers |
| --- | --: | --- |
| `test_security_identity.py` | 2 | The PURL ≠ CPE ≠ CAS shape: `cpe: null` + unverified `cpe_candidates`. |
| `test_cpe.py` | 6 | CPE verification against a dictionary (verified / ambiguous_vendor / candidate); distro-backport flag. |
| `test_cve_feed.py` | 3 | `CveFeed` parsing + version-range matching (vendor/product/version). |
| `test_cve_details.py` | 5 | On-demand CVE details (D134): the NVD/OSV description+CVSS parsers and the NVD-first / OSV-fallback `fetch_cve_details` via an injected fetcher (offline-degraded, canonical links appended). |
| `test_live_feeds.py` | 11 | Live CPE/CVE feed fetcher (D76): HttpCache + TTL + graceful degradation; the descriptive User-Agent (D108). |
| `test_errata.py` | 2 | File-based errata/CVE attachment. |
| `test_errata_source.py` | 24 | Live errata source + three-state status (D79): http feed / dnf updateinfo, advisory_present/confirmed_clean/not_checked, the AlmaLinux default-URL + version inference (D108), the web-vs-dnf cross-check marking agreement / single-source / corroborated-clean (D119), the advisory→CVE edge de-duplication (D126), and the AlmaLinux errata-page + upstream Red Hat (RHSA) advisory URL helpers (D139). |

## CAS attestation

| File | Cases | Covers |
| --- | --: | --- |
| `test_cas.py` | 6 | `cas authenticate` wrapping (opt-in); reported-vs-verified hash distinction. |

## Provenance analyses (trust, coverage, identify, vuln, license, slsa)

| File | Cases | Covers |
| --- | --: | --- |
| `test_trust.py` | 7 | Source-to-artifact trust paths + the focused subgraph; provenance/security-context completeness axes. |
| `test_coverage.py` | 2 | The five-axis coverage report (resolution/linkage/identity/provenance/security_context). |
| `test_identify.py` | 6 | File→owning-RPM identification from the stored payload file lists. |
| `test_vuln.py` | 4 | The vulnerability-applicability report (F1): addressed CVEs + CPE + backport + linkage; `--cve-feed` potentially-affected matching. |
| `test_license.py` | 3 | The license-compliance rollup (per-license, unlicensed bucket). |
| `test_slsa.py` | 2 | The in-toto Statement v1 + SLSA provenance v1 export. |

## Universe & SQLite store

| File | Cases | Covers |
| --- | --: | --- |
| `test_universe.py` | 7 | `build_universe` (capability nodes), dependents/dependencies, reachable, dependency paths (in-memory). |
| `test_store.py` | 16 | The SQLite store: save/load, merge, schema migrations, recursive-CTE queries (`sql_dependents`/`sql_reachable`/`sql_dependency_paths`), `sql_search`/`sql_node_labels`, analysis snapshots, and the `UniverseStore` facade. |
| `test_arch_universe.py` | 3 | `build_arch_universe` merging per-repo graphs. |
| `test_arch_builder.py` | 12 | The live arch builder (D77): enumerate repos + repograph each + merge. |

## Pipeline & services facade

| File | Cases | Covers |
| --- | --: | --- |
| `test_pipeline.py` | 5 | `AnalysisPipeline` step orchestration: guards (`applies`), order, reconcile, the errata-source default URL/all-arch step (D108). |
| `test_fixture_pipeline.py` | 3 | The pipeline end to end on the synthetic fixture. |
| `test_services.py` | 28 | The `services/` facade shared by CLI + GUI: coverage/evidence/security/dependency rows, slices, findings (aggregation + drilldown), graph queries, timeline (tree + Gantt), compare, sessions, evidence bundle + HTML/Markdown report + reproducibility. |

## Rendering & CLI

| File | Cases | Covers |
| --- | --: | --- |
| `test_render.py` | 2 | The JSON/DOT/SVG export formats. |
| `test_cli_help.py` | 6 | The Typer CLI surface (every command is registered + has help). |
| `test_demo_wrapper.py` | 1 | The `example--full.sh` demo wrapper is gated and skips gracefully. |
| `test_http_cache.py` | 8 | The content-addressed `HttpCache`: atomic writes, 4xx/5xx propagation, cache-key sharing. |

## PyQt investigation workbench (GUI)

| File | Cases | Covers |
| --- | --: | --- |
| `test_gui_ansi.py` | 6 | The ANSI→HTML console renderer (D128): basic colours → spans, reset + bold/italic/underline, HTML-escaping, stripping cursor/clear/CR/OSC, 256/truecolour, plain passthrough. |
| `test_gui_qt_app.py` | 61 | Headless main-window smoke + interaction: construction, result-handling, slice render, inspector, the errata/CVE/CPE run-spec toggles, the Security/Dependency/Universe panels, Markdown/PNG export + session capture/restore, the two-toolbar layout, a real build loading into artifacts, the interactive cache-aware source badges (state probe + click-to-fetch), the build-id fetch-all host enrichments, the context-sensitive Analyze action, the host-aware errata default (dnf/http), the errata "both (cross-check)" option, the build-catalog refresh/browse + the filterable picker dialog (D120/D121), the start launcher + verified-build-id entry + identifier badges (D122), the missing-build "not found" routing (informational, not a failure), the un-clipped Timeline view switch + non-overlapping columns + reveal-node-on-click that scrolls the Gantt (D124/D127), the build-list fetch progress counter (D123), the Inspect-Build-Id menu action, the Inspect-Binary host-RPM gating, the Gantt scaled-to-the-short-majority duration bars + clip flag + elided columns (D130), the Gantt-as-default sub-view + the clip note clear of the axis labels + the status-bar analysis step counter (D131), the window geometry saved on close + restored by the next instance via QSettings (D132), the timeline search/filter that keeps only matching rows in both the Gantt and the Tree (D133), the inspector CVE tab (Show CVE details button enables/requests/renders + the window wiring, D134), the graph frame painted the graph background, the macOS accessibility-noise filter (D135), the always-present CAS badge (greyed without the tool) + the "AlmaLinux OS" / "Non-AlmaLinux OS" host badge (D136), and the view-only toolbar (build-id/source/SBOM as backing fields) + one-line status-bar coverage + content-fitted artifact list (D137), and the filterable bottom row tables (FilteredTable wrappers + Security/Dependency panel filters, D138), an errata (ALSA) node rendering its AlmaLinux + upstream Red Hat (RHSA) + CVE links in the CVE tab (D139), the Package tab (render + the CVE/Package auto-fetch checkbox, D140), and the About dialog (artwork + repo link + Help menu, D141). |
| `test_gui_render.py` | 6 | `workbench_graph_to_dot` theming/label wrapping/clickable URLs + the cmapx-vs-SVG coordinate alignment (D112); `graph_background` matches the theme (D135). |
| `test_gui_hitmap.py` | 4 | Parsing the Graphviz image map (cmapx) into node/edge hit regions + point-in-region testing, and the region centre used to scroll the graph to a node (D129). |
| `test_gui_inspect.py` | 3 | The node/edge inspector view models. |
| `test_gui_entry.py` | 2 | The `albs-graph-workbench` entry point argument handling. |

# PyQt5 Investigation Workbench App Plan

The current project is already close to being a backend for a graphical
investigation tool. The value of a PyQt5 frontend is not "CLI with buttons"; it
is a read-only workbench for traversing provenance, dependency, identity, and
security evidence without losing the exact graph semantics that make the CLI
trustworthy.

The app should be an evidence microscope: it helps answer why a node exists,
what evidence supports it, what is missing, and which paths make an artifact
trustworthy.

---

## 1. Product Thesis

A frontend is worth building if it is task-oriented around investigation:

- Follow a source-to-artifact trust path.
- Inspect why an RPM, SBOM component, CAS attestation, errata, CVE, or
  dependency claim is present.
- Compare evidence sources that agree or conflict.
- See completeness gaps without reading raw JSON.
- Traverse graph slices rather than the entire graph at once.
- Produce demoable, repeatable explanations for ALBS builds.

The CLI remains the stable automation and test surface. The PyQt app becomes a
human-facing explorer over the same backend contracts.

---

## 2. Non-goals

The workbench should not become:

- A package-manager resolver.
- A replacement for the CLI.
- A write path back into ALBS.
- A graph database project before the existing SQLite store is exhausted.
- A generic graph viewer that dumps every node into one unreadable canvas.
- A second implementation of provenance, reconciliation, vulnerability, or
  rendering logic.

The UI should consume typed backend services. It should not embed resolver
semantics or duplicate analysis rules.

---

## 3. Core User Workflows

### Build Investigation

1. Enter an ALBS build id, select cached metadata, or open a fixture.
2. Run the existing analysis pipeline with selected options.
3. Pick a binary RPM.
4. View its trust path: source package, git commit, build task, SRPM, binary
   RPM, signature, repository release, CAS/SBOM/errata context.
5. Click any node to inspect metadata, provenance evidence, raw fields, and
   missing checks.

### Dependency Evidence Review

1. Select an artifact or source tree.
2. Open the dependency evidence mode.
3. Group claims by package identity and context.
4. Inspect manifest, source-import, SBOM, DNF, repograph, header, and payload
   evidence separately.
5. Highlight agreement, drift, identity mismatch, unresolved claims, and
   context issues such as cross-distro resolution.

### Security Context Review

1. Select a package or CVE.
2. View attached errata, CVE relationships, CPE candidates, verified CPEs,
   vendor-asserted CPEs, and distro-backport flags.
3. Distinguish addressed CVEs from potentially affected CVEs from feed
   matching.
4. Show whether the security context is complete independently from provenance
   completeness.

### Universe Traversal

1. Open a saved SQLite universe or imported repograph.
2. Search for a package.
3. Traverse dependents, dependencies, or dependency paths.
4. Render only the relevant neighborhood or path.

---

## 4. Main Window Shape

The first usable screen should be the workbench, not a landing page.

Recommended layout:

- **Top command bar:** build id / graph file / SQLite store selector, run
  options, refresh/cache controls, current mode, progress state.
- **Left sidebar:** artifact tree, node-type filters, saved fixtures, search,
  recent selections.
- **Central graph canvas:** focused graph slice for the current mode.
- **Right inspector:** selected node or edge details, metadata, raw evidence,
  incoming/outgoing edges, completeness flags.
- **Bottom findings panel:** warnings, missing evidence, reconciliation
  conflicts, vulnerability findings, failed optional integrations, and export
  messages.

The central canvas should never default to the full graph if a focused slice is
available. The default should be the most useful investigative view for the
selected artifact.

---

## 5. Modes

| Mode | Purpose | Primary slice |
|------|---------|---------------|
| Trust Path | Explain source-to-artifact provenance | Source -> build -> RPM -> signature/release/CAS/SBOM |
| Dependency Evidence | Review declared/resolved/runtime/static claims | Artifact/source -> claim groups -> resolution verdicts |
| Security Context | Review CPE, errata, CVE, SBOM state | Package -> CPE/SBOM/errata/CVE |
| Build Timeline | Understand tasks, timing, and artifacts | Build -> tasks -> artifacts |
| Universe | Traverse repo-wide dependency graph | Package neighborhoods and dependency paths |
| Raw Graph | Debug exact nodes/edges | Filtered full graph, opt-in |

Mode changes should preserve the current selected artifact when possible.

---

## 6. Backend Service Layer

The app should not call random CLI commands internally. It should use an
app-facing service layer that also benefits the CLI over time.

Proposed package:

```text
albs_graph/services/
  analysis.py       # run pipeline from build/file/options
  queries.py        # graph search, node/edge lookup, typed summaries
  slices.py         # focused graph projections for UI modes
  findings.py       # warnings/completeness/conflicts as UI-friendly records
  sessions.py       # optional saved workbench sessions
```

Example service shape:

```python
result = AnalysisService().analyze_build(build_id, options)

graph = result.graph
coverage = result.coverage
findings = result.findings
artifacts = result.artifacts
```

The CLI can keep its current commands, but new orchestration should gradually
move into services so both CLI and GUI consume the same tested behavior.

---

## 7. PyQt5 Architecture

The UI should be thin and reactive:

- `MainWindow`: layout, menu actions, top command bar.
- `ProjectState`: current graph, selected node, selected mode, filters,
  active findings.
- `AnalysisWorker`: runs ingestion/pipeline work off the UI thread.
- `GraphCanvas`: renders the current graph slice.
- `NodeInspector`: renders selected node/edge details.
- `ArtifactTreeModel`: `QAbstractItemModel` over builds, tasks, packages,
  source evidence, and security context.
- `FindingsModel`: `QAbstractTableModel` over missing evidence, conflicts, and
  verification failures.
- `SearchModel`: indexed search over node ids, names, PURLs, CPEs, CVEs, files,
  and package coordinates.

Long-running operations must use `QThread`, `QThreadPool`, or a small worker
abstraction with Qt signals. ALBS fetches, RPM header/payload reads, resolver
calls, Graphviz rendering, and SQLite universe loads must not block the UI
thread.

---

## 8. Rendering Strategy

Start with existing Graphviz/DOT/SVG renderers and display SVG in Qt:

- `QWebEngineView` if available.
- `QSvgWidget` / `QGraphicsSvgItem` as a fallback.

The SVG-first route reuses existing rendering code and keeps visual output
consistent with CLI demos. A richer HTML/JS graph view or Qt graphics scene can
come later if SVG interaction becomes too limiting.

The current SVG path also emits Graphviz image-map coordinates for every node,
so the Qt widget can hit-test clicks without embedding browser technology. This
keeps the first implementation lightweight while still allowing graph-driven
selection in the inspector and node table.

---

## 9. MVP Scope

The first milestone should be deliberately small:

1. Open a fixture, graph JSON export, or cached ALBS build.
2. Run the existing pipeline through a service wrapper.
3. Select one binary RPM.
4. Show the trust-path graph slice.
5. Click nodes and edges to inspect metadata.
6. Show provenance/security completeness flags.
7. Show findings: missing SBOM, missing errata, missing CPE verification,
   unverified CAS/signature, dependency conflicts.
8. Export the current slice as SVG/JSON.

This MVP proves the backend/frontend boundary, node selection, focused graph
rendering, and the investigation workflow.

Current branch status: the first runnable shell exists as
`albs-graph-workbench` / `python -m albs_graph.gui`. It opens ALBS metadata JSON
or a live build id, runs `AnalysisService` in a background Qt worker, lists RPM
artifacts, renders Trust Path / Dependency Evidence / Security Context slices as
SVG, and shows node metadata plus findings. The inspector is split into Summary
/ Metadata / Edges / Raw tabs, the graph canvas shows the selected artifact and
slice size, graph nodes are clickable, findings and inspector edges can drive
navigation, and the artifact list can be filtered. The workbench has its own
light/dark-aware SVG renderer with wrapped graph labels; PyQt5 is installed via
the optional `gui` extra. It also now has a one-hop Node Neighborhood mode,
coverage and timeline tabs, recipe shortcuts, JSON evidence-bundle export, and
save/load support for lightweight workbench sessions.

The next layer makes the graph itself more workbench-like: edges are clickable
and inspectable as first-class objects, the canvas has zoom / fit / reset and
search controls, the compare tab can diff the current build against another
ALBS metadata JSON via `compare_artifacts`, and HTML report export produces a
human-readable investigation artifact from the same evidence bundle.

Timeline is now driven by `BuildAnalysis` when the workbench opens raw ALBS
metadata. Instead of a flat node list, the Timeline tab is a tree:
build/sign task rows carry status, start, finish and wall time, and build tasks
expand into performance steps, aggregate test steps and artifact groups. Graph
node ids remain attached to rows where a timeline event can navigate back into
the provenance graph.

The next investigation layer is now present in the branch. Timeline can be
viewed either as the expandable task tree or as a Gantt-style cascade derived
from the same `BuildAnalysis` rows. The bottom pane also has an Evidence matrix
that shows per-binary build, source CAS, artifact CAS, signature, release, SBOM,
errata and test coverage. Build comparison now combines artifact deltas with
evidence-status changes and build-task timing changes. The graph toolbar has
toggleable layers for Build, CAS, Sign/Release, Tests, Security and
Dependencies, and the inspector summary includes relation counts plus semantic
completeness context for binary RPMs, build tasks and CAS attestations.

Source and repeated investigation questions are now also first-class workbench
views. The Source tab summarizes the source package, git repository, git commit,
source CAS, optional source-tree scan, spec files, manifests, declared
dependencies and source/patch references. The Queries tab provides reusable
path/finding helpers such as source-to-artifact path, missing SBOM, missing
errata, missing CAS/signature evidence, coverage gaps, all CAS attestations and
dependency conflicts. Activating a finding now also fills a Finding Detail tab
with the failed trust checks and related source evidence for the selected
subject.

The workbench also carries the CLI's build-SBOM enrichment path. A toolbar field
and `--build-sbom` startup flag feed `RunSpec(build_sbom=...)`, so the Evidence
matrix can show the same per-RPM `SBOM ok` status as `coverage` / `trust-path`
when the real AlmaLinux build CycloneDX file is present. For common demo/cache
names it can suggest `build-<id>.cyclonedx.json`, while rejecting obvious source
vs. SBOM build-id mismatches.

The top-level shell now keeps commands in a menu bar instead of crowding the
toolbar. The toolbar is reserved for the active run context and investigation
switches; full source/SBOM paths move to tooltips plus the selectable status-bar
summary. Reload Program, Exit, window-close cleanup and terminal Ctrl+C handling
are part of the application lifecycle rather than ad hoc toolbar buttons.

---

## 10. Recommended First Implementation Path

1. Add `albs_graph/services` with a small `AnalysisService` facade over the
   existing pipeline.
2. Add graph query helpers for node search, node summaries, edge summaries, and
   artifact selection.
3. Add graph slice helpers for trust path and dependency evidence.
4. Build a PyQt5 prototype that opens a fixture and displays a trust-path SVG.
5. Add node-click inspection.
6. Add findings panel.
7. Add ALBS build-id execution once the local fixture flow is stable.

The branch should first make the current implementation cleanly callable by both
CLI and UI. The window comes after the shared backend is real.

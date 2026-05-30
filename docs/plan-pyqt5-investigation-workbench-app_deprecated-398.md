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
- Traverse graph slices rather than the entire graph hairball.
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

The UI should expose analysis as explicit modes, each backed by a focused graph
projection.

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

## 6. Graph Interaction Model

Useful graph UI depends more on navigation than on drawing.

Required interactions:

- Click node: show metadata, labels, evidence source, completeness flags.
- Click edge: show relation type, source evidence, and raw metadata.
- Double-click node: recenter around that node in the current mode.
- Breadcrumbs: maintain a history of selected nodes and graph slices.
- Search: by NEVRA, PURL, CPE, CVE id, filename, package name, build task id,
  git commit, node id.
- Filters: node type, relation type, evidence source, architecture, package,
  agreement state, verification state.
- Diff/highlight: show missing evidence and conflicting claims without removing
  the rest of the graph.

The app should prefer graph slices:

- Trust-path subgraph.
- Dependency-claim group.
- CVE applicability context.
- Build-task neighborhood.
- Universe neighborhood.
- Path between two selected packages.

The full graph view should be a debug mode.

---

## 7. Backend Service Layer

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

Graph-query APIs should expose typed methods instead of forcing the UI to scan
raw dictionaries:

```python
queries.find_nodes(text)
queries.node_summary(node_id)
queries.edge_summary(edge_id)
queries.artifacts_for_build(build_id)
queries.dependency_groups(subject_id)
queries.security_context(subject_id)
```

Graph-slice APIs should return ordinary `ProvenanceGraph` objects or a thin
view model containing nodes, edges, layout hints, and findings:

```python
slices.trust_path(binary_rpm_id)
slices.dependency_evidence(subject_id)
slices.security_context(subject_id)
slices.build_timeline(build_id)
slices.universe_neighborhood(package_id, depth=1)
slices.path_between(source_id, target_id)
```

The CLI can keep its current commands, but new orchestration should gradually
move into services so both CLI and GUI consume the same tested behavior.

---

## 8. PyQt5 Architecture

The UI should be thin and reactive.

Recommended components:

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

## 9. Rendering Strategy

Start simple and robust.

### MVP Renderer

Use existing Graphviz/DOT/SVG renderers and display the SVG in Qt:

- `QWebEngineView` if available.
- `QSvgWidget` / `QGraphicsSvgItem` as a fallback.

The SVG-first route reuses the existing rendering code and keeps visual output
consistent with CLI demos.

### Later Renderer

If interaction needs exceed SVG click handling, embed a local HTML graph view in
`QWebEngineView` using a dedicated JS graph library, or build a Qt graphics
scene from backend-provided layout coordinates.

Do not start with a custom graph-layout engine. Layout is not the core product;
investigative traversal is.

---

## 10. MVP Scope

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

---

## 11. Follow-up Milestones

### Milestone 2 - Dependency Workbench

- Group dependency claims by subject, identity, context, and evidence source.
- Show reconciliation verdicts and conflict kinds.
- Add filters for runtime/build/static/optional/test scopes.
- Add "show only conflicts" and "show only unresolved" toggles.

### Milestone 3 - Security Workbench

- CPE candidate browser.
- Verified vs vendor-asserted vs unverified identity display.
- Errata/CVE attachment view.
- CVE feed match view with version-range explanation.
- Distro-backport caveat display.

### Milestone 4 - Universe Workbench

- Open SQLite universe store.
- Search packages.
- Traverse dependencies/dependents.
- Render dependency paths.
- Save favorite graph slices.

### Milestone 5 - Session and Report Export

- Save a local investigation session.
- Export current findings as Markdown/HTML.
- Export selected graph slices.
- Generate a small reproducibility/security appendix for a build.

---

## 12. Data and State Boundaries

The app should keep these boundaries explicit:

- Backend graph data is immutable unless a pipeline step intentionally enriches
  it.
- UI filters should not delete graph facts; they only change visibility.
- Derived findings should be recomputable from the graph.
- Raw evidence should remain inspectable beside normalized facts.
- Cache behavior belongs to backend options, not hidden UI magic.
- Optional host tools must degrade gracefully, exactly as CLI integrations do.

This preserves the project's current read-only, evidence-first character.

---

## 13. Why PyQt5 Specifically

PyQt5 is a reasonable fit because the app is closer to an investigator's desktop
tool than a public web service:

- Native desktop file picking for fixtures, JSON exports, SQLite stores, and
  local RPMs.
- Long-running background jobs with progress signals.
- Rich split-pane UI for graph, tree, inspector, and findings.
- Works well for an internal/demo/prototype workbench.
- Keeps deployment local and read-only.

A web frontend may still make sense later if the goal becomes multi-user
sharing, hosted analysis, or remote graph stores. That should be a later
decision, not a prerequisite for proving the workbench.

---

## 14. Risks

| Risk | Mitigation |
|------|------------|
| Graph hairball UX | Default to focused slices and mode-specific projections. |
| Duplicated business logic | Put orchestration in `albs_graph/services`, not widgets. |
| UI freezes | Run pipeline, fetches, stores, and rendering in worker threads. |
| Misleading dependency display | Label evidence sources clearly; separate claims from resolved facts. |
| CPE/PURL/CAS confusion | Use explicit identity panels and status labels. |
| Scope creep | MVP starts with fixture/build load, trust path, inspector, findings, export. |
| Renderer complexity | Start with existing DOT/SVG renderer; only replace if interaction demands it. |

---

## 15. Architectural Payoff

Building the app forces useful backend cleanup:

- A stable service API over the current CLI orchestration.
- Reusable graph-query and graph-slice primitives.
- Better typed summaries for nodes, edges, claims, and findings.
- More testable separation between ingestion, analysis, and presentation.
- Clearer UX pressure around correctness issues such as idempotent
  reconciliation, CPE mutation semantics, and raw-vs-normalized identity.

The best outcome is not only a GUI. It is a cleaner core that can serve CLI,
desktop UI, reports, and future automation from the same evidence model.

---

## 16. Recommended First Implementation Path

1. Add `albs_graph/services` with a small `AnalysisService` facade over the
   existing pipeline.
2. Add graph query helpers for node search, node summaries, edge summaries, and
   artifact selection.
3. Add graph slice helpers for trust path and dependency evidence.
4. Build a PyQt5 prototype that opens a fixture and displays a trust-path SVG.
5. Add node-click inspection.
6. Add findings panel.
7. Add ALBS build-id execution once the local fixture flow is stable.

This keeps the first version honest: it demonstrates real value while staying
close to the implementation that already works.

# Next-goal options

Candidate next directions, not commitments. Each item notes what it buys (which
coverage axis it moves, which `limitations.md` gap it closes, or which consumer
it serves), a rough effort, and dependencies. The most honest place to aim is
the coverage report itself: two axes (`identity`, `security_context`) currently
sit at a flat **0.00**.

(The **live arch builder** is now implemented as `arch-universe`; this file
tracks the remaining alternatives and deferred extensions.)

---

## A. Move the flat-zero coverage axes (highest signal)

- **A1 - CPE verification → `identity` axis.** ✅ Done -
  `coverage --verify-cpe FILE` matches `cpe_candidates` against a CPE dictionary,
  flips `verified` / sets `cpe` (single-vendor match), records `ambiguous_vendor`
  without asserting, and flags `distro_backport` on `.elN` releases for the vuln
  report. *(decisions.md D23)*
- **A2 - Errata/CVE ingest → `security_context` axis.** ✅ Done -
  `coverage --errata FILE [--errata-subject RPM]` attaches an errata + its CVEs,
  so SBOM + errata together reach `security_context_complete` (axis moves off
  0.00). File-based ingest; live errata.almalinux.org fetch is future.
  *(decisions.md D22)*

## B. Finish half-done things (cheap, high utility)

- **B1 - Store full cpio file lists during rung 4.** ✅ Done - `payload_contents`
  records every path; `identify` resolves ownership from the stored list first,
  so any file (configs, docs) is traceable offline. *(decisions.md D21)*
- **B2 - Real version comparison in the reconciler.** ✅ Done - `version_compare`
  moved to `albs_graph/vercmp.py` and wired into the reconciler: `VERSION_DRIFT`
  is now rpmvercmp-semantic and `RANGE_VIOLATION` fires on declared relational
  constraints (the backport case is detected in the graph). *(decisions.md D26)*
- **B3 - Python module → package mapping** ✅ Done - `module_to_package`
  (built-in map + `--module-map` override); `coverage --imports FILE` scans a
  source file's imports and attaches mapped PyPI claims. *(decisions.md D28)*

## C. Complete rung 4 (static linkage is invisible today)

- **C1 - Go `.go.buildinfo` module extraction.** ✅ Done - the ELF parser reads
  `.go.buildinfo` (inline format) and `go_static_claims` emits Go STATIC RESOLVED
  dependency claims, so a static Go binary contributes a real module BOM.
  *(decisions.md D29)* Rust has no comparable embedded BOM; it stays
  toolchain-detected.

## D. Real verification (CAS is gone; this is the verification story now)

- **D1 - GPG signature verification of RPMs.** ✅ Done -
  `coverage --verify-signatures` downloads RPMs and runs `rpmkeys --checksig`
  against the host keyring, flipping `signature_verified` / `externally_verified`
  on success. Opt-in, crash-proof (degrades to `unavailable`). *(decisions.md D27)*

## E. Real resolvers behind the existing contract (rung 5, non-RPM)

- **E1 - Native language resolvers.** ✅ Done for **Go** (`go list -m all`),
  **Cargo** (`cargo metadata`), **PyPI** (`pip install --dry-run --report`),
  **Maven** (`mvn dependency:list`) and **npm** (`npm ls --json --all`) via
  `resolver_for` + the `resolve` command; injectable runner, UNRESOLVABLE on
  failure. *(decisions.md D32, D92)* Gradle remains `NullResolver` until its
  larger tooling surface is handled.

## F. The "why does this exist" payoff - a consumer report

- **F1 - Vulnerability-applicability report.** ✅ Done - the `vuln` command
  combines addressed CVEs (errata) + verified CPE + distro-backport caveat +
  linkage (`dlopen` / static) per package *(decisions.md D24)*, and
  `--cve-feed` matches verified CPE + version (rpmvercmp ranges) to report
  **potentially-affected** CVEs beyond those an errata addresses *(D25)*.
- **F2 - License-compliance rollup** ✅ Done - the SBOM ingest captures component
  licenses and the `license` command rolls them up per-license with an
  unlicensed bucket. *(decisions.md D31)*
- **F3 - SLSA / in-toto provenance export** ✅ Done - `slsa` command renders the
  backbone as an in-toto Statement v1 + SLSA provenance v1 predicate (subject
  sha256, git resolvedDependencies, signature status). *(decisions.md D30)*

## G. Scale / performance (without the live builder)

- **G1 - Parallelize + cache header/payload fetches.** ✅ Done -
  `_http_cache.HttpCache` (content-addressed disk cache, atomic writes,
  4xx/5xx propagate so the mirror cascade still self-heals) wraps both
  `rpm_remote` (default-on header cache) and `rpm_payload` / `rpmsig`
  (opt-in `--cache-payloads`, shared cache key by URL so a single download
  serves both ELF analysis and `rpmkeys --checksig`). Bounded concurrency
  via `ThreadPoolExecutor(max_workers=spec.max_concurrency)` (default 4)
  on all three; workers compute pure results, the main thread merges into
  the graph. CLI: `--max-concurrency`, `--http-cache/--no-http-cache`,
  `--cache-payloads`. VPS-verified: cold 1230 ms vs warm 740 ms on a single
  RPM; output byte-identical. *(decisions.md D63, D64)*
- **G2 - Incremental store updates.** ✅ Done -- `save_graph(.., mode="merge")`
  upserts and deep-merges node + edge metadata; multi-build / multi-arch
  accumulation no longer wipes prior claims. Versioned schema + in-place
  migrations land alongside; multi-hop SQL queries (recursive CTE) come for
  free (`sql_reachable_dependencies`, `sql_dependency_paths`). Plus
  materialized analysis snapshots (`save_analysis_snapshot` /
  `load_analysis_snapshot`) so a coverage / vuln / license run can be cached
  per `(kind, subject_id)`. *(decisions.md D92)*
- **G3 - `sqlite-vec` similarity overlay** ("find packages like this") - optional,
  adds a loadable-extension dependency, so deliberately deferred.

---

## Recommendation

**A (both)** is the strongest: it turns the two embarrassing zeros into real
numbers and unlocks **F1** (the consumer payoff). Fold in **B1** as a cheap,
low-risk quick win that immediately improves `identify`.

Suggested sequence:

```
B1 (full file lists)  ->  A2 (errata)  ->  A1 (CPE + backport)  ->  F1 (vuln report)
```

✅ **Done** - the full sequence (decisions.md D21-D24) plus CVE-feed matching
(D25), semantic version comparison (B2/D26), and GPG signature verification
(D1/D27). The flat-zero axes move (`identity`, `security_context`), any file is
identifiable, drift/range conflicts are version-semantic, RPM signatures are
verifiable, and the `vuln` command (with `--cve-feed`) is the consumer
deliverable. Subsequent waves landed everything else flagged here: **B3** (py
module→package, D28), **C1** (Go static BOM via `.go.buildinfo`, D29), **F2**
(license rollup, D31), **F3** (SLSA / in-toto export, D30), **E1** for **Go**,
**Cargo**, **PyPI**, **Maven** and **npm** (D32, D92), **G1**
(content-addressed HTTP cache + bounded concurrency on
`rpm_remote`/`rpm_payload`/`rpmsig`, D63 + D64; VPS-verified), **G2** store
merge/recursive queries/snapshots, live CPE/CVE feed fetch, and the live
`arch-universe` builder.

Remaining genuinely open: **E1** for **Gradle** only (bigger tooling surface)
and **G3** (`sqlite-vec` similarity overlay, optional). The remaining items are
host-/tool-heavy or infra-heavy, so they need recorded fixtures or an AlmaLinux
host to exercise.

---

## Desktop workbench roadmap (this branch)

The PyQt5 investigation workbench (`albs_graph/services` facade + `albs_graph/gui`)
has its full design and milestone plan in
`docs/plan-pyqt5-investigation-workbench-app.md`. Status against those
milestones:

- **MVP + M1** (load build, artifacts, focused slices, inspector, findings,
  timeline tree + Gantt, evidence matrix, graph queries, finding drill-down,
  classic-CLI runner) -- **done** (decisions.md D80-D90).
- **M2 Dependency workbench** -- **done** (D98): the "Dependencies" tab turns
  each reconciled `DEPENDENCY_RESOLUTION` group into one row -- subject +
  coordinate, the verdict (consensus / compatible / conflict /
  insufficient_evidence), conflict kinds, cross-distro context, and the
  scope / linkage / resolution-state facets aggregated from the member claims --
  with filters for runtime/build/static/test scope and "only conflicts / only
  unresolved".
- **M3 Security workbench** -- mostly **done**: the **errata three-state**
  (advisory_present / confirmed_clean / not_checked, D79) in the evidence matrix
  (b703443), a workbench errata-source toggle so `clean` is reachable live
  (D96), and a dedicated **Security panel** -- CPE candidate browser (verified
  vs vendor-asserted vs unverified guess), errata posture, addressed/potential
  CVEs, distro-backport + reachability caveats (D97), and a CVE-feed + CPE-verify
  toggle pair (D101) so the **Potential CVEs** column populates with
  version-range matches (CPE verify resolves an official CPE the feed can match).
- **M4 Universe workbench** -- **done** (D99): the "Universe" tab opens a SQLite
  universe store (D74), searches packages/capabilities (`sql_search`), walks
  Dependencies / Dependents / Reachable, finds label-resolved dependency paths
  (the recursive-CTE queries), and saves favourite (store, search, focus,
  target) explorations to re-run. Backed by the read-only
  `services.universe.UniverseStore` facade so the CTEs stay in SQLite.
- **M5 Session + report export** -- **done** (D100): richer session save/load
  (now persists the dependency filters + the universe store/favourites),
  Markdown **and** HTML report export (`evidence_report_markdown`), slice export
  as SVG **and** PNG (`QtSvg.QSvgRenderer`), and a reproducibility appendix
  (inputs + graph size + tool/python/timestamp) carried in the JSON bundle and
  both reports.

The PyQt workbench roadmap (M2-M5) is complete, and the M3 CVE-feed toggle
(D101) is done. Remaining genuinely open:

- **quality follow-ups** (orthogonal to features): headless + interaction tests
  now bring `gui/qt_app.py` to ~73%, and the god-object split is underway -- the
  M4 Universe panel (D102), the M3 Security panel (D103) and the M2 Dependency
  panel (D104) are extracted into `gui/universe_panel.py` /
  `gui/security_panel.py` / `gui/dependency_panel.py`, each type-checking under
  mypy strict with no ignore (3/4 panels done), the template for retiring the
  blanket ignore panel-by-panel. Remaining: extract the timeline / inspector
  cluster the same way, then drop the blanket ignore from the slimmed
  `qt_app.py`; deeper interaction coverage continues.

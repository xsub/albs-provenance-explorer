# Limitations

An honest register of what the system does **not** do today, why, and what would
lift each limit. Stating the residue explicitly is part of the design goal - a
tool that hides its gaps is worse than one that names them.

Coverage axes referenced below are defined in `plan.md`.

---

## Coverage axes that are intentionally low

These are not bugs; they are unfed axes. The code refuses to fabricate the
evidence that would raise them.

### `security_context` axis = 0.00 even with an SBOM attached
Two distinct facts here:

- **SBOMs carry provenance, not licenses.** AlmaLinux's own
  [`alma-sbom`](https://github.com/AlmaLinux/alma-sbom) *does* generate a real
  CycloneDX build SBOM **anonymously** (immudb_wrapper's default read
  credentials; verified on an el10 host -- `alma-sbom --file-format
  cyclonedx-json build --build-id 57810` produced a 457-component SBOM with real
  PURLs, CPEs, SHA-256 hashes and ALBS build properties). But those components
  carry **no per-component license field**, so an SBOM license rollup is empty.
  The real license therefore comes from the RPM `License:` header tag (rung 3,
  already range-read) and `dnf repoquery %{license}`: `license --rpm-licenses`
  rolls up the subject + its resolved runtime deps, and `coverage` surfaces the
  subject's header license. `coverage --sbom FILE` / `license --sbom FILE` still
  consume a *provided* CycloneDX file when one carries licenses; `import-sbom`
  ingests the real `alma-sbom` SBOM for its PURL/CPE/provenance.
- **The axis is binary-complete and needs errata too.** `security_context_complete`
  requires *both* an attached SBOM **and** an errata check. Two errata paths now
  exist: `--errata FILE` (a single provided advisory on one subject) and a
  **live errata source** (D79) `--errata-source http|dnf` that queries advisories
  for **every** RPM. The errata check is **three-state**: `advisory_present` (an
  advisory ships this exact NEVRA), `confirmed_clean` (a source was consulted and
  found none -- this satisfies `has_errata_link`, because a package with no
  advisory is normal, not incomplete), or `not_checked` (no source consulted --
  the only genuinely-open case). Remaining: the AlmaLinux errata feed schema is
  matched leniently (point `--errata-url` at the real `errata.full.json`); CAS
  addressing of the SBOM by `alma_commit_sbom_hash` stays opt-in future work.

### `identity` - two real CPE sources, both honest
The `identity` axis counts binaries with a verified CPE. Two paths populate it:
- **Vendor SBOM (`coverage --build-sbom FILE`).** AlmaLinux's own `alma-sbom`
  asserts a CPE per RPM; matched by `(name, arch)` it sets `cpe` with
  `cpe_source=almalinux_sbom`. On build 57810 this lifts identity to 1.00. This
  is the vendor's own assertion (the authority for its artifact), labelled as
  such and never overriding a stronger prior match.
- **NVD dictionary (`coverage --verify-cpe FILE` or `--verify-cpe-url URL`).**
  Matches `cpe_candidates` against a cpe:2.3 dictionary. The file path is fully
  offline; the URL path uses the HTTP cache and TTL, and degrades gracefully on
  network/tooling failure. Without it (and without a build SBOM) the axis stays
  0.00 (candidates remain unverified, by design).
- **Ambiguous vendors are not asserted.** A product mapping to several vendors is
  recorded as `ambiguous_vendor`, not verified - honest, but uncounted.
- **Backport flag, not CVE math.** `.elN` releases are flagged `distro_backport`;
  full affected-range evaluation is the vuln-report's job, not CPE verification.

### `resolution` ≈ 0.00 - sonames carry no version
Header-derived soname claims have no package version (the symbol version lives in
the name, not a NEVRA), so each reconciles to `INSUFFICIENT_EVIDENCE`. The
resolution axis only rises once a version-resolving source (SBOM or a real
resolver) is added.
- **Lift:** rung 5 resolvers and/or SBOM ingest.

---

## Rung-by-rung implementation status

### Rung 4 - payload ELF analysis (implemented, with caveats)
Implemented: full RPM download → cpio payload → ELF parse of confirmed
`DT_NEEDED`, `DT_RPATH`/`DT_RUNPATH`, dynamic-vs-static linkage, a best-effort
`dlopen` flag, and Go/Rust toolchain detection. Remaining limits:
- **Whole-RPM download, no early-abort.** A compressed payload defeats
  random-access range reads, and the current reader downloads the entire RPM
  rather than stream-decompressing with early-abort. Bounded at 256 MB.
- **zstd needs an optional dependency.** Real el9 payloads are zstd; install
  `pip install '.[payload]'`. gzip/xz/bzip2 work out of the box.
- **Static BOM: Go done, Rust not.** A static **Go** binary's embedded module
  list is now parsed from `.go.buildinfo` (inline format) into Go dependency
  claims (decisions.md D29). Older pointer-based Go layouts are not dereferenced,
  and **Rust** has no comparable embedded module list, so it stays
  toolchain-detected (flag only).
- **`dlopen` is a heuristic.** It scans the dynamic symbol table for
  `dlopen`/`dlmopen` imports; a binary that reaches `dlopen` only transitively,
  or is fully stripped of section headers, may be missed.
- **Section-header dependence.** Analysis uses ELF section headers (present in
  distro RPM binaries); objects stripped of sections return `is_elf=True` with
  empty analysis. 32-bit and big-endian are handled but exercised less.

### Rung 5 - real per-ecosystem resolvers
RPM resolution is available via `dnf repograph` / `rpmgraph`; **Go**
(`go list -m all`), **Cargo** (`cargo metadata`), **PyPI**
(`pip install --dry-run --report`), **Maven** (`mvn dependency:list`) and
**npm** (`npm ls --json --all`) now have real resolvers behind the contract
(`resolve` command, decisions.md D32/D92). Still on `NullResolver`: **Gradle**
and higher-level frontends such as Poetry/uv. All resolvers are host tools: they
run against a checked-out project on the host (the `resolve` CLI is host-side);
the adapters are tested offline with injected runners.

### `dnf repoquery` caveats
- **Host tool, many subprocess calls.** `coverage --use-dnf` runs several
  `dnf repoquery` invocations *per selected package* (requires + weak relations
  + conflicts/obsoletes). Scope it with `--package`/`--arch`/`--limit`; the full
  matrix is slow. Absent `dnf`, it records `available=false` and changes nothing.
- **Weak deps collapse to one scope.** `recommends`/`suggests` both map to
  `DependencyScope.OPTIONAL` (the precise relation is kept in the claim's raw).
  RPM also has `supplements`/`enhances` (reverse weak deps) which are not yet
  emitted as claims.
- **`--whatprovides` resolves sonames to providers.** `coverage
  --resolve-sonames` runs it (and `--provides-map FILE` is the offline
  equivalent), so a header/ELF soname gains a `soname_provider` package claim
  that corroborates the SBOM/dnf claims (see "Soname → package resolution" below).
  Remaining: the *first* provider wins when several supply a soname.

### `dnf repograph` / `rpmgraph` caveats
- **Host tools, ingested via dot.** The tested path is `--repograph-dot FILE`
  (output you generate on an AlmaLinux host). Live `run_repograph`/`run_rpmgraph`
  require `dnf`/`rpmgraph` on `PATH`; they are not exercised in CI.
- **Version depends on node labels.** `rpmgraph` NEVRA labels yield a version
  (counts toward the resolution axis); `dnf repograph`'s bare package names do
  not, so those claims reconcile to `INSUFFICIENT_EVIDENCE`.
- **Capability edges become name claims.** An edge target like
  `libc.so.6()(64bit)` is recorded as a dependency named by that capability
  string, not mapped to a providing package (the same soname↔package gap above).

---

## Vault URL reconstruction is heuristic

The ALBS artifact `href` is a Pulp content API path that does not resolve to a
direct download without distribution context. We instead reconstruct
`vault.almalinux.org/{ver}/{repo}/{arch}/os/Packages/{file}` from the RPM's NEVRA
and try a fixed repo list (`BaseOS`, `AppStream`, `CRB`, `extras`,
`HighAvailability`).

Known gaps observed on build 17812 (2 of 8 sampled RPMs failed to resolve):
- `i686`, module RPMs, and some repo layouts are not covered by the candidate
  list.
- Only **superseded** point-release builds are reliably in the vault; current
  builds live under the rolling `almalinux/` tree at a different path.
- Debug RPMs (`-debuginfo`/`-debugsource`) are skipped by design.
- The `--limit` default in demos processes a subset; a full run is sequential and
  unbatched (see Scale).

A Pulp-href resolver (querying the content API for `location_href`) would be more
correct than NEVRA reconstruction but needs the distribution base path.

---

## Reconciler scope

The reconciler (see `decisions.md` D7, D26):
- detects `VERSION_DRIFT` by **rpmvercmp equivalence** now, not exact string
  (`1.01` == `1.1`); and fires `RANGE_VIOLATION` on declared **relational**
  constraints (`name >= 3.2`) checked against a concrete version, in addition to
  the resolver-asserted `range_satisfied=False` path. Caveats: only relational
  operators are evaluated (`=` provides/config skipped), **epochs are stripped**
  before comparison, and only simple `name OP version` constraints are parsed
  (Maven brackets / compound pip ranges are not).
- auto-detects `IDENTITY_MISMATCH` when two claims assert the **same version**
  with **different PURL coordinates** (a real cross-source identity disagreement,
  distinct from version drift). It only fires when at least two claims carry a
  PURL, so the common single-PURL group is never flagged. PURL **qualifier
  order** is canonicalised (sorted) before comparison so `...?arch=x&distro=el10`
  and `...?distro=el10&arch=x` are recognised as the same identity (D69).
  Remaining caveats: URL-encoded values (`%2F` vs `/`) and scheme case are not
  normalised; both spec-compliant variants would still compare unequal until a
  full PURL parser is wired in.
- treats `context` as part of the grouping key via a string serialization; two
  contexts that differ only in field ordering are normalized, but exotic context
  values are compared as strings.

### Soname → package resolution (implemented, with caveats)
`coverage --resolve-sonames` (via `dnf --whatprovides`) or `--provides-map FILE`
(offline JSON) now bridges the soname↔package gap: a `libz.so.1` claim gains a
`soname_provider` package claim (`zlib@...`) that corroborates SBOM/dnf claims
(see `decisions.md` D14). Remaining limits:
- **Needs dnf or a provides map.** Without either, sonames stay in their own
  coordinate space (still deliberately excluded from `PRESENCE_UNDECLARED`).
- **Unresolved sonames remain unmapped.** A soname with no provider in the repo
  (or absent from the supplied map) is left as-is.
- **First provider wins.** When several packages provide a soname,
  `build_soname_index` records the first; alternatives are not modelled.

---

## GPG signature verification (`--verify-signatures`)
`coverage --verify-signatures` downloads each selected RPM and runs
`rpmkeys --checksig`, but:
- **Host + network.** It needs `rpmkeys`/`rpm` with the AlmaLinux GPG keys
  imported, and downloads full RPMs (scope with `--package`/`--arch`/`--limit`).
  Absent `rpmkeys` it records `unavailable` and skips downloads - never an error.
- **Report-only.** Like CAS, a successful check flips `signature_verified` /
  `externally_verified` but does **not** change the presence-based `provenance`
  axis; verification is surfaced separately.

## Verification vs. reporting

CAS hashes are **reported, not verified** by default: `externally_verified`
stays `false` unless `--use-cas` runs a successful `cas authenticate`. The
build-17812 provenance score of 1.00 reflects *evidence present and well-formed*,
not *cryptographically re-verified*.

`--use-cas` is opt-in and crash-proof, but in practice the `cas` binary is now
**uninstallable** (Codenotary changed product lines; `getcas.codenotary.io` and
the GitHub releases 404). So on most hosts CAS verification records `unavailable`
and changes nothing - by design, never an error. If you have a host that still
has `cas`, `--use-cas` will use it.

---

## Python language dependencies
`coverage --requirements FILE` parses requirements.txt and (best-effort) imports
into PyPI claims, but:
- **Module name ≠ package name.** `import foo` records the *module*; mapping it
  to its distribution (e.g. `cv2` -> `opencv-python`) is not done.
- **Markers are recorded, not evaluated.** A `; python_version < "3.8"` marker is
  kept in the claim's raw but does not gate the claim by context.
- **requirements.txt + imports only for static PyPI claims.** `pyproject.toml` /
  Poetry / Pipfile are still not parsed as manifests here. For concrete PyPI
  resolution, use the separate rung-5 `resolve --ecosystem pypi --manifest
  requirements.txt` path, which shells out to pip's dry-run report.

## `identify` ownership resolution
`identify <filepath>` walks the provenance graph fully offline, but mapping a
file to its owning package depends on:
- `--owner` (explicit), or an `owner_lookup`, or ELF paths from rung-4 payload
  analysis, then host `rpm -qf` (installed files), then `dnf repoquery --file`
  (repo files - works even when the package is not installed locally).
- Full RPM **file lists are stored when rung-4 payload analysis has run**
  (`--with-rpm-payloads`), making any owned file (configs, docs) resolvable
  offline from graph data. Without payload analysis, a file that is neither
  installed nor in the enabled repos still needs `--owner`. File lists can be
  large, so they are only populated by payload analysis.

## Vulnerability-applicability report (`vuln`)
The `vuln` command reports CVEs a build **addresses via errata** and, with
`--cve-feed` or `--cve-feed-url`, **potentially-affected** CVEs (verified CPE +
version matched against the feed's affected ranges). Remaining limits:
- **Live feed fetch is best-effort.** `--cve-feed FILE` is the deterministic
  offline path; `--cve-feed-url URL` uses the HTTP cache and TTL, and returns no
  live feed when fetching or parsing fails.
- **Backport matches are advisory.** A `distro_backport` package keeps its
  upstream version, so a range match is flagged "verify" rather than asserted -
  it may be a false positive (fix backported without a version bump).
- **Reachability is a hint, not a proof.** `dlopen` / static counts indicate
  exposure breadth; they do not prove a specific CVE's code path is reachable.

## `dnf repograph` repo selection
`dnf repograph` selects a repo with the global `--repo` flag, **not** a
positional argument (`dnf repograph appstream` is rejected). `run_repograph` and
`universe --repograph <repo>` use `--repo`; for a manual dot, run
`dnf repograph --repo appstream > appstream.dot`.

## Dependency universe
`universe_from_dot` / `build_universe` / `build_arch_universe` + traversal exist,
but:
- **Live fetching needs host tooling.** `arch-universe` can run `dnf repograph`
  for every known repo of an arch, but it needs `dnf` on the host. Missing or
  failing repos are recorded as skips, not fatal errors.
- **First definition wins on merge.** When the same `pkg:<name>` appears in
  several sources, `merge_graphs` keeps the first node's metadata (e.g. arch);
  edges from all sources are unioned.
- **`build_universe` needs claims.** From `--source` alone (raw ALBS metadata)
  it has no dependency edges until the graph is enriched (headers/dnf/repograph/
  sonames); the repo-wide `--repograph-dot` path is the populated one.
- **Substring node matching.** `--dependents-of` / `--path-to` match nodes by
  name/coordinate substring, which is convenient but can over-match.
- **Visualization is focused-subgraph only.** Queries render `path_subgraph` /
  `neighborhood_subgraph` (the chain or one hop), not a laid-out view of the
  whole universe (which would be unreadable at repo scale). `svg` needs Graphviz
  on PATH; `dot`/`json` are dependency-free.

## SQLite store
The `albs_graph/store.py` persistence is intentionally lightweight:
- **One- and multi-hop SQL.** `sql_dependents` / `sql_dependencies` (one hop)
  plus `sql_reachable_dependencies` / `sql_dependency_paths` (recursive CTE)
  run without loading the graph, so a repo-wide universe is walkable from the
  persisted store. Rendering still `load_graph`s the whole store into memory.
- **Substring/exact name matching** (label / `pkg:<name>` / `cap:%<name>`), same
  trade-off as the in-memory traversal.
- **Replace and merge modes.** `save_graph(..., mode="replace")` is the original
  behaviour; `mode="merge"` upserts and deep-merges node + edge metadata so
  multi-build / multi-arch accumulation does not lose claims. There is still no
  concurrency control: treat it as single-writer.
- **Versioned schema and snapshots.** In-place migrations are idempotent, and
  `save_analysis_snapshot` / `load_analysis_snapshot` persist coverage / vuln /
  license reports as JSON payloads keyed by `(kind, subject_id)`.
- **No vector/similarity.** A `sqlite-vec` overlay is noted in the plan but not
  implemented.

## Scale and performance

The current implementation targets correctness and demonstrability, not the
stated "thousands of applications":
- Beyond the SQLite store, there is **no heavier query backend**; rendering and
  some focused graph operations still load the full store into memory.
- Header/payload/signature fetches have content-addressed caching and bounded
  concurrency, but cache invalidation is still age/config driven rather than
  registry-state driven.
- Reconciliation is a single full pass; there is no incremental re-reconciliation
  as new evidence arrives.
- Native resolver runs are host-tool executions; there is no sandboxing layer or
  persistent resolver-result cache yet.

---

## Desktop workbench (GUI)

The PyQt5 investigation workbench is a read-only frontend over the same
`services` facade; its current limits:

- **`gui/qt_app.py` is large but now fully typed.** The main window was a
  single ~2.6k-line class under a blanket `# mypy: ignore-errors`. It has been
  split into typed `QWidget` panel modules -- Universe (`gui/universe_panel.py`,
  D102), Security (`gui/security_panel.py`, D103), Dependency
  (`gui/dependency_panel.py`, D104), Timeline (`gui/timeline_panel.py`, D105) --
  and the residual shell was then made strict-clean and the **blanket ignore
  retired** (D106): `qt_app.py` (now ~2k lines) type-checks under `mypy
  --strict` with the rest of the package, with **exactly one** targeted
  `# type: ignore[arg-type]` (the idiomatic `QWidget.close` -> void signal). The
  remaining limit is interaction *coverage*, not typing: headless + interaction
  tests drive construction, result-handling, slice rendering, the inspector, the
  four panels, the M5 Markdown/PNG export + session capture/restore and the
  read-only paths (view switch, layer filter, graph search, zoom, queries,
  finding drill-down, recipes, edge inspect, bundle/HTML export, session save) --
  ~73% line coverage; deeper interaction coverage is the open follow-up. The
  analysable logic lives in the well-covered, typed `services/` layer (80-97%).
- **Needs a Qt platform.** Tests run headless via `QT_QPA_PLATFORM=offscreen`;
  a real run needs a display. Graphviz (`dot`) renders the graph and degrades
  to a built-in fallback SVG when absent.
- **Rendering is stretch-to-fill SVG** in a scroll area (zoom / fit / reset),
  not an interactive graphics scene; a whole large build is best read as
  focused slices rather than the full graph. Slice export is SVG or PNG.
- **The Security panel's *Potential CVEs* column needs a CVE feed + a resolved
  CPE.** Both are now wired (D101): a CVE-feed field (file or cached URL) and a
  CPE-dictionary "verify" field that resolves an official CPE the feed can match.
  Without them the column reads `-`; addressed CVEs (via errata) always populate.
  A vendor-asserted SBOM CPE alone rarely matches NVD tokens, so verify is the
  load-bearing input.
- **Single-window, single-build.** No multi-build tabs. Session save/load now
  persists the dependency filters + the universe store/favourites alongside the
  inputs and selection. The `--build-id` path fetches live (no metadata-cache
  reuse) -- re-open a cached `--source` JSON to work offline.
- **The Git tab is Gitea-specific and network-dependent (D144).** It queries the
  public `git.almalinux.org` Gitea API for a `git_commit` node's message +
  changed files and its raw `.diff`; a non-Gitea repo URL, the
  `unknown-albs-source:<pkg>` placeholder, or an offline server yields just the
  web link. The per-file diff is **sliced client-side** from the whole-commit
  diff by the `b/` path, so a file that does not appear in that diff (or an
  unusual rename) falls back to showing the entire commit diff. Read-only: it
  shows commits, it does not check them out.

---

## Testing boundary

Per the repo rule, tests never hit the network. The remote RPM path is exercised
by serving a hand-built RPM byte structure through a fake range fetcher, so the
parser, incremental fetch loop, and claim generation are covered - but **live
vault/mirror behavior** (redirects, `Accept-Ranges` quirks, 404s, throttling) is
only validated manually, not in CI.

## AlmaLinux security errata is downstream of RHEL

AlmaLinux is a 1:1 RHEL rebuild, so its security fixes and advisories are
**inherited from upstream Red Hat**. A CVE is tracked first at Red Hat
(`access.redhat.com/security/cve/<id>`) and shipped via an **RHSA**; AlmaLinux
re-publishes the same advisory number as an **ALSA** (RHSA-2026:21378 ↔
ALSA-2026-21378 -- the same advisory, "doubled"). AlmaLinux's own errata pages
are terse, and a CVE can be real for an AlmaLinux RPM while AlmaLinux's own
errata is sparse or only fully described upstream.

Consequences for this tool:

- A *missing ALSA* does not mean "not affected" -- check the upstream RHSA / Red
  Hat CVE record. The workbench surfaces both: CVE nodes link the Red Hat CVE
  page, and an errata (ALSA) node links its AlmaLinux errata page **and** the
  corresponding upstream `RHSA` advisory + the CVEs it fixes (D139).
- The `ALSA`↔`RHSA` mapping is a number-preserving prefix swap
  (`ALSA`/`ALBA`/`ALEA` ↔ `RHSA`/`RHBA`/`RHEA`); it is a heuristic over the
  documented AlmaLinux ↔ RHEL correspondence, not a fetched cross-reference, so a
  hypothetical renumbered advisory would not resolve.
- We do **not** fetch the Red Hat security-data API; the upstream links are
  derived locally (offline-safe). Pulling the authoritative Red Hat record
  (affected packages, fix state) is a possible future enrichment.

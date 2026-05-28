# Decisions

This document records the architecture and design decisions made while extending
`albs-provenance-explorer` from a read-only metadata explorer toward a
**maximal, conflict-aware provenance + dependency graph** over ALBS data.

All work landed on branch `max` in two commits:

- `1339b8e` - conflict-aware dependency reconciliation, resolver contract, coverage axes.
- `f5b6bdd` - public-data rungs: RPM header range reads, linkage claims, `coverage` CLI.

Together they touch 17 files (~1.8k insertions) and keep `pytest`, `ruff` and
`mypy --strict` green. Tests never hit the network.

---

## Framing: what we are optimizing

The pre-existing codebase already encoded three load-bearing distinctions that
most supply-chain tools conflate. We treated them as invariants, not things to
re-litigate:

1. **Identity is three things, not one.** PURL (package coordinate) ≠ CPE
   (security-applicability identity) ≠ CAS (build/source/artifact evidence). The
   graph stores `pkg:rpm/almalinux/...` PURLs, `cpe: null` plus unverified
   `cpe_candidates`, and CAS attestation as a separate node class.
2. **Evidence ≠ resolution.** Discovering a `package.json`/`go.mod` is evidence;
   running pip/Maven/Cargo/Go resolution is a separate, expensive, context-
   dependent step.
3. **Scope/linkage/context are part of dependency identity**, not free-form tags.

"Maximal fulfillment" was made measurable: drive five orthogonal **coverage
axes** toward 1.0 and report the irreducible residue rather than a single green
checkmark. This objective function drives every decision below.

---

## D1 - "Could not resolve" is a first-class outcome

**File:** `albs_graph/dependency/model.py`

Added `ResolutionState.UNRESOLVABLE`, `AMBIGUOUS`, `RESOLUTION_SKIPPED` and a
`resolution_note` field on `DependencySpec`.

**Why.** A tool that only ever reports success lies about its coverage. A failed
or skipped resolution must be distinguishable from a merely `DECLARED` one, and
must carry *why* (e.g. "uv: no version of X satisfies >=9999"). Downstream
consumers (security, compliance) need to know which trees are evidence-only.

---

## D2 - Model the disagreement (do not collapse evidence)

**Files:** `albs_graph/model/nodes.py`, `model/edges.py`,
`albs_graph/provenance/reconcile.py`

The single biggest design decision. A logical dependency is **not** collapsed
into one resolved edge. Instead each evidence source contributes a
`DependencyClaim`; claims describing the same logical dependency
`(subject, package-coordinate-without-version, context)` are reconciled into a
`DEPENDENCY_RESOLUTION` verdict, with the underlying claims preserved.

New vocabulary (extended first, per the repo rule):

- Node types: `DEPENDENCY_CLAIM`, `DEPENDENCY_RESOLUTION`.
- Relations: `OBSERVED_AS` (resolution → claim), `CORROBORATES`,
  `CONFLICTS_WITH` (claim ↔ claim).
- `Agreement` verdicts: `CONSENSUS` (≥2 independent sources agree on a version),
  `COMPATIBLE` (one concrete version, nothing contradicts), `CONFLICT`,
  `INSUFFICIENT_EVIDENCE` (no concrete version anywhere).
- `ConflictKind`: `VERSION_DRIFT`, `RANGE_VIOLATION`, `PRESENCE_UNDECLARED`,
  `LINKAGE_MISMATCH`, `IDENTITY_MISMATCH`.

**Why.** When manifest, lockfile, resolver and shipped artifact disagree
(AlmaLinux backports are a routine example), picking one "source of truth"
destroys information the consumers need. The conflict-aware graph is a superset:
vuln triage reads the artifact-observed claim, license compliance reads the
resolved tree, reproducibility reads the lockfile-vs-artifact triple - one
graph, three projections.

---

## D3 - Typed resolver contract; never reimplement a solver

**File:** `albs_graph/dependency/resolver.py`

`ResolverRequest` / `ResolverResult` / `DependencyResolver` (a `Protocol`), plus
a `NullResolver` baseline and a context-sensitive `cache_key`.

**Why.** Each ecosystem's package manager is the source of truth for that
ecosystem's semantics (pip/uv, Maven nearest-wins mediation, Cargo features, Go
MVS, libsolv). Reimplementing them produces answers that look right and are
wrong. The "unified" part of the system is this contract plus the graph storage,
**not** a shared solver. A real resolver shells out to the authoritative tool and
returns a `ResolverResult`; `unresolved` is never silently dropped. The cache key
includes `context`, so two pip deps under different markers do not collapse.

---

## D4 - Five-axis coverage with honest residue

**File:** `albs_graph/provenance/coverage.py`

`coverage_report(graph)` computes orthogonal axes: `resolution`, `linkage`,
`identity`, `provenance`, `security_context`. `identity` counts only
**verified** CPEs (unverified candidates deliberately do not count).

**Why.** "All three consumers equally" means no axis may be sacrificed. A sparse
graph honestly reports low coverage on axes nothing has fed yet (today: linkage,
identity, resolution) while provenance stays high. The report is the deliverable;
the residue is part of it.

---

## D5 - The cost ladder, and choosing rung 3 for public access

**Files:** `albs_graph/adapters/rpm_header.py`, `adapters/rpm_remote.py`,
`cli/main.py` (`coverage` command)

Data acquisition is a cost ladder. The PoC sat on rung 1 (ALBS metadata). We
implemented **rung 3** (RPM header via HTTP Range) because it is the highest-
value rung reachable with current public access:

| Rung | Acquires | Public access | Status |
|------|----------|---------------|--------|
| 1 | ALBS metadata | open API | pre-existing |
| 2 | git spec/manifests | open git | pre-existing |
| 3 | RPM header (range read) | open mirror/vault | **implemented** |
| 4 | payload ELF (RPATH/RUNPATH/dlopen/toolchain) | open, but large | **implemented** |
| 5 | resolver execution | needs tooling | contract only |

Key insight: the RPM **header** already encodes dynamic `DT_NEEDED` sonames
(`RPMTAG_REQUIRENAME`), because rpmbuild's automatic dependency generator runs
ELF extraction at build time. So dynamic-linkage evidence needs **no payload and
no ELF parse** - only the first tens of KB of the file. `repo.almalinux.org` /
`vault.almalinux.org` serve `Accept-Ranges: bytes`, confirmed against the real
build-17812 `nginx-core` RPM (HTTP 206, lead magic `edabeedb`).

Sub-decisions:

- **Self-contained header parser** (`rpm_header.py`) rather than depending on
  `rpm`/`rpmfile` for remote bytes: parses lead + signature + main header from a
  byte buffer; `required_header_length()` enables incremental fetching.
- **Vault URL reconstruction** from NEVRA. The ALBS artifact `href` is a Pulp
  content path that does not resolve to a download without distribution context,
  so we rebuild `vault/{ver}/{repo}/{arch}/os/Packages/{file}` candidates from
  the RPM's own release string (`.elN_M` → point release) and try each repo.
- **Soname dedup.** A package requires the same soname under many symbol
  versions (`libc.so.6(GLIBC_2.2.5)`, `(GLIBC_2.34)` …). Those are one logical
  dynamic dependency on `libc.so.6`; they collapse to one claim that keeps every
  expression in its raw payload. (This surfaced as a real "conflicting node"
  crash on live data and was fixed.)

---

## D6 - `PRESENCE_UNDECLARED` requires subject-level declaration context

**File:** `albs_graph/provenance/reconcile.py`

Refined after live data showed every header soname being flagged as a presence
conflict. `PRESENCE_UNDECLARED` now fires only when the **subject has
declaration evidence somewhere** (a manifest/lockfile/resolver claim). With
header-only ingest, a lone soname observation is `INSUFFICIENT_EVIDENCE`, not a
false conflict.

**Why.** An RPM header soname *is* the package's declared dynamic dependency, not
"vendored code nothing declared." `PRESENCE_UNDECLARED` is meaningful only
relative to a declaration source that could have mentioned it.

---

## D7 - The reconciler does not evaluate version ranges

`reconcile.py` detects only cross-source disagreement it can establish soundly:
`VERSION_DRIFT` (different concrete versions, exact inequality), `LINKAGE_MISMATCH`
(static vs dynamic), `PRESENCE_UNDECLARED` (set logic). `RANGE_VIOLATION` is
surfaced only when a resolver **asserts** it via a `range_satisfied=False` claim
flag.

**Why.** Deciding whether `3.0.9` satisfies `>=3.2` is per-ecosystem version
math - the authoritative resolver's job (D3). Doing it in the reconciler would
re-introduce exactly the solver-reimplementation mistake we are avoiding.

---

## D8 - Reported ≠ verified stays labelled

Every fact carries the provenance of *how* it was established:

- Header sonames are tagged `evidence="rpm_header_soname"` - RPM's recorded
  dependency facts, not an independent ELF parse.
- CAS hashes remain `externally_verified: false` until an explicit `cas` step
  records verification.
- CPE stays `null` with unverified `cpe_candidates`; the identity coverage axis
  counts only verified CPEs.

**Why.** "We maximized coverage" must never silently mean "we asserted things we
didn't check."

---

## D9 - CycloneDX-from-file SBOM claims

**Files:** `albs_graph/adapters/sbom.py`, `cli/main.py` (`coverage --sbom`),
`provenance/reconcile.py`

`cyclonedx_dependency_claims()` / `attach_cyclonedx_sbom_claims()` turn the
components of a CycloneDX SBOM into versioned dependency claims
(`evidence="sbom"`, `resolution_state=OBSERVED`) on a subject RPM, and attach the
SBOM evidence node. `coverage --sbom FILE --sbom-subject RPM` wires it into the
pipeline. Because each component carries a concrete version (from its PURL), the
reconciler resolves it to `COMPATIBLE`, so **SBOM ingest raises the resolution
axis** and lets package versions drift-check against other sources.

**Why a *file* path, not a ledger fetch.** AlmaLinux SBOMs live in Codenotary
immudb and require the `alma-sbom`/`cas` tooling plus credentials; there is no
documented anonymous read. So we consume a *provided* CycloneDX file (the
artifact `alma-sbom` produces) rather than fabricating a fetch - the tractable
step under current public access.

Two reconciler refinements were required to make SBOM + header evidence coexist
honestly:

- **`"sbom"` evidence is classified `resolved`, checked before the `"bom"`
  artifact token** - otherwise "sbom" would be mis-read as ELF binary analysis
  (which `static_bom` genuinely is).
- **Soname capabilities are excluded from `PRESENCE_UNDECLARED`.** A soname
  (`libz.so.1`) and a package (`zlib`) live in different coordinate spaces;
  package-level SBOM declarations neither declare nor contradict sonames. Without
  this, attaching an SBOM would falsely flag every dynamically linked soname as a
  presence conflict. (Confirmed on build 17812: SBOM + live header reads produce
  20 reconciled deps and **zero** false conflicts.)

The soname-to-providing-package mapping (so `libz.so.1` could cross-validate
against the `zlib` component) is intentionally future work; see `limitations.md`.

---

## D10 - Rung 4: full payload ELF analysis

**Files:** `albs_graph/adapters/elf.py`, `adapters/rpm_payload.py`,
`adapters/rpm_header.py` (payload offset/compressor), `cli/main.py`
(`coverage --with-rpm-payloads`)

Downloads the whole RPM, decompresses the cpio payload, and parses each ELF to
recover what the header cannot: confirmed `DT_NEEDED`, `DT_RPATH`/`DT_RUNPATH`,
dynamic-vs-static linkage, a best-effort `dlopen` flag, and the build toolchain
(Go/Rust). Confirmed sonames become `evidence="elf_dt_needed"` claims that
**corroborate** the rung-3 `rpm_header_soname` claims (reported vs. independently
verified); RPATH/RUNPATH/dlopen/static facts land on the binary RPM node under
`elf_analysis`.

Sub-decisions:

- **Own ELF parser, no `pyelftools` dependency.** Mirrors the dependency-free
  `rpm_header` parser: parse the ELF header + section headers, then `.dynamic` /
  `.dynstr` / `.dynsym`. Binaries stripped of section headers return
  `is_elf=True` with empty analysis rather than raising.
- **This crosses the "metadata-only" boundary on purpose.** Rung 4 fetches and
  decompresses real artifact bytes - the deliberate step beyond the PoC's
  read-only framing, taken because dynamic-loading facts (dlopen) and static
  linkage are otherwise invisible. Verified on build 17812: `/usr/sbin/nginx`
  reports `dlopen=true`, which the header cannot reveal.
- **zstd is an optional extra (`pip install '.[payload]'`).** gzip/xz/bzip2 use
  the standard library (and the offline tests), so the core install stays light;
  only real el9 zstd payloads need `zstandard`.
- **Static-BOM module extraction is detected, not parsed.** Go/Rust toolchains
  are flagged from ELF sections, but enumerating a static Go binary's module
  graph (parsing `.go.buildinfo`) is left as follow-up; see `limitations.md`.

---

## D11 - Optional, crash-proof CAS verification (`--use-cas`)

**Files:** `albs_graph/adapters/cas.py`, `cli/main.py` (`coverage --use-cas`),
`example--almalinux.sh`

CAS verification is strictly opt-in and never required. The `cas` binary is
frequently uninstallable now (Codenotary changed product lines; the public
installer/releases 404), so `verify_hash` / `verify_graph_cas` return a recorded
`unavailable` status instead of raising, and `example--almalinux.sh` no longer
`exit 1`s when `cas` is missing - it reports the ALBS hashes and skips
verification with a clear "reported, not verified" note.

Only a successful `cas authenticate` flips a CAS node's `externally_verified`
from false to true - the single sanctioned place to assert CAS evidence was
independently verified, per the "reported, not verified" rule. The runner is
injectable so the whole path is tested offline without the binary.

---

## D12 - AlmaLinux-native resolution via `dnf repograph` / `rpmgraph`

**Files:** `albs_graph/adapters/rpmgraph.py`, `provenance/trust.py`
(`make_binary_rpm_selector`), `cli/main.py` (`coverage --repograph-dot` + arch/
package selectors)

`dnf repograph` (dnf-plugins-core) and `rpmgraph` (rpm) ship on AlmaLinux and
emit a package dependency graph in Graphviz dot - a *real* RPM resolution via
libsolv/rpm, i.e. rung 5 for the RPM ecosystem using the authoritative tooling
rather than a reimplemented solver. The adapter parses dot edges and emits
resolved dependency claims (`evidence="repograph"`/`"rpmgraph"`,
`resolution_state=RESOLVED`, namespace `almalinux` so they align with ALBS PURLs
and reconcile against SBOM claims). NEVRA node labels yield a version (counts
toward the resolution axis); bare names do not.

Sub-decisions:

- **dot-ingest is the tested path; live run is host-only.** `--repograph-dot
  FILE` ingests output the user generated on an AlmaLinux host
  (`dnf repograph --repo appstream > repo.dot` - repo via `--repo`, not a
  positional argument), so the parser is fully
  offline-testable. `run_repograph` / `run_rpmgraph` shell out when present and
  raise `RpmgraphUnavailable` (treated as "skipped") otherwise - never crash.
- **Enrichment is scoped by a selector.** `make_binary_rpm_selector` filters by
  `--package` and `--arch`, defaulting to x86_64 + noarch so a plain run does not
  fan out across every architecture; `--all-archs` widens it. The same selector
  scopes header (rung 3) and payload (rung 4) enrichment, exposed as
  `--package` / `--arch` / `--all-archs` / `--all-packages`.

---

## D13 - Deep `dnf repoquery` extraction + portable/native example split

**Files:** `albs_graph/adapters/dnf.py`, `cli/main.py` (`coverage --use-dnf`,
`--repograph`), `example.sh`, `example--almalinux-native.sh`

`dnf repoquery` is the richest native source, so the dnf adapter extracts as
much as is well-defined:

- `--requires --resolve` -> versioned RUNTIME dependencies (real resolution that
  counts toward the resolution axis),
- `--recommends` / `--suggests` (resolved) -> weak dependencies, scope OPTIONAL,
- `--conflicts` / `--obsoletes` -> recorded as `dnf_relations` node facts,
- `--whatprovides <capability>` -> the soname -> providing-package mapping.

Claims use namespace `almalinux`, so they reconcile against SBOM and repograph
claims. Like every native adapter the runner is injectable (tested offline) and
absence of `dnf` returns `available=false` rather than raising. `--repograph
REPO` runs `dnf repograph` live and ingests it; `RpmgraphUnavailable` is caught
and reported, never fatal.

**Two example scripts, by environment:**

- `example.sh` - **portable** (any OS): synthetic fixture, offline coverage,
  trust path, rung-3 header reads, rung-4 payload (if the `payload` extra is
  installed). No AlmaLinux-native tools required; optional steps degrade.
- `example--almalinux-native.sh` - **AlmaLinux-native**: detects
  dnf/rpm/rpmgraph/cas/zstandard and exercises `--use-dnf`, `--repograph`,
  rung 3/4, and `--use-cas`, each skipped gracefully when its tool is absent.
  `FULL=1` runs the full `--all-packages --all-archs` matrix.

(`example--almalinux.sh`, the CAS-focused demo, remains and is now crash-proof.)

---

## D14 - Soname -> providing-package resolution

**Files:** `albs_graph/adapters/dnf.py`, `provenance/reconcile.py`,
`cli/main.py` (`coverage --resolve-sonames` / `--provides-map`)

Closes the soname↔package coordinate gap from D9. `build_soname_index` maps each
soname to a providing package NEVRA (via `dnf --whatprovides`, or a supplied
JSON map for offline use); `resolve_soname_claims` then adds a package-level
`soname_provider` claim (e.g. `zlib@1.2.11-40.el9`) on the same subject for every
resolved soname. That claim shares the package coordinate with SBOM / dnf /
repograph claims, so a dynamically linked `libz.so.1` now **corroborates** the
`zlib` package claim instead of sitting in its own space.

Two reconciler fixes were required:

- **Soname detection is now name-based** (`.so` in the coordinate name), not
  evidence-string based. The old `"soname" in evidence` check missed rung-4
  `elf_dt_needed` claims, which would have been falsely flagged
  `PRESENCE_UNDECLARED` once an SBOM made the subject "have declarations". This
  was a latent bug fixed here with a regression test.
- **`soname_provider` evidence classifies as `resolved`** (checked before the
  `soname` artifact token), since it is the resolved package behind a soname.

Offline-testable: `resolve_soname_claims` takes a plain dict, and
`build_soname_index` takes an injectable runner.

---

## D15 - `identify`: file -> full provenance lineage

**Files:** `albs_graph/provenance/identify.py`, `cli/main.py` (`identify`)

`identify <filepath>` answers "what produced and installed this entity?" It
resolves the owning package, then walks the provenance graph to report every
element behind the file: source package, git repo + commit, CAS source
attestation, build task + environment, SRPM, the binary RPM, signature, release
repository, artifact CAS attestation, SBOM, and resolved dependencies.

Ownership resolution order: explicit `--owner`, an injectable `owner_lookup`
(host `rpm -qf` / `dnf provides`), ELF paths recorded by rung-4 payload
analysis, then host `rpm -qf`. The graph traversal is offline and fully tested;
only ownership may touch the host, and it degrades to "could not determine
owning package" rather than failing.

Verified on build 17812: `identify /usr/sbin/nginx --owner nginx-core` lists the
complete nginx → commit → build task 188077 → RPM → sign task → release chain.

---

## D16 - The dependency "universe" + traversal (scaling)

**Files:** `albs_graph/provenance/universe.py`, `cli/main.py` (`universe`)

A cross-package, traversable graph - the first concrete step on the scaling
vision. Two builders:

- `universe_from_dot(dot)` - from a `dnf repograph` / `rpmgraph` dot of a whole
  repo: one node per package, `requires` edges between them. `libc`/`glibc` ends
  up with an incoming edge from every package that links it.
- `build_universe(graph)` - collapses an enriched provenance graph's per-subject
  dependency *claims* into shared capability nodes, so a single `libc.so.6` node
  is shared by every artifact (carrying linkage/evidence), and `soname_provider`
  claims add `package -PROVIDES-> soname` bridges.

Traversal helpers: `dependents_of` (who links libc), `dependencies_of`,
`reachable_dependencies`, `dependency_paths` (chains from any node to a target).
Direction matters: `dependents_of`/`dependencies_of` follow only *requires*
edges; PROVIDES is followed only during reachability/path walks so a soname
bridges to its provider - getting this wrong made `glibc` look like a *dependent*
of `libc.so.6` (caught by a test).

CLI: `universe --repograph-dot FILE --dependents-of glibc` / `--dependencies-of
nginx-core` / `--path-from X --path-to Y`, or render the universe as dot/svg/json.

---

## D17 - Python language dependencies (requirements.txt + imports)

**Files:** `albs_graph/adapters/pylang.py`, `cli/main.py`
(`coverage --requirements`)

The graph is not RPM-only. `pylang` turns Python `requirements.txt` lines and
top-level `import` statements into PyPI dependency claims that reconcile
alongside RPM/SBOM/dnf claims: a pinned `==` requirement is a LOCKED claim with a
version (counts toward resolution), a range/bare name is DECLARED, and an
`import foo` is a DECLARED, version-less claim. It records evidence, not
resolution - running a real pip/uv resolve is rung 5 for PyPI. CLI:
`coverage --requirements FILE [--requirements-subject RPM]`.

This is the template for other language ecosystems (npm/Cargo/Go/Maven): a
manifest parser emitting normalized claims, with the real resolver deferred to
rung 5 behind the existing `ResolverResult` contract.

---

## D18 - Arch-wide universe merge

**Files:** `albs_graph/provenance/universe.py`, `adapters/rpmgraph.py`,
`cli/main.py` (`universe --repograph-dot` repeatable + `--source` repeatable)

Combines many sources into one arch-wide universe. The enabling decision is
**canonical node ids**: `build_universe` now re-keys packages to `pkg:<name>`
(keeping the original RPM id in `rpm_node_id`), matching `universe_from_dot`. So
when `merge_graphs` unions several universes, a package appearing in several
repos is one node and cross-repo edges connect - appstream's `nginx-core`
reaches baseos's `glibc` and on to `filesystem`.

`build_arch_universe(dots=..., graphs=..., arch=...)` builds a component universe
per repograph dot and per enriched build graph, then merges them. CLI:
`universe --repograph-dot baseos.dot --repograph-dot appstream.dot
--dependents-of glibc` lists every package across the arch that links glibc.

Fixed along the way: `parse_dot_edges` used `re.search` per line and captured
only the first edge on a line; switched to `finditer` over the whole text so
multiple edges per line are all captured (regression test added).

---

## D19 - Visualizing traversal (focused subgraphs)

**Files:** `albs_graph/provenance/universe.py` (`path_subgraph`,
`neighborhood_subgraph`), `cli/main.py` (`universe` rendering)

A universe query plus a graphical format renders the *focused* subgraph rather
than the whole (potentially huge) universe:

- `universe --path-from X --path-to Y --format svg` -> `path_subgraph` of just
  the chain nodes/edges (e.g. nginx-core -> openssl-libs -> glibc).
- `--dependents-of glibc --format dot` -> `neighborhood_subgraph` of glibc plus
  everything that requires it.
- `--dependencies-of nginx-core --format svg` -> glibc/openssl-libs neighborhood.

Without a graphical format the queries stay textual (lists / `a -> b -> c`).
Rendering reuses the existing `render/` layer (dot is pure text; svg needs
Graphviz on PATH), so focused chains export cleanly for review.

---

## D20 - Low-footprint SQLite persistence (stay small)

**Files:** `albs_graph/store.py`, `cli/main.py` (`universe --save` / `--db`)

Persistence, deliberately minimal: stdlib `sqlite3` + JSON metadata, two tables
(`nodes`, `edges`) with indexes, **no external dependency, no graph DB, no
vector extension**. It delivers "build once, query later":

- `universe --repograph-dot … --save universe.db` persists the built universe.
- `universe --db universe.db --dependents-of glibc` queries it again without
  rebuilding. One-hop text queries (`--dependents-of` / `--dependencies-of`) run
  in SQL via `sql_dependents` / `sql_dependencies` **without loading the whole
  graph**; paths/rendering load it whole (`load_graph`).

A heavier backend (Postgres recursive CTEs, a real graph store) or a similarity
overlay (`sqlite-vec`/vector) is left to the bigger-system plan in `plan.md` -
this stays a single small module so the low-footprint path keeps working with
zero dependencies.

---

## D21 - Full cpio file lists (any file is identifiable)

**Files:** `albs_graph/adapters/rpm_payload.py`, `provenance/identify.py`

Rung-4 payload analysis now records the **full file list** of each RPM (not just
ELF objects) on the binary RPM node under `files`, captured in the same single
decompress pass (`payload_contents` returns both ELF info and all paths).
`identify` then resolves ownership from these stored lists first, so any file -
configs, docs, anything - is traceable offline from graph data, no host
`rpm -qf` needed. File lists can be large, so they are populated only when
payload analysis runs.

---

## D22 - Errata/CVE ingest wired into coverage (`security_context` axis)

**Files:** `albs_graph/adapters/errata.py` (existing), `cli/main.py`
(`coverage --errata`)

`security_context_complete` needs an SBOM **and** an errata/CVE link. The errata
adapter existed but was never exposed; `coverage --errata FILE [--errata-subject
RPM]` now attaches an errata (with its CVEs via `FIXES` edges) to a subject, so a
package with both an SBOM and errata reaches `security_context_complete` and the
axis moves off 0.00. Errata is ingested from a provided JSON file (parallel to
`--sbom`); a live errata.almalinux.org fetch is left as future work.

---

## D23 - CPE verification + distro-backport flag (`identity` axis)

**Files:** `albs_graph/security/cpe.py`, `cli/main.py` (`coverage --verify-cpe`)

Closes the standing rule that the graph must not assert an official CPE without
verification. `verify_graph_cpe` matches each binary's `cpe_candidates` (product)
against a supplied CPE dictionary (`(vendor, product)` pairs from NVD cpe:2.3
strings): a single matching vendor flips the candidate to `verified=True` and
sets `cpe`; multiple vendors are recorded as `ambiguous_vendor` and deliberately
**not** asserted. Only verified CPEs count toward the `identity` axis.

It also flags `distro_backport=true` for AlmaLinux releases (`.elN`), because the
upstream version in the CPE (e.g. `1.20.1`) is shipped with backported patches -
so naive version-vs-CVE matching is misleading. That flag feeds the
vulnerability-applicability report.

The dictionary is supplied (`--verify-cpe FILE`), so verification is offline and
testable; pointing it at a real NVD CPE export is a drop-in.

---

## D24 - Vulnerability-applicability report (the consumer payoff)

**Files:** `albs_graph/provenance/vuln.py`, `cli/main.py` (`vuln`)

The deliverable the graph exists to produce, tying three layers together
per package: the CVEs a build **addresses** (rpm -FIXES-> errata -FIXES-> cve,
from A2), the **identity confidence** (verified CPE vs candidate, from A1) with a
**distro-backport** caveat (`version_match_reliable=false` when patched), and the
**linkage reachability** (`dlopen` = runtime-loaded code, static-object count,
from rung 4).

It deliberately does *not* invent CVE data - without a CVE feed it reports the
CVEs already linked via errata and frames how reliable a naive version match
would be. CLI: `vuln --build-id … [--verify-cpe FILE] [--errata FILE]
[--with-rpm-payloads] [--package P] [--arch A] [--only-with-cves]`.

This completes the recommended `B1 -> A2 -> A1 -> F` sequence from
`next_goals_options.md`.

---

## D25 - CVE-feed matching + rpmvercmp version comparison

**Files:** `albs_graph/security/cve_feed.py`, `provenance/vuln.py`,
`cli/main.py` (`vuln --cve-feed`)

Turns "CVEs addressed" into "CVEs potentially applicable". A supplied CVE feed
lists, per CVE, affected `(vendor, product)` configs with optional
`introduced` (>=) / `fixed` (<) bounds (mirroring NVD versionStartIncluding /
versionEndExcluding). `vulnerability_report(..., cve_feed=...)` parses each
package's *verified* CPE into `(vendor, product, version)`, matches it against
the feed, and reports matches **not already addressed by an errata** as
`potentially_affected_cves`.

Range evaluation uses an **rpmvercmp-style** `version_compare` (segment rules
RPM/DNF use: numeric runs compared numerically, alpha lexically, numeric
outranks alpha, `~` is a pre-release marker), so `1.2.11 > 1.2.3` and
`1.0~rc1 < 1.0` are correct - not string comparison.

The **distro-backport caveat** (A1) is carried through: a backported `.elN`
package keeps its upstream version, so a range match may be a false positive
(fix backported without a version bump); the report flags it ("backport:
verify") rather than asserting applicability. The feed is supplied (offline,
testable); a live NVD/OSV feed is a drop-in. No CVE data is invented.

---

## D26 - Semantic version comparison in the reconciler (B2)

**Files:** `albs_graph/vercmp.py` (moved here, neutral), `provenance/reconcile.py`

The rpmvercmp `version_compare` (D25) now powers the reconciler, not just CVE
matching - so it lives in a dependency-free `albs_graph/vercmp.py` that both the
security and provenance layers import (no odd cross-layer dependency).

- **`VERSION_DRIFT` is now semantic.** Concrete versions are grouped into
  rpmvercmp equivalence classes; `1.01` and `1.1` no longer count as drift, while
  `1.2.11` vs `1.2.3` still does. CONSENSUS likewise uses semantic equality.
- **`RANGE_VIOLATION` now fires on declared constraints.** A declared relational
  requirement (`name >= 3.2`, parsed from a claim's `requested`) checked against a
  concrete version in the same group fires `RANGE_VIOLATION` when unmet - so the
  AlmaLinux backport case (`require >= 3.2`, shipped `3.0.7`) is detected in the
  graph, not only flagged in the vuln report. Conservative by design: only
  relational operators (`=` provides/config are skipped), epochs stripped, and
  it never fires without a concrete version to test.

---

## D27 - RPM GPG signature verification (real provenance verification)

**Files:** `albs_graph/adapters/rpmsig.py`, `cli/main.py`
(`coverage --verify-signatures`)

With CAS gone (D11), this is the verification story. `verify_graph_signatures`
downloads each selected binary RPM and runs `rpmkeys --checksig` against the
host's AlmaLinux GPG keyring, moving a signature from "present" to
"cryptographically verified". Only a successful check flips `signature_verified`
on the RPM node and `externally_verified` on its signature node(s); `NOKEY` /
failed leave it unverified.

Opt-in and crash-proof, exactly like the CAS adapter: absent `rpmkeys` returns
`available=false` (and skips the downloads entirely) rather than raising. The
command runner and RPM fetcher are injectable, so parsing and graph-mutation are
tested offline without the binary or network. Like CAS, this is reported
separately and does **not** change the presence-based `provenance` axis -
verification is a distinct quality the report surfaces.

---

## D28 - Python import -> distribution mapping (B3)

**Files:** `albs_graph/adapters/pylang.py`, `cli/main.py` (`coverage --imports`)

The module you `import` is often not the distribution you install
(`cv2` -> `opencv-python`, `PIL` -> `pillow`). `module_to_package` applies a
built-in common map plus an optional supplied override (`--module-map FILE`), so
import-scan claims (`python_import`) carry the real PyPI package while keeping
the original module in `raw`. `coverage --imports FILE` scans a Python source
file's top-level imports and attaches the mapped claims. Best-effort by design;
unknown modules pass through unchanged.

---

## D29 - Go static BOM from `.go.buildinfo` (C1)

**Files:** `albs_graph/adapters/elf.py`, `adapters/rpm_payload.py`

Completes rung 4's static story for Go. The ELF parser now reads the
`.go.buildinfo` section (Go 1.18+ inline format: 32-byte header, uvarint-prefixed
version + module-info strings, 16-byte sentinels stripped) and extracts the
embedded `mod` / `dep` module list. `go_static_claims` turns those into Go
dependency claims (`evidence="go_buildinfo"`, `linkage=STATIC`,
`resolution_state=RESOLVED`), so a statically linked Go binary now contributes a
real dependency BOM instead of just a "toolchain: go" flag.

Scope: the inline buildinfo format only (older pointer-based layouts are not
dereferenced); Rust has no comparable embedded module list, so it stays
toolchain-detected.

---

## D30 - SLSA / in-toto provenance export (F3)

**Files:** `albs_graph/provenance/slsa.py`, `cli/main.py` (`slsa`)

`slsa_provenance` renders a binary RPM's backbone (source -> git commit -> build
task -> artifact -> signature) as an in-toto **Statement v1** with a **SLSA
provenance v1** predicate - the standard supply-chain attestation format, so the
graph's provenance is consumable by SLSA-aware tooling. The subject digest uses
the artifact CAS hash (a sha256); `resolvedDependencies` records the git source
(`git+<repo>@<ref>` + `gitCommit`); and the D27 signature-verification status is
surfaced under run metadata. Only graph-present fields are emitted (nothing
fabricated). CLI: `slsa --build-id … --rpm <name> --arch <arch>`.

---

## D31 - License-compliance rollup (F2)

**Files:** `albs_graph/adapters/sbom.py` (capture licenses), `provenance/license.py`,
`cli/main.py` (`license`)

The SBOM ingest now captures each CycloneDX component's licenses (ids and
expressions) into the claim's raw payload. `license_report` rolls those up into a
per-license component count plus an explicit **unlicensed** bucket (components
with no license field are surfaced as unknown, not guessed) - the view a license
consumer needs. CLI: `license --sbom FILE [--sbom-subject RPM]`.

---

## D32 - Native language resolvers behind the contract (E1)

**Files:** `albs_graph/dependency/native_resolvers.py`, `cli/main.py` (`resolve`)

Real resolvers for the rung-5 contract, shelling out to the authoritative tool
rather than reimplementing resolution: `GoResolver` runs `go list -m all`,
`CargoResolver` runs `cargo metadata`. Each satisfies the `DependencyResolver`
protocol and returns a `ResolverResult` whose resolved specs carry concrete
versions, so `add_resolver_result` feeds them into the graph and they count
toward the resolution axis. `resolver_for(ecosystem)` returns the wired resolver
or falls back to `NullResolver`.

Like every native adapter: injectable runner (fully tested offline), and an
absent/failing tool yields an `UNRESOLVABLE` result rather than raising. CLI:
`resolve --ecosystem go --manifest go.mod [--build-id … --subject <rpm>]` runs
the tool and (with a build) attaches the resolved deps + reports the resolution
axis. pip/Maven/npm remain `NullResolver` until wired the same way.

---

## D33 - Verbose detail for the coverage report (`--verbose`)

**Files:** `cli/main.py` (`coverage`), `provenance/reconcile.py` (`resolution_details`)

The `coverage` summary lines ("RPM header enrichment: ...", "Reconciled
dependencies: N; conflicts: M") stay one-line by default; `--verbose` expands
them. `resolution_details(graph)` is a read-only listing of every reconciled
group (subject, coordinate, verdict, versions, evidence sources); verbose prints
the agreement breakdown plus each resolution grouped by subject, and lists
header/payload fetch failures. Detail prints with `markup=False` so soname and
evidence tokens in `[...]` are not swallowed as Rich markup (the same fix
hardened the pre-existing conflict listing). Capped at 40 rows to stay readable
on `--all-packages` runs. The two coverage-running example scripts (`example.sh`,
`example--almalinux-native.sh`) run verbose by default (`VERBOSE=0` for concise
output), threading the flag through their fetch/trust-path/coverage steps.

---

## D34 - Versioned package requires from the RPM header (rung 3)

**Files:** `adapters/rpm_remote.py`, `adapters/rpm_header.py`, `provenance/reconcile.py`

The rung-3 header we already range-fetch carries the full REQUIRE
name/flags/version, not just the DT_NEEDED sonames. `header_dependency_claims`
now also emits the package-kind requires (`evidence="rpm_header_requires"`): an
`=` require becomes a concrete `identity.version` (counts toward the resolution
axis as COMPATIBLE), a relational one (`>=`/`<=`) becomes a `requested`
constraint string (drives RANGE_VIOLATION), and a bare name is a name-only
declaration. These are the deps the el-N RPM itself declares -- no host repos,
no extra fetch. `_evidence_class` maps `rpm_header_requires` to the *declared*
class (the package's declared dependency contract), so it is the declaration
baseline for presence-gap detection rather than an artifact observation.
`classify_capability` now treats parenthesised non-soname capabilities
(`rtld(GNU_HASH)`) as synthetic rpm features, not packages.

Note: many RPMs (e.g. nginx-core) declare name-only requires, so the version
value appears only where the spec/auto-deps carry an EVR; the resolved provider
NEVRA still comes from the buildroot or the repo closure.

---

## D35 - Parse `dnf repograph` block-form dot edges

**Files:** `adapters/rpmgraph.py` (`parse_dot_edges`)

Modern `dnf repograph` (EL10) emits the Graphviz **block form**
`"A" -> { "B" "C" ... }` spanning lines, not pairwise `"A" -> "B";`. The old
single-regex parser captured only `A -> {` (taking `{` as the destination) and
missed every real target, so a whole-repo universe collapsed to ~one edge per
node and `dependents_of` returned nothing (and `coverage --repograph` claims
were bogus). `parse_dot_edges` now runs two disjoint passes: a block pass that
expands each token inside `-> { ... }` into an `A -> token` edge, and a simple
pass for `A -> B` (whose destination can never be `{`). Node colour attributes
(`"389-ds-base" [color="0.89 1.0"]`) are ignored because they are not edges.
Verified live: an el10 appstream universe now connects 3000+ packages and
`--dependents-of perl-libs` returns its real dependents.

---

## D36 - Per-source attribution for multi-source (batch) builds

**Files:** `adapters/albs.py` (`_graph_from_albs_api_build`, `_source_package_name`)

An ALBS build can bundle many source packages (build 57810: 91 SRPMs across 12
sources). The adapter modelled a single build-level `source_package` (from the
first/representative SRPM), so every binary RPM's trust path resolved to that
one source -- e.g. `nginx-core` traced to `nghttp2`. Now each task gets its own
source chain (`source_package -> git_repository -> git_commit`) derived from the
task's own `ref` + SRPM, and the task's CAS attestation links to that per-task
commit. The package name stays SRPM-authoritative (the git ref/url can be a
non-authoritative mirror, per `_package_from_build_metadata`).
`source_to_artifact_path` already walks the binary's own task->cas->commit->
source edges, so `identify`/`trust-path` now report the correct source per
binary. Ref-less / single-package builds (e.g. 17812) fall back to the
build-level source, so they are unchanged.

---

## D37 - Live-repo URL candidates for current builds

**Files:** `adapters/rpm_remote.py` (`vault_candidate_urls`)

The range-read rungs (3/4) and GPG signature verification reconstruct public
download URLs from a RPM's NEVRA. Only **vault** paths were generated, so a
*current* build -- whose RPMs are still on the live mirror, not archived --
returned 404 (e.g. el10_2 `nginx-core` fetched 0 headers). The resolver now
offers both layouts per repository, interleaved live-then-vault:
`.../almalinux/<ver>/<repo>/<arch>/os/Packages/<file>` (current point release)
and `.../vault/<ver>/...` (archived). The reader tries each until one serves
bytes, so headers/payloads/signatures work for current and EOL builds alike.
Verified out-of-band: the el10_2 live URL returns HTTP 206 to a range request
where the vault path 404s/redirects.

---

## D38 - Most-depended-upon leaderboard in the universe summary

**Files:** `provenance/universe.py` (`most_depended_upon`), `cli/main.py` (universe)

Building a 10k-edge repo universe but printing only "N nodes, M edges" buried
the insight. `most_depended_upon(graph, n)` counts each package's direct
dependents (distinct requires edges = its blast radius), and the `universe`
summary now lists the top-N -- the repo's foundational packages (e.g. for el10
AppStream, `perl-libs` leads). The grand tour traverses both directions for the
top package (dependents = impact, dependencies = needs), so the universe step
shows real analysis instead of a single flat list.

---

## D39 - External code-review fixes (P1-P3)

A second-agent review found six real issues; all fixed with regression tests.

- **Cache build_id guard** (`adapters/albs.py`): `fetch_build_metadata` reuses a
  fresh cache only when its `id` matches the requested build, so a reused cache
  path can no longer silently return another build's graph.
- **Version-aware corroboration edges** (`provenance/reconcile.py`):
  `_link_claims` uses `version_compare` (rpmvercmp), not string `==`, so
  semantically equal versions (1.01/1.1) corroborate instead of getting a false
  `VERSION_DRIFT` edge that contradicted the CONSENSUS verdict.
- **Soname resolution count** (`adapters/dnf.py`): reports unique resolved
  sonames, not per-claim occurrences (no more "12/6").
- **SQLite capability lookup** (`store.py`): the `cap:` LIKE gained a trailing
  wildcard, so a partial soname (`libssl`) matches `cap:rpm:libssl.so.3`,
  mirroring the in-memory substring matcher.
- **Independent `--imports-subject`** (`cli/main.py`): Python import evidence is
  no longer attached via `--requirements-subject`; imports can target their own
  RPM.
- **Cargo skips workspace/root crates** (`dependency/native_resolvers.py`):
  `cargo metadata` lists the local crate(s); its `workspace_members` are now
  excluded from the resolved deps. The resolver-contract docstring distinguishes
  request-matching from discovery resolvers (Go/Cargo legitimately return
  `unresolved=()` on success).

---

## D40 - Demo shows only determinable data; consolidated on build 57810

A short-lived earlier iteration shipped `examples/nginx-core.cyclonedx.json` - an
illustrative CycloneDX SBOM with plausible-but-invented versions - so the demo's
license rollup (the `license` command requires `--sbom`) would run. That was
fabricated data: the versions did not come from build 57810, so the reconciler
emitted synthetic `version_drift` conflicts that taught a reader nothing real.

Decision: the demo must show only what the tool can actually determine under
public access today. AlmaLinux's real SBOMs live in immudb and need the
`alma-sbom`/immudb tooling plus credentials (no documented anonymous read path),
and the RPM header carries no machine-readable license rollup - so a license
rollup is **not** currently determinable without a supplied SBOM. Therefore:

- removed `examples/nginx-core.cyclonedx.json`;
- removed the license step from `example--full.sh` and dropped the SBOM
  injection from its coverage step;
- the `license` command itself stays (it works on a real supplied SBOM, e.g.
  the output of `alma-sbom --file-format cyclonedx-json build --build-id 57810`);
  the README documents it with a generic `--sbom FILE`, not a shipped fake.

Also consolidated the README onto build 57810 (AlmaLinux 10) - the 17812
(AlmaLinux 9) walkthrough is de-referenced so a single build is shown end to
end; the 17812 example files stay on disk but are no longer in the README. No
code change; test count unchanged.

---

## D41 - Real licenses from the RPM header + dnf; real `alma-sbom` SBOM

D40 dropped the fabricated SBOM. The follow-up question was whether a *real*
license rollup is reachable. Findings (verified on an el10 host):

- AlmaLinux's [`alma-sbom`](https://github.com/AlmaLinux/alma-sbom) installs
  (`pipx --system-site-packages`) and generates a real CycloneDX **build** SBOM
  **anonymously** - immudb_wrapper ships default read credentials, no API key
  needed. This corrects D40's assumption (and the limitations note) that there is
  "no anonymous read path". The SBOM has 457 components with real PURLs, CPEs,
  SHA-256 hashes and ALBS build properties.
- But those components carry **no license field** (build SBOM: 0 licensed;
  `package` SBOM: 0 components), so an SBOM license rollup is empty. The license
  that *is* determinable lives in the RPM `License:` header tag.

So licenses now come from RPM evidence, not the SBOM:

- `rpm_header.py` parses `RPMTAG_LICENSE` (1014); `enrich_graph_with_rpm_headers`
  records it on the binary-RPM node (`rpm_license`) and in its result, at no
  extra cost (the header is already range-read for the sonames). `coverage`
  prints `RPM license (from header): nginx-core=BSD-2-Clause`.
- `dnf.package_licenses` runs `dnf repoquery --qf '%{name}\t%{license}'`;
  `license --rpm-licenses` rolls up a subject + its resolved runtime deps into a
  real multi-package rollup (nginx-core: 7 packages, 6 distinct licenses) - no
  SBOM required. `RpmLicenseRollup` (pure data, in `provenance/license.py`) keeps
  the layering rule (provenance imports no adapters; the CLI orchestrates).
- The real `alma-sbom` build SBOM is committed at
  `examples/build-57810.cyclonedx.json` and ingested by the demo via
  `import-sbom` (433 package nodes) for its provenance data. Importing a real
  multi-arch SBOM exposed a latent bug: the component node id dropped the arch,
  so arch variants of one NEVR collided. `sbom.py` now keeps the arch in the id
  (arch-variant RPMs are distinct artifacts) and dedupes exact repeats (a noarch
  built per arch task), so multi-arch SBOMs import cleanly.

`alma-sbom` is documented as an optional tool. Tests +5 (header license, header
enrichment license capture, `package_licenses` x2, `RpmLicenseRollup`, multi-arch
import); suite now 178.

---

## D42 - The build SBOM enriches every report (vendor CPEs -> identity 1.00)

D41 ingested the real `alma-sbom` SBOM only via `import-sbom` (a standalone
graph). But its components carry per-RPM **CPEs, PURLs and SHA-256 hashes** that
describe the build's *own* binary RPMs, so it should enrich them in place rather
than sit beside them.

`enrich_graph_with_build_sbom` (`adapters/sbom.py`) matches each component to its
binary-RPM node by `(name, arch)` and attaches: a `described_by` edge to the
SBOM, the component PURL/SHA-256, and - the big lever - the vendor-asserted CPE
into the node's `security_identity` (`cpe_source="almalinux_sbom"`, a verified
candidate). It never overrides a node that already has a CPE (e.g. an NVD match),
so it only fills gaps. Wired as `--build-sbom FILE` on `coverage`, `vuln`,
`trust-path` and `identify`; the build SBOM is applied to the whole build (no
selector) because the `identity` axis is measured across all binaries.

Effect on build 57810: `identity` moves **0.00 -> 1.00** (456/456 vendor CPEs
from 457 components), the trust path's `has_sbom` flips **missing -> ok**, and
the `vuln` report's identities go **candidate_only -> vendor_asserted** (a status
distinct from NVD `verified`; see D46). This is honest: the CPE comes from
AlmaLinux's own published SBOM, labelled vendor-asserted and kept distinct from
an NVD dictionary verification. `security_context` stays 0.00 because it still
requires errata in addition to the SBOM.

On the strict PURL/CPE stance: asserting a CPE from the *vendor's own* SBOM is
not the forbidden case (guessing an official match without evidence) - the
vendor is the authority for its artifact's CPE; the `cpe_source` label keeps the
provenance of the assertion explicit. Tests +2 (vendor CPE moves the identity
axis; wrong-arch / pre-existing-CPE skip); suite now 180.

---

## D43 - A readable middle-zoom build graph (`trust-path --whole-source`)

The full build graph for a 13-source batch is 1613 nodes / 3.2 MB - real, but
unreadable when embedded and too heavy to show inline; collapsing it in
`<details>` hid it. The gap was a zoom level between one RPM's trust path (~13
nodes) and the whole build (1613).

`source_build_subgraph` (`provenance/trust.py`) fills it: it unions the
`focused_trust_graph` of every binary RPM a source produced (optionally one
arch), so the shared backbone (source -> commit -> CAS -> build task -> SRPM)
appears once and fans out to all of that source's signed, released RPMs. Exposed
as `trust-path --whole-source`. For nginx at `x86_64` that is 72 nodes / 157 KB
(vs 1613 / 3.2 MB) - readable, and embedded inline in the README while the full
graph stays linked in `<details>`. The demo renders all three (trust path,
source fan-out, full build). Tests +1; suite now 181.

---

## D44 - Commit the `build_analysis` test fixture (build-17812.albs.json)

`pytest` on a clean checkout (the VPS) showed 10 failures; two distinct causes:

- **8 (test_trust, test_artifact_inventory): environment, not a bug.** The VPS
  working tree was missing *committed* files under `examples/live-build-17812/`
  (a concurrent checkout had deleted the tracked fixtures). `git checkout HEAD --`
  restored them; those tests read `build-17812.json`, which is committed.
- **2 (test_build_analysis): a real fragility.** Both read
  `examples/live-build-17812/build-17812.albs.json`, which was **gitignored**
  (`*.albs.json`). It only existed locally (left over from a demo fetch), so the
  suite passed on a dev box but failed on any clean clone / CI / the VPS - the
  tests silently depended on a non-committed file.

Fix: un-ignore that single file and commit it as the fixture (295 KB; build
17812 is finished and immutable, so its raw metadata never changes). No test
edit; every other `*.albs.json` cache stays gitignored. The full suite (181)
now passes from a clean checkout. Lesson reinforced: offline tests must read
only committed fixtures, never a locally-generated cache.

---

## D45 - Scope-boundary fixes from an external review (Phase 0 + F1)

A second-agent review flagged correctness risks at three scope boundaries
(batch-build vs source-package, vendor-assertion vs dictionary-verification,
name vs artifact identity). This batch lands the cheap correctness fixes plus
the one genuine silent-wrong-result bug; the rest are sequenced (see `plan.md`).

- **F1 - batch source over-attribution (the silent bug).** `artifacts_from_source`
  used unrestricted `graph.reachable`, so the build's representative source
  (`build.package`, e.g. `nghttp2` on 57810) reached *every* task's artifacts
  through the build-level aggregate node - making `trust-path --whole-source`
  wrong for that source. Reimplemented to attribute each artifact via its own
  `source_to_artifact_path` (the per-task chain, already correct since D36),
  never global reachability. The graph structure is untouched (safer than
  removing the aggregate edge); only the over-reaching consumer changed.
- **F2 - cache guard.** `fetch_build_metadata` trusted only `cached.get("id")`,
  but `parse_build_metadata` accepts `build_id` too, so a cache holding
  `{"build_id": 999}` with no `id` was treated as "idless fixture" and reused
  for any build. Now it checks `id` then `build_id`; only a cache with neither
  (a real synthetic/HTML fixture) is accepted without a match.
- **F7 - source edges independent of nodes.** In the per-task loop the
  `STORED_IN`/`POINTS_TO`/`AUTHENTICATED_BY` edges were added only inside the
  `if node not in graph.nodes` blocks, so a repo/commit shared across source
  nodes left the second source without its edge. New idempotent `_ensure_edge`
  (`add_edge` does not dedup) ensures each edge regardless of node creation.
- **F5 - honest license label.** `license --rpm-licenses` advertised "RPM header
  + dnf" but never fetched a header. It now range-reads the subject's header
  (rung 3, best-effort), so the subject license is genuinely from the header and
  the rollup's `source` reflects what was actually used (falls back to dnf, and
  says so, if the header read is unavailable).

Tests +4 (F2 x2, F1 multi-source attribution, F7 shared-repo); F5 verified via
the demo. Suite now 185. Still planned: split vendor-asserted vs NVD-verified
CPE (F4), NEVRA/PURL-exact SBOM + dnf/rpmgraph matching (F3, F8), per-source
checkout/evidence selector (F6).

---

## D46 - Vendor-asserted vs NVD-verified CPE (F4)

D42 set the SBOM's vendor CPE to `cpe_status="verified"`, which coverage and the
`vuln` report then treated identically to an NVD dictionary match - blurring two
different evidence strengths. They are now distinct:

- The SBOM path sets `cpe_status="vendor_asserted"` (AlmaLinux asserting its own
  artifact's CPE), not `verified` (a match confirmed against an external NVD
  dictionary). Both set `cpe` and both count toward the identity axis (an
  artifact *is* identified either way), so the axis number is unchanged.
- `vuln` derives `identity_verified` from `cpe_status == "verified"`, so a
  vendor-asserted CPE now shows as `vendor_asserted` in the Identity column, not
  `verified` - while staying usable for CVE-feed matching (it carries a real
  `cpe`).
- `coverage` gains `identity_strength(graph)`: the identity axis is broken down
  by status (`N NVD-verified, M vendor-asserted`), so a 1.00 axis no longer reads
  as all-NVD-grade.
- NVD still wins: `verify_security_identity` upgrades a candidate to `verified`
  on a dictionary match, and `--build-sbom` never overwrites an existing `cpe`,
  so a real NVD verification takes precedence over the vendor assertion.

Tests +2 (vendor CPE -> vendor_asserted + identity_strength; vuln distinguishes
the two). Suite now 186.

---

## D47 - Remaining scope-boundary fixes (F3, F6, F8)

### F3 - NEVRA-exact build-SBOM matching

`enrich_graph_with_build_sbom` indexed components by `(name, arch)` with
first-wins, ignoring version/release - so a merged graph or a duplicate component
set (two builds of one package at one arch, different versions) attached the
*first* same-name component's CPE/hash/PURL to every matching node. It now keys
by `(name, version-release, arch)` (version-release parsed symmetrically from the
PURL `@` part for both component and node). An unambiguous `(name, arch)` fallback
still matches when a node or component lacks a parseable version-release (minimal
nodes), but an ambiguous fallback is skipped rather than guessing. The
single-build demo is unchanged (one NEVRA per name+arch). Tests +1 (two versions
at one arch attach their own evidence).

### F6 - per-source checkout / source-evidence selector

`checkout-source` and `source-evidence` used the top-level
`AlbsBuildMetadata.source_repository`/`commit`, which describe only the batch's
representative source - so for build 57810 they only ever touched the first
source. Both now take `--package`; `source_ref_for_package` resolves that
package's own per-task repo+commit (same attribution as the graph builder) and
`dataclasses.replace` retargets the metadata. `source-evidence` still builds the
full-batch graph but attaches the source tree to the chosen package's source
node. Tests +1 (resolver maps each batch source to its own ref; unknown -> None).

### F8 - arch-scoped dnf + rpmgraph matching

Native resolution attached claims by package **name** only, which is fine for a
single selected arch but wrong for `--all-archs` / a repo union / multiple
versions:

- **rpmgraph** (`enrich_graph_with_rpmgraph`) indexed `name -> node` with
  `setdefault`, so only the first arch variant of a package received the
  dependency claims. A repograph dot is name-level (no arch), so the dependency
  applies to *every* arch variant - it now indexes `name -> [node ids]` and
  attaches to each.
- **dnf** (`enrich_graph_with_dnf` / `repoquery`) queried the bare `name`, so on
  a multi-arch graph every arch node inherited the host arch's resolution. The
  query is now scoped to the node's arch (`name.arch`), so each node resolves
  against its own architecture (verified on the el10 host: `nginx-core.x86_64`
  returns the same 6 runtime + 1 weak as the bare name, so the demo is
  unchanged). `src` is not a queryable binary arch and is left unscoped.

Tests +2 (rpmgraph attaches to all arch variants; dnf query is arch-scoped).
Suite now 190. This completes the external review's scope-boundary findings
(F1-F8).

---

## D48 - Distro-aware reconciliation + retarget the tour to el10 (57810)

The grand tour (`example--tour.sh`) still defaulted to `BUILD_ID=17812`
(AlmaLinux 9). Run on the el10 host, that resolves an el9 build's dependencies
against the host's el10 repos: `dnf` and soname resolution agree on el10
releases (glibc 2.39 el10, openssl-libs 3.5 el10, ...) and the reconciler
reported them as `consensus` *for an el9 build* - presenting host packages as
the build's own deps. Two changes:

- **Retarget (a).** `example--tour.sh` now defaults to `BUILD_ID=57810`
  (AlmaLinux 10), matching the el10 host so the tour resolves the build's own
  deps. `example--full.sh` already pinned 57810; only the tour had drifted.
- **Cross-distro honesty (b).** `reconcile_dependency_claims` now compares the
  subject build's distro generation (from the RPM release, e.g. `el9`) against
  each resolved dependency's (`el10`). Only the *generation* is compared, so
  `el9_2` vs `el9_4` (same distro, different minor) is not flagged. Agreement and
  build-context validity are kept on **separate axes** (see below): the verdict
  stays whatever the sources support (a cross-distro group is still honest
  `consensus`), and the mismatch is recorded as an orthogonal `ContextIssue`
  (`cross_distro`), alongside `distro_mismatch` / `subject_distro` /
  `dependency_distros` on the resolution node. It is deliberately *neither* a
  `ConflictKind` (the sources agree -- it must not inflate the conflict count)
  *nor* an `Agreement` value (it is not a weaker form of agreement). Coverage
  policy decides what it costs: `_resolution_axis` counts a `consensus`/
  `compatible` only when it carries no context issue, so an el9-on-el10 run
  reports those deps as unresolved rather than falsely resolved. The CLI surfaces
  it: a `cross-distro: N` suffix on the non-verbose "Reconciled dependencies"
  line, and a `(cross_distro: build elX, deps elY)` note per verbose claim.

The 57810 demo (el10 build, el10 host) has no mismatch, so its output - and the
committed README text-screenshot - is unchanged. But the el10 BaseOS/AppStream
repos have since consolidated to a single build per package, so the run now
shows 6 `consensus` + 8 `insufficient_evidence` and **0 conflicts** (was 3
`version_drift` when two builds each of glibc/openssl-libs/zlib-ng-compat
co-existed). The README and plan prose that explained "3 real conflicts" are
rewritten to match the screenshot and to introduce the cross-distro guard.

Why a separate axis, not a `CROSS_DISTRO` agreement verdict (the structural call):
`Agreement` answers only *do the sources agree on a version?* A dependency can be
perfectly version-consistent and still invalid for the subject's build context.
Folding context validity into the agreement enum conflates the two and forces
every consumer to special-case one value; modelling it as an orthogonal
`ContextIssue` keeps `Agreement` a clean four-value verdict and lets coverage (and
future policies) weigh the two axes independently.

Tests +4 (cross_distro recorded as a context issue, not a weaker agreement;
excluded from coverage; same-distro consensus carries no issue; a minor-version
difference is not flagged). Suite now 194.

---

## D49 - Central `RpmNevra` value object (architecture hardening, identity step 1)

From an external architecture review: NEVRA / name-version-release-arch-epoch and
dist-tag parsing was re-implemented in every module that touched an RPM
coordinate, and the copies had drifted. Concretely, before this change:

- **filename -> dict** was byte-identical in `adapters/albs.py` and
  `provenance/build_analysis.py`, and near-identical in `adapters/rpm_remote.py`;
- **NEVRA/capability token -> (name, version)** was duplicated in `adapters/dnf.py`
  (`parse_nevra`) and `adapters/rpmgraph.py` (`_parse_node_token`);
- **dist-tag extraction** existed three ways: `rpm_remote._distro_version_from_release`
  (major.minor), `reconcile._distro_tag` (generation only, added in D48), and a
  platform-name normaliser in `albs.py`.

Decision: a single leaf module `albs_graph/nevra.py` (stdlib-only, like
`vercmp.py`, so adapters and provenance can both import it without cycles) owns
RPM identity parsing:

- `RpmNevra` (frozen dataclass: name, epoch, version, release, arch) with
  `from_filename` (strict canonical NVRA, no epoch) and `from_token` (dnf/rpmgraph
  label or capability string -- drops `>=` tails, splits an embedded epoch), plus
  derived `version_release` / `evr` / `distro` / `distro_version`.
- module helpers `distro_generation` (`el9`/`el10`) and `distro_version`
  (`9`/`9.4`), and `rpm_metadata_from_filename` (the lenient legacy dict that
  reports arch even when the n-v-r split fails).

`dnf.parse_nevra`, `rpmgraph._parse_node_token`, `rpm_remote` (filename + distro),
`albs._rpm_metadata_from_filename` and `build_analysis._rpm_metadata_from_filename`
now delegate; the local copies, their `_ARCH_SUFFIXES` / `_DISTRO_TAG` regexes and
a now-unused `re` import are gone. Behaviour is byte-for-byte preserved (the
existing dnf / rpmgraph / build-analysis / artifact-inventory / metadata tests are
the guard), so the only observable change is less drift surface.

`SecurityIdentity` (`security/identity.py`) and the generic `PackageIdentity`
(`dependency/model.py`) already existed, so this step adds only the missing
`RpmNevra`. A composing `ArtifactIdentity` (NEVRA + PURL + node id, replacing the
hand-rolled construction in `albs._rpm_package_identity`) is the next identity
step. Tests +9 (`test_nevra.py`). Suite now 203.

---

## D50 - `ArtifactIdentity`: compose `RpmNevra` into the RPM PURL (identity step 2)

The ALBS adapter hand-rolled an RPM artifact's PURL (`quote` / `urlencode`), its
PURL qualifiers, its `version-release`, and the `PackageIdentity` in four inline
helpers (`_rpm_artifact_purl`, `_rpm_package_identity`, `_rpm_purl_version`,
`_rpm_purl_qualifiers`). The NEVRA (now an `RpmNevra`), the PURL and the
dependency coordinate could drift apart because nothing tied them together.

Decision: an `ArtifactIdentity` (in `dependency/model.py`, beside
`PackageIdentity`) composes an `RpmNevra` with its repo `namespace`, `distro` and
an `is_srpm` flag, and is the single place that renders the RPM PURL and the
`PackageIdentity`. It encodes the RPM conventions once: the epoch rides as a PURL
`epoch=` qualifier rather than in the version; a `.src.rpm` advertises `arch=src`;
qualifiers are sorted. `albs._rpm_artifact_purl` / `_rpm_package_identity` now
delegate through a single `_artifact_identity` bridge from the ALBS metadata dict,
and the four inline helpers plus the now-unused `quote` / `urlencode` / `Ecosystem`
imports are gone. The PURL strings are byte-identical (the `test_albs_metadata`
and `test_artifact_inventory` PURL assertions are the guard), so the only change
is that NEVRA/PURL/coordinate can no longer diverge.

The graph *node id* is deliberately left out of `ArtifactIdentity`: node ids are
ALBS-structural (built from the artifact id and filename, e.g.
`rpm:<artifact_id>:<filename>`), not a property of the packaging identity, so
forcing them through the value object would couple it to ALBS internals for no
gain. Tests +3 (binary PURL + `PackageIdentity`; src arch; epoch-as-qualifier).
Suite now 206.

---

## D51 - Rule-based reconciliation (architecture hardening)

From the same review: `reconcile.py` had become a policy hub. A single
`_evaluate_group` decided version drift, declared-range violations, linkage
mismatches and artifact-presence gaps, and the loop bolted cross-distro context
on top. Every new policy was another branch in a growing monolith.

Decision: factor each policy into an independent `ReconciliationRule` in a new
`provenance/reconcile_rules.py`. A rule inspects a precomputed `ResolutionGroup`
(plain fields -- versions, version classes, linkages, evidence flags, distros) and
emits a `RuleFinding` (conflict kinds and/or context issues). The combiner
`evaluate_group(group, rules=DEFAULT_RULES)` folds the findings plus the
version-agreement question (CONSENSUS / COMPATIBLE / INSUFFICIENT_EVIDENCE) into
one `EvaluationResult`. The five rules are `VersionDrift`, `RangeViolation`,
`LinkageMismatch`, `PresenceUndeclared` and `CrossDistro`; `DEFAULT_RULES` is the
ordered registry (order preserves the historical conflict precedence, so the
reported `DependencyConflict.kind` is unchanged), and a caller can pass a custom
rule tuple.

The reconciliation vocabulary (`Agreement`, `ConflictKind`, `ContextIssue`) moved
into `reconcile_rules` because the rules and combiner need it and `reconcile`
importing them back would cycle; `reconcile` re-exports them (and keeps `__all__`)
so `from ...reconcile import Agreement` and the package API are unchanged.
`reconcile.py` keeps orchestration only: grouping claims, a `_build_group`
fact-gatherer, writing the resolution node, `_link_claims`, and the report. The
rule API (`ReconciliationRule`, `ResolutionGroup`, `RuleFinding`, `evaluate_group`,
`DEFAULT_RULES`) is exported from `albs_graph.provenance` so a new policy is a new
rule object, not a new branch.

Behaviour is preserved -- the existing reconcile/coverage tests (consensus, drift,
range, linkage, presence, cross-distro) all pass unchanged. Tests +6
(`test_reconcile_rules.py`: each rule fires only on its condition; the default
five; conflict wins and keeps rule order; context issue is orthogonal to the
verdict; rules are pluggable; insufficient-evidence default). Suite now 212.

---

## D52 - Indexed `ProvenanceGraph` (architecture hardening)

From the review: `graph.py` stored nodes as a dict and edges as a flat list, so
the hot read paths rescanned everything. `outgoing` / `incoming` filtered the
whole edge list, `find_by_type` walked every node, and `reachable` /
`neighborhood` rebuilt an adjacency map on every call -- O(E) or O(N) per query,
which does not scale past demo graphs.

Decision: maintain three insertion-ordered indexes, updated in `add_node` /
`add_edge`: `_outgoing` and `_incoming` (`dict[str, list[Edge]]`) and
`_nodes_by_type` (`dict[str, list[Node]]`). `outgoing` / `incoming` /
`find_by_type` now read the relevant index (returning a fresh copy so callers
can't corrupt it), and `reachable` / `neighborhood` traverse via the adjacency
indexes instead of rebuilding. Because the indexes preserve insertion order, all
query results are byte-for-byte identical to the old linear scans -- the full
existing suite (trust paths, reachability, every adapter that iterates
`find_by_type`) is the guard.

Consistency is safe because every mutation already goes through `add_node` /
`add_edge` (verified: nothing else assigns `.nodes[...]` or appends to `.edges`),
and the common in-place `node.metadata.update(...)` keeps the same `Node` object
the index points at. `add_node` only indexes a genuinely new id, so re-adding an
equal node (the idempotent path) does not duplicate it. Tests +4
(`test_graph_model`: ordered + idempotent `find_by_type`; fresh-copy result;
`outgoing`/`incoming` order + relation filter + copy; `reachable` follows
out-edges only). Suite now 216.

---

## D53 - First-class build/task model (`BuildTaskRef` / `BuildSourceRef`)

From the review: parsed ALBS metadata leaned on a *representative* source
(`AlbsBuildMetadata.source_repository` / `commit`) plus targeted re-derivation.
The per-task source attribution -- SRPM filename > git ref > repo url > build
package -- was re-implemented in two places: `source_ref_for_package` (the F6
per-source selector) and the graph builder's task loop, each re-parsing
`build.raw["tasks"]` on its own.

Decision: parse it once into typed collections. `BuildTaskRef` is the per-task
view (task id, arch, resolved `source_package` / `source_repo` / `source_commit`
/ `source_cas_hash`, distro, plus `raw` / `ref` for the long tail);
`build_task_refs(build)` produces them. `BuildSourceRef` aggregates a source
package's tasks (repo/commit from the first task, accumulated arches + task ids);
`build_source_refs(build)` produces the by-package map. `source_ref_for_package`
is now a one-line lookup in that map, and the graph builder iterates
`build_task_refs` and reads `task.source_package` / `.source_repo` / `.source_commit`
-- its node-building body is unchanged (the loop locals are sourced from the typed
ref, with `raw` / `ref` covering the remaining fields), so the graph is
byte-for-byte identical. The fixture tests (trust path, artifact inventory, build
analysis, metadata) are the guard.

Node ids stay ALBS-structural (artifact id / filename), not derived from the typed
ref. Tests +2 (`build_task_refs` exposes typed per-task source incl. distro;
`build_source_refs` groups tasks by package with accumulated arches/task ids).
Suite now 218.

---

## D54 - Docs pruning: current gaps only, point-in-time vs current-state counts

From the review's last item: some docs still read as partially historical after
the F1-F8 fixes and the architecture refactors. Pruned to match reality:

- **plan.md roadmap.** Item 1's "remaining follow-up: extract CPE into identity
  candidates" is done (a build SBOM's vendor CPE and NVD `--verify-cpe` both move
  the `identity` axis off 0.00), and item 6's "CPE verification adapter" is
  implemented (NVD dictionary match flips `verified`; ambiguous vendors stay
  uncounted; the AlmaLinux backport case is a `RANGE_VIOLATION`). Both are now
  marked done, with only the genuine residue (the dictionary is supplied, not
  fetched) left as remaining.
- **limitations.md is current gaps only.** The "`--whatprovides` is not auto-wired
  into reconciliation" caveat contradicted the "Soname → package resolution
  (implemented)" section three paragraphs below it -- `coverage --resolve-sonames`
  wires exactly that -- so it is corrected. The "Process note: branch history"
  section (a one-time note about an old two-commit history) was removed: it is not
  a current gap.
- **Test-count convention made explicit.** `scripts/check-test-count.sh` now
  documents that a bare "N tests" figure is a current-state claim (cross-checked
  against `pytest --collect-only`), whereas decisions.md's "Suite now N" lines are
  point-in-time records of the count when each decision landed and are
  deliberately *not* cross-checked. A general automated check for stale prose
  "done/remaining" claims is not cleanly feasible; the most drift-prone figure
  (the current-state test count) is hook-guarded, the rest is review.

Docs/comment only; no code or test change (suite unchanged at 218).

---

## D55 - Evidence patches via a recording graph (architecture hardening)

From the review: adapters mutate the graph in place, so there is no first-class
"what this adapter would add" object -- hard to test, cache, diff, dry-run, or
answer "why did the graph change?". Introduce `EvidencePatch(nodes, edges,
metadata_updates, warnings)` (`model/patch.py`) with `apply` / `merge` /
`summary` / `is_empty`.

Approach: a **recorder**, chosen over "every adapter returns a patch" after a
code audit showed the writes are entangled -- a shared `add_dependency_claim`
helper (6 adapters), direct `add_node`/`add_edge` (5 adapters), and in-place
`node.metadata` mutation (8 adapters). Rewriting every adapter + the shared
helper + all call sites would be large and risky; the recorder delivers the same
capability for *all* adapters with no adapter-signature changes:

- `RecordingGraph` subclasses `ProvenanceGraph` and **shares** the wrapped
  graph's state (nodes, edges, indexes are the same objects), so reads see the
  live graph and writes mutate it exactly as before, while each write path also
  appends to `patch`. `capture_patch(graph, fn, apply=...)` runs an adapter
  against a recorder: `apply=True` records while mutating, `apply=False` is a dry
  run against `graph.copy()` (a deep-enough copy with fresh metadata dicts), so
  the original is untouched and you get just the patch.
- `ProvenanceGraph.update_metadata(node_id, updates)` is now the one in-place
  metadata-merge method; the 8 adapters that poked `node.metadata` directly route
  through it (so the recorder captures metadata enrichment too). `sbom`'s nested
  CPE mutator became `_sbom_cpe_identity` (returns a fresh `security_identity`
  dict) so vendor-CPE enrichment is recordable. Behaviour is byte-for-byte
  preserved (the adapter tests guard each conversion).

Adapters still default to mutating a real graph -- the recorder is opt-in. Residue:
no adapter emits warnings yet (the `warnings` field + `RecordingGraph.warn` exist
for future use). Tests +6 (`test_patch`: record + apply; dry run leaves the
original untouched; apply mutates + records; merge/is_empty; `update_metadata`
rejects unknown nodes; a real dnf adapter patch captured via a dry run). Suite
now 224.

---

## D56 - Identity-mismatch reconciliation rule (extending D51)

`ConflictKind.IDENTITY_MISMATCH` existed but nothing emitted it (a documented gap
in limitations.md: "the enum exists ... but nothing emits it yet"). The rule
engine from D51 makes adding a sound detector a small, isolated change rather
than another branch in a monolith -- which is the point of having made
reconciliation rule-based.

Decision: add `IdentityMismatchRule` to `DEFAULT_RULES` (right after
`VersionDriftRule`, since both are "what/which" conflicts). It fires when two or
more claims in a group assert the **same concrete version** with **different PURL
coordinates** -- two sources agreeing on the version but disagreeing on what the
dependency actually is. It is deliberately conservative: it groups PURLs by
version (so a genuine version disagreement is left to `VersionDriftRule`, not
double-reported) and only fires when at least two claims carry a PURL, so the
common single-PURL group is never flagged. Verified against the whole suite: the
rule did not fire on any existing fixture (the only change was updating the
rule-list assertion), so no contrived conflicts -- it lights up only on a real
cross-source identity disagreement.

Caveat (recorded in limitations.md): PURLs are compared as raw strings, so a
purely cosmetic difference (qualifier ordering / encoding) is not normalized
away. Tests +3 (rule fires on same-version/different-PURL; stays silent without
two PURLs, on identical PURLs, and on a version drift; an integration case
through `reconcile_dependency_claims`). Suite now 227.

---

## D57 - Analysis pipeline extraction (architecture hardening; coverage first)

From the review's top item: `coverage` / `identify` / `trust-path` / `vuln` /
`license` each re-encoded the same flow inline -- load a graph, run a chosen
subset of enrichments in a fixed order, reconcile, render. Long, and (since the
CLI commands have almost no test coverage -- only `test_cli_help`) the *wiring*
was untested.

Decision: factor the orchestration into `albs_graph/pipeline.py`:

- `RunSpec` -- the resolved inputs for one run (which enrichments + options).
- `EnrichmentStep` (Protocol) + 13 step objects, each a thin wrapper over one
  `enrich_graph_with_*` / `attach_*` adapter call plus its guard. `DEFAULT_STEPS`
  is the registry in the **exact historical coverage order** (build_sbom before
  verify_cpe; everything else only adds claims the final reconcile groups), so
  behaviour is preserved; a caller can pass a custom subset.
- `AnalysisPipeline.run(spec, graph, *, on_progress=, dry_run=)` runs the
  applicable steps against a `RecordingGraph`, reconciles, and returns a
  `PipelineResult` (enriched graph, each step's result by name, the
  reconciliation, and the cumulative `EvidencePatch`). `dry_run=True` runs against
  `graph.copy()`, so the source graph is untouched -- a "what would this change?"
  run, the synthesis with D55.

Coverage migrated: `coverage_command` builds a `RunSpec`, runs the pipeline, and
aliases `result.result(name)` back to the existing render variables, so the
(unchanged) rendering block keeps working. The repograph dot resolution and its
console warning stay in the command (I/O + presentation, not enrichment).

Verification, given the thin CLI tests: a **golden-output check** -- `coverage`
on the synthetic fixture runs fully offline, and its `summary` and `json` output
is byte-for-byte identical before and after the migration. New pipeline unit
tests (5) cover the orchestration the CLI lacked: applicable-step running +
record + reconcile, dry-run isolation, non-applicable skipping, `DEFAULT_STEPS`
order, and per-step gating. `identify` / `trust-path` / `vuln` / `license` migrate
in follow-ups. Tests +5. Suite now 232.

---

## D58 - Close the tour's security-context axis (SBOM wired; trust-path --errata)

`example--tour.sh` ran `trust-path` / `coverage` / `vuln` with **no SBOM or errata
flag**, so the trust path reported `has_sbom` *and* `has_errata_link` missing --
which looked like a regression vs `example--full.sh`. It is not: the live ALBS
builder (`graph_from_build_metadata`) creates **no SBOM node** (it only records
`alma_commit_sbom_hash`/`sbom_api_ver` as CAS metadata), and `has_sbom` requires a
`DESCRIBED_BY` edge that only `--build-sbom` / `--sbom` / `import-sbom` (or the
synthetic fixture) create. `git show main:example--tour.sh` is identical here
(only `BUILD_ID` differs), and `main`'s builder has no SBOM node either -- the
tour reported the same on `main`. The SBOM you see in the README is from
`example--full.sh`, which passes `--build-sbom examples/build-57810.cyclonedx.json`.

Decision -- let the tour close the axis honestly:

- Wire the real committed build SBOM into the tour: `SBOM_FILE` (default
  `examples/build-<id>.cyclonedx.json`) is passed as `--build-sbom` to
  `trust-path` / `coverage` / `vuln` **when the file exists**, closing `has_sbom`
  and lifting identity to 1.00. Absent file -> no-op.
- Add `--errata` / `--errata-subject` to the **`trust-path`** command (parity with
  `vuln` / `coverage`, which already had them) so the trust path's
  `has_errata_link` can close; wire an optional `ERRATA_FILE` into the tour.
  **Nothing is fabricated** -- with no real errata file the link stays open (the
  default tour now shows only `has_errata_link` missing, not `has_sbom`).
- Portable empty-array idiom `${arr[@]+"${arr[@]}"}` in the tour, so it still runs
  under bash 3.2 (macOS) when the args are empty (plain `"${arr[@]}"` errors under
  `set -u` there; verified).

Tests +1 (`trust-path --errata` closes `has_errata_link`; the synthetic source
carries no SBOM, so `has_sbom` stays missing -- proving the flag closed errata
specifically). The `coverage` golden output is unchanged. Suite now 233.

---

## D59 - One comprehensive demo script; retire the per-facet scripts

Six example scripts had accreted - `example.sh` (portable), `example--tour.sh`
(grand tour), `example--verbose.sh` (build-intelligence), `example--almalinux.sh`
(CAS), `example--almalinux-native.sh` (native stack), `example--full.sh` (fullest)
- each a *partial* subset. A coverage audit showed even the tour exercised only 7
of 17 commands (no `license`, `import-sbom`, signatures, ...). The ask: one
comprehensive, extensive demo, not yet another partial.

Decision: `example--full.sh` is now THE single demo, covering all 17 commands plus
the `demo_verbose` build-intelligence view. Added to it: `source-evidence` +
`checkout-source` (git source + manifest discovery, gated on git), `resolve`
(language-native; opt-in `RESOLVE_ECOSYSTEM`+`RESOLVE_MANIFEST`, since an RPM build
carries no language manifest), `inspect-rpm` (opt-in `RPM_FILE`), the offline
`fixture`/`render-fixture`/`inspect-fixture` trio, the build-intelligence step
(`python3 -m albs_graph.cli.demo_verbose`: artifact matrix + build/signing/
processing timing), and the `--verify-cpe`/`--errata` flags (opt-in
`CPE_FILE`/`ERRATA_FILE`) alongside the existing `--verify-signatures`/`--use-cas`/
`--build-sbom`. Every step stays gated - a missing tool, file, or network skips,
never fails - and the portable empty-array idiom keeps it runnable under bash 3.2.

Removed `example.sh`, `example--tour.sh`, `example--verbose.sh`,
`example--almalinux.sh`, `example--almalinux-native.sh` (folded in or already
covered). The `demo_verbose` *module* is retained (full.sh calls it). This
supersedes the tour decisions (D48 retarget, D58 wiring) as a script; their *code*
features persist - notably `trust-path --errata` (D58) is now used by full.sh.

Consequence: the committed README text-screenshot and
`examples/demo-build-57810/console.txt` reflect the older nine-step run and must be
regenerated on the el10 VPS (`COLUMNS=200`; `COLUMNS=140` for the README splice)
now that the script has more steps. Docs updated (CLAUDE.md, AGENTS.md, plan.md,
README script sections). No test change - the scripts are not unit-tested; the
suite stays 233.

---

## D60 - First comprehensive VPS run: step-8 fix, repos re-drifted, screenshot refresh

The first full run of the consolidated `example--full.sh` on the el10 VPS exposed
two things.

1. **`example--full.sh` step 8 was wired wrong.** `checkout-source` takes the
   **source** package (`nginx`, not the binary `nginx-core`) plus a required
   `--dest`, and `source-evidence` takes the checked-out tree as a **positional
   `SOURCE_DIR`** (not `--build-id`). The run showed both erroring then skipping
   gracefully. Fixed: a `SRC_PACKAGE` env (default `nginx`), `checkout-source
   --package "$SRC_PACKAGE" --dest <dir>`, then `source-evidence <dir>
   --build-id ... --package "$SRC_PACKAGE"`. (Future: `checkout-source` could
   accept a binary name and resolve its source, removing the `SRC_PACKAGE` knob.)

2. **The el10 repos re-drifted to two `glibc` builds** (`2.39-121.el10_2.alma.1`
   and `2.39-124.el10_2.alma.1`). So the run now reports resolution **5/14**,
   **5 consensus + 1 `version_drift` conflict** (glibc) + 8 `insufficient_evidence`
   - not the single-build `0 conflicts` of the prior capture. This is the
   reconciler working correctly (it records both releases rather than picking
   one); the repos oscillate between one and two builds per package over time. The
   README prose is updated to match.

Everything else in the comprehensive run worked: trust path (has_sbom ok via the
build SBOM; has_errata_link still missing, no errata file), identify, coverage
(identity 1.00, signatures 1 verified), license rollup, vuln, whole-SBOM ingest
(433 nodes), SLSA, build-intelligence (artifact matrix + 90-row processing/signing
timing), SVG renders, the offline fixture trio, and the 4398-node/11720-edge
universe.

README text-screenshot refreshed to this 14-step run (hostname sanitized; the two
giant build-intelligence tables truncated with pointers to `console.txt`; step 8
shown as an editorial `[output omitted ...]` note since the capture predated the
fix - **nothing fabricated**). Still pending (need the el10 host): regenerate
`examples/demo-build-57810/console.txt` from a fresh post-fix run, and run `pytest`
on the VPS (the dev box has no SSH access to it from here). Suite unchanged at 233.

---

## D61 - Source-tree import/include scanning across languages

`source-evidence` already discovered the manifest *files* in a checked-out tree
(`go.mod`, `Cargo.toml`, `package.json`, `pyproject.toml`, `pom.xml`, Gradle).
It did not look at the source code itself. The remaining rung -- *what the code
says it imports* -- existed only for Python (`adapters/pylang.py:parse_imports`,
scoped to a single file). For Go/Rust/C/C++/JS/TS/Java/Ruby the project had no
equivalent.

Decision: new adapter `albs_graph/adapters/source_imports.py` -- a generalised
detector + per-language extractor + tree walker:

- **Detection** by extension (`.py`/`.go`/`.rs`/`.c`/`.h`/`.cpp`/`.js`/`.ts`/
  `.java`/`.rb` and variants), with a shebang fallback for extensionless
  scripts (`#!/usr/bin/env python|node|ruby`).
- **Per-language regex extractors**, each anchored at line start so a `//`
  comment cannot match:
  - Python -- reuses `pylang.parse_imports` for consistency (single source of
    truth for the Python stdlib filter).
  - Go -- bare `import "pkg"` *and* `import ( ... )` blocks; stdlib heuristic
    (first path segment carries no dot → stdlib).
  - Rust -- `use crate::...`/`pub use ...` and the older `extern crate name;`;
    filters `std`/`core`/`alloc` and the `self`/`super`/`crate` path keywords.
  - C/C++ -- both `<system>` and `"local"` `#include`s, recorded as
    `Ecosystem.GENERIC` evidence (C has no single package ecosystem).
  - JS/TS -- ES `import ... from "pkg"` *and* CommonJS `require("pkg")`; the
    mandatory `\s+` after `import` excludes the dynamic `import("...")` call
    form; npm-root reduction handles `@scope/pkg/sub` -> `@scope/pkg`; relative
    `./local` imports are skipped (project-internal).
  - Java -- `import [static] foo.bar.Baz;` with the `.*` wildcard stripped;
    filters `java.*`/`javax.*`/`jdk.*`/`sun.*`/`com.sun.*` JDK roots.
  - Ruby -- only `require '...'` (the `\s+` after `require` excludes
    `require_relative`); stdlib filter for the common ones.
- **Walker** prunes `.git`/`node_modules`/`vendor`/`target`/`build`/`dist`/...
  and dotted dirs in-place (never descends), and is bounded by `file_limit`
  (default 5000) so a huge tree cannot run away.
- **Claim emission** deduplicates per (language, import) so a module imported
  in every test is one claim, not hundreds. Each claim carries the
  language-appropriate `Ecosystem` (PYPI/GO/CARGO/NPM/MAVEN/GENERIC),
  `resolution_state=DECLARED`, and a `<language>_import` evidence tag, so the
  reconciler groups them alongside other adapters' claims.

CLI: `source-evidence` runs the scanner by default; `--no-scan-imports` opts
out. The scan attaches to `src:<source_package>` (the natural subject for "what
the source declares it needs").

Regex-based by design: fast, dependency-free, lossless for the common cases
(top-level statements at column zero). Deliberately does not chase nested
conditional imports or dynamic `__import__` -- the reconciler is fed real
evidence, not best-guess static analysis.

Tests +12 (extension + shebang detection; per-language extractor with stdlib
and project-internal filters; walker prunes ignored dirs; integration: a
mixed-language tree adds typed claims; missing-subject is a no-op). Suite now
245.

---

## D62 - Idempotent spec dep nodes (regression from the first real VPS run)

The first comprehensive `example--full.sh` run on the el10 VPS (after gaining
SSH access) ran step 8 against a real nginx `.spec`. `source-evidence` raised:

> `error: Conflicting node definition for dep:rpm:nginx(abi):runtime:nginx(abi)_=_%{nginx_abiversion}`

A real spec lists the same `Requires:` line across every subpackage block (in
the nginx case, `nginx-core` + every `nginx-mod-*` each declare
`Requires: nginx(abi) = %{nginx_abiversion}`). `_add_dependency_spec` was
unconditionally calling `graph.add_node`, which raises on a duplicate id.

Fix: make the dep-node add idempotent (`if node_id not in graph.nodes`). The dep
is one node; what multiplies is the *edge* from each declaring source file -
which is exactly the call's intent. The unexpanded `%{macro}` in the node id is
preserved verbatim (the spec parser sees raw text, no rpmbuild macro context);
that is a known caveat, not the regression.

Tests +1 (a spec listing the same `Requires:` twice + another duplicate must
not raise; the dep collapses to a single node). Suite now 246.

---

## D63 - Content-addressed HTTP cache + bounded concurrency for RPM fetches

Review item #8. Two adapters hit the network per RPM and neither cached:
`rpm_remote.py` (HeadersStep) Range-fetches the RPM header, trying up to three
mirror URLs sequentially per RPM (BaseOS -> vault -> AppStream); even the
single-RPM demo shows three 200/404 round-trips for one header. `rpm_payload.py`
(PayloadStep) downloads the full RPM payload (5-50 MB). Every run paid the same
network cost, and the per-RPM walks were strictly sequential -- `--all-archs` on
a 456-RPM build was linear in wall-time.

Decision: a stdlib-only, read-through disk cache + a worker pool around the
existing per-RPM loop.

- **`albs_graph/adapters/_http_cache.py`** -- `HttpCache.get_or_fetch(url, fetch,
  *, range_)`. Key = `sha256(url + ":" + range)`, bucketed by the first 2 chars.
  Only successful responses are cached: an inner-fetcher exception (today's
  cascade signal) propagates as-is, so the mirror cascade still self-heals when
  a vault URL becomes live. Atomic writes (tmp + rename) make a partial write
  impossible to read back. Cache root: `$ALBS_HTTP_CACHE` -> `$XDG_CACHE_HOME/
  albs-provenance-explorer` -> `~/.cache/albs-provenance-explorer`. Convenience
  wrappers `cached_range_fetcher` / `cached_full_fetcher` adapt to the existing
  `RangeFetcher` / `FullFetcher` Protocols.
- **`rpm_remote.py`** (HeadersStep) -- the default `fetch` is now wrapped in a
  cache (default-on; `--no-http-cache` opts out). The per-node work is gathered
  into a list and processed via `ThreadPoolExecutor` (default `max_workers=4`,
  user choice over 1/4/8/16); workers compute pure results, the main thread
  merges into the graph sequentially (no graph locking needed). An injected
  `fetch` (tests) is honoured verbatim -- the cache never touches test data.
- **`rpm_payload.py`** (PayloadStep) -- same pattern, but the cache is **opt-in**
  via `cache_payloads=True` (default False): payloads are 5-50 MB and a full
  `--all-archs` run could reach tens of GB. Same `max_workers=4` worker pool.
- **`RunSpec` + CLI** -- `max_concurrency: int = 4`, `http_cache: bool = True`,
  `cache_payloads: bool = False`. Exposed on `coverage` as `--max-concurrency`,
  `--http-cache/--no-http-cache`, `--cache-payloads`. Threaded through
  `HeadersStep`/`PayloadStep`.

Verification: the `coverage` golden output on the synthetic fixture is
byte-identical before and after (no network, cache untouched). Cache-module
tests cover miss-then-hit, range isolation, failure-not-cached, disabled
pass-through, atomic layout, both wrappers, and env-driven root resolution.
Existing rpm_remote/payload tests inject their own fetcher and `len(work) <= 1`
so the worker pool degrades to sequential -- behaviour preserved.

Deferred (planned next): `rpmsig.py` (`verify_graph_signatures`) downloads RPMs
for `rpmkeys --checksig`. It gets a free win when `cache_payloads=True` (same
URLs cached) but doesn't yet thread `HttpCache` explicitly. That follow-up
ships once VPS-verified.

Tests +8 (`test_http_cache.py`). Suite now 254.

VPS verification (`vps-ac97e687`, AlmaLinux 10.2, Python 3.12): `pytest` 254
passed. Cold-cache `coverage --with-rpm-headers` for nginx-core ran in **1230
ms**; warm run **740 ms** (-40% on a single RPM; the win scales linearly with
RPM count on multi-RPM / `--all-archs` runs). Output **byte-identical** cold
vs warm. Cache footprint **24 KB / 3 files** for one header (the cascade's
tail-probe + header-region range reads).

---

## D64 - rpmsig follow-up: share the cache with rpm_payload

D63 deferred `rpmsig.py` so we could verify the headers/payload caching on the
real VPS first. With that green, this lands the same pattern for the signature
adapter: `verify_graph_signatures` takes `cache_payloads` + `max_concurrency`,
wraps the default fetcher in :class:`HttpCache` when `cache_payloads=True`, and
parallelises the per-RPM `requests.get` + `rpmkeys --checksig` via the same
worker-pool / main-thread-merge pattern. `SignatureStep` threads
`ctx.spec.cache_payloads` + `ctx.spec.max_concurrency` through.

Key win: rpmsig and rpm_payload now **share the cache** (URL is the cache key).
A run with both `--with-rpm-payloads` and `--verify-signatures` enabled
downloads each RPM **once** -- the payload step's ELF analysis and the
signature step's `rpmkeys` invocation read the same bytes from disk.

Behaviour preserved: existing rpmsig tests inject `fetch_full` (cache untouched)
and use a single-RPM graph (`len(work) <= 1` -> sequential path). Suite stays
at 254. No CLI surface change (the `--cache-payloads` / `--max-concurrency` /
`--http-cache` flags from D63 already cover this).

---

## D65 - Dry-run isolation + EvidencePatch capture for CPE verification

Review item #1 (highest-severity). Two coupled correctness bugs:

1. **`ProvenanceGraph.copy()` was shallow** -- `dict(node.metadata)` made fresh
   top-level dicts but kept all nested values (e.g. `security_identity` and the
   candidate dicts inside its `cpe_candidates` list) **shared** with the source.
   So `AnalysisPipeline.run(spec, graph, dry_run=True)`, which runs against a
   copy, leaked any in-place nested mutation back into the source graph.
2. **`verify_graph_cpe` mutated `security_identity` (and its nested candidate
   dicts) in place**, bypassing `update_metadata`. `RecordingGraph` records
   `add_node` / `add_edge` / `update_metadata` writes -- so CPE verification
   never showed up in the `EvidencePatch`. A "patch" that misses the change is
   worse than no patch.

Reproduced (review): `verify_graph_cpe(graph.copy(), dictionary)` flipped the
original node's `cpe_status` from `candidate_only` to `verified`.

Fixes:

- **`ProvenanceGraph.copy()`** uses `copy.deepcopy(node.metadata)` (and the same
  for edge metadata). The docstring's "deep-enough copy" promise is now true.
  Cost: deep-copying small dicts is negligible; `copy()` is only used by
  `dry_run` paths.
- **`verify_graph_cpe`** works on a `deepcopy(original)` of the node's
  `security_identity`, then `graph.update_metadata(node.id, {"security_identity":
  identity})`. `verify_security_identity`'s contract (in-place mutation +
  returns status) is preserved -- the per-node copy isolates it. The final
  state rides through the mutation API so `RecordingGraph` captures it.

Both axes (dry-run safety, patch capture) are now testable in isolation. Tests
+2 (`test_verify_graph_cpe_on_a_copy_does_not_mutate_the_original`,
`test_verify_graph_cpe_changes_are_captured_in_the_evidence_patch`). Coverage
golden output on the synthetic fixture is byte-identical (CPE behaviour
unchanged for callers that don't dry-run / don't use RecordingGraph). Suite now
256.

Open: the same audit should follow for any other adapter that touches nested
metadata dicts in place. None known today, but the review's underlying lesson
is "adapters must mutate the graph only through its mutation API" -- a
convention worth a CLAUDE.md rule once one more example surfaces.

---

## D66 - HttpCache cannot store Range-ignoring 200 responses (bug #6)

Review item #6 (silent cache poisoning). `_requests_range_fetch` accepted both
HTTP 206 (the server honoured `Range:`) and HTTP 200 (the server ignored
`Range:` and returned the *full file*). The cache key, however, was the
`(url, start, end)` tuple. So a Range-ignoring server's full-file body got
stored under a tiny-range cache key and replayed forever -- every subsequent
"header" read for that URL replayed the wrong bytes (full RPM), and the RPM
parse on the next run would fail or be wrong with no obvious cause.

The fix lives at the **fetcher**, not in HttpCache: HttpCache is intentionally
HTTP-agnostic (it stores whatever its callable returns). `_requests_range_fetch`
now requires either 206, or 200 with `len(body) == end - start + 1`. Anything
else raises `RpmHeaderFetchError`, the same exception
`_try_candidates` already catches to advance to the next mirror; the cascade
self-heals and HttpCache never sees the bad body.

The 200-with-correct-length tolerance is deliberate: some intermediaries (a CDN
serving from cache) may legitimately return 200 with the exact requested slice;
if the byte count matches, the bytes are correct and cacheable.

Tests +1 (`test_requests_range_fetch_rejects_range_ignoring_200_so_httpcache_is_not_poisoned`):
`unittest.mock.patch` returns a fake 200 with full-RPM-sized content for a
small-range request; the call raises *and* the cache directory stays empty.
Suite now 257.

---

## D67 - Idempotent reconciliation (bug #2)

Review item #2. `reconcile_dependency_claims` was *rebuild-from-claims* but did
not clear the previous rebuild's output. Two failure modes:

- Two back-to-back runs duplicated every `OBSERVED_AS` / `CORROBORATES` /
  `CONFLICTS_WITH` edge (the same resolution node existed already, so its
  `add_node` was a no-op, but the edges from it were appended each time).
- Run, attach new conflicting evidence (changing the verdict), re-run:
  ``add_node`` on the resolution node raised ``Conflicting node definition for
  dep-res:...`` because the stored node now disagreed with the new verdict.

That broke any save-graph -> reload -> re-enrich workflow.

Fix: purge-and-rebuild. Added two minimal removal APIs to ``ProvenanceGraph`` --
``remove_node`` (drops the node + every incident edge, keeping the type and
adjacency indexes consistent) and ``remove_edges_where`` (predicate-based bulk
removal that rebuilds the adjacency from the kept edges). At the top of
``reconcile_dependency_claims``, ``_purge_prior_reconciliation`` drops every
``DEPENDENCY_RESOLUTION`` node and every ``CORROBORATES`` / ``CONFLICTS_WITH``
edge between claim pairs. Claim nodes themselves are preserved -- they are the
*inputs* to reconciliation, owned by the adapters that emitted them.

Tests +2: a second run leaves edge + resolution-node counts unchanged; a re-run
after a new conflicting claim flips a CONSENSUS to a CONFLICT/VERSION_DRIFT
without raising. Coverage golden byte-identical. Suite now 259.

(This is also the D62 pattern, scaled up: D62 made dep-spec node adds
idempotent; D67 makes the entire reconciler re-runnable.)

---

## D68 - Claim node ids key on context + PURL too (bug #3)

Review item #3. `claim_node_id` keyed on
`(subject, coordinate, evidence, version)`, but ``_group_key`` already keyed on
``context_key`` (arch / profile / distro / language_version / extras /
profiles / features). The mismatch was real: two claims for the same subject +
name + version + evidence but different ``DependencyContext`` (e.g.
``arch=x86_64`` vs ``arch=aarch64``) collided on the *id* even though the
reconciler would have put them in *separate groups*. ``add_dependency_claim``
raised ``Conflicting node definition`` for the second.

Fix: include the spec's ``_context_key`` *and* PURL (when set) in
``claim_node_id``, so the id distinguishes everything the grouping logic
distinguishes. The existing default-context, no-PURL claims still get unique
ids; new context-bearing or PURL-bearing claims no longer collide.

Tests +1: two claims with the same subject/name/version/evidence but different
``context.arch`` both add cleanly, get distinct ids, and remain two independent
groups after reconciliation. Coverage golden byte-identical. Suite now 260.

---

## D69 - Canonicalise PURL qualifier order in IdentityMismatchRule (bug #4)

Review item #4. ``IdentityMismatchRule`` (D56) compared the PURLs in each
version-group via a raw set: two PURLs that differed only in qualifier *order*
(``...?arch=x86_64&distro=el10`` vs ``...?distro=el10&arch=x86_64``) were
counted as different and tripped a false ``IDENTITY_MISMATCH`` -- already
flagged as a documented caveat (limitations.md), now a real footgun as
reconciliation has become more central.

Fix: a small ``canonical_purl`` helper in ``reconcile_rules.py`` that splits a
PURL on ``?`` and ``#``, sorts the qualifier ``k=v`` items alphabetically, and
re-emits. ``IdentityMismatchRule.check`` canonicalises each PURL before adding
it to the per-version set. Per the PURL spec, qualifier order is not
semantically meaningful, so this is a value-preserving normalisation.

Scope: qualifier-order only. URL-encoded values (``%2F`` vs ``/``) and scheme
case are still raw-compared; both spec-compliant variants would compare unequal
until a full PURL parser is wired in. Recorded as a remaining caveat in
``limitations.md`` (replacing the now-fixed string-compare note).

Tests +2: same-PURL/different-order does not trip; a real qualifier *value*
difference (different distro) still trips; plus edge-case unit tests for
``canonical_purl`` (no qualifiers, already-sorted, subpath preserved).
Coverage golden byte-identical. Suite now 262.

---

## D70 - Source-import scanner: filter Node stdlib + tag coordinate_kind (bug #7)

Review item #7. Two overstatements in the multi-language source-import scanner
(D61) that could mislead a downstream CVE matcher or resolver:

1. **JavaScript:** ``require("fs")`` / ``import "path"`` is the Node runtime's
   own stdlib, not an npm package, yet they were emitted as ``Ecosystem.NPM``
   claims -- a fake dependency on the standard library, indistinguishable from
   a real missing/vulnerable npm dep.
2. **Java / C / C++:** the extractor recovers a class path
   (``com.google.common.collect.ImmutableList``) or a header path
   (``openssl/ssl.h``), **not** a package coordinate. A consumer that read the
   claim's name as a Maven ``groupId:artifactId`` or a system-package name
   would be wrong every time.

Fix:

- Added a ``_NODE_STDLIB`` set (Node 20+, canonical) and a small
  ``_maybe_add_npm`` helper that filters both project-internal paths
  (``./`` / ``/``) and Node built-ins. Submodule specifiers (``fs/promises``)
  collapse via ``_npm_root`` to their root and are filtered.
- Added a ``_COORDINATE_KIND`` map: each language is tagged with what shape its
  extracted name actually is -- ``module``, ``module_path``, ``crate``,
  ``npm_package``, ``require_name``, ``class_path``, ``header_path``. The tag
  rides on every claim's ``raw["coordinate_kind"]``, so a consumer can refuse
  to treat a ``class_path`` or ``header_path`` as an artifact coordinate. The
  per-language ``Ecosystem`` is unchanged (a Java class import is still
  ``Ecosystem.MAVEN`` evidence -- but it now self-describes as a class path).

Tests +1 (the existing JS test is tightened to also assert ``fs`` / ``crypto`` /
``fs/promises`` are filtered; a new integration test verifies that a mixed-tree
scan tags the Java claim ``class_path``, the C claim ``header_path``, and the
Python / JavaScript claims with their package-coordinate kinds). Coverage
golden byte-identical. Suite now 263.

---

## D71 - Split identity_verified into established + externally_verified (bug #8)

Review item #8 (naming clarity, with a real semantic split underneath).
``PackageVulnAssessment.identity_verified`` was true only when
``cpe_status == "verified"`` (an NVD-dictionary match), but **CVE matching
ran against any set CPE** including ``vendor_asserted`` ones (AlmaLinux's own
SBOM). The field name suggested a stronger guarantee than the matching
behaviour delivered: a reader could believe a "not identity_verified" package
was *not* being matched, when it actually was.

Fix: replace the single bool with the two flags it was always covering:

- ``identity_established: bool`` -- a CPE is set, so CVE matching can run.
  True for both ``verified`` (NVD) and ``vendor_asserted`` (vendor SBOM).
- ``identity_externally_verified: bool`` -- true only for ``verified``. This
  is the narrower NVD-dictionary case.

Both ride in ``to_dict()`` (and so in the ``vuln --format json`` output);
``identity_verified`` is removed (no consumer relies on the old name now that
the two callers -- CLI render, test_vuln -- are updated). The CLI render
``identity = "verified" if pkg.identity_verified else pkg.cpe_status`` was
redundant (when verified, ``cpe_status`` already equals ``"verified"``), so it
simplifies to ``identity = pkg.cpe_status``.

Tests +0 net (existing test assertions updated to the two new fields,
documenting the established/verified split they were always silently testing).
Coverage golden byte-identical. Suite stays 263.

---

## D74 - Real SQLite query backend (versioning, merge mode, recursive CTEs, snapshots)

D-entry G2 from the review's open list. ``albs_graph/store.py`` was the
"persist a built universe and reload it later" minimum -- replace-on-save,
one-hop SQL only, no schema versioning. Multi-build / multi-arch accumulation
silently lost evidence (the second ``save_graph`` wiped the first); multi-hop
queries required a full ``load_graph``; there was no way to evolve the schema
without a follow-up migration burden on every caller.

Decision: turn ``store.py`` into a small but real query backend. Four
additions, all stdlib-only:

1. **Versioned schema with in-place migrations.** A ``schema_version`` table
   plus an ordered ``MIGRATIONS`` tuple (``_migration_v1_*`` ...
   ``_migration_v3_*`` today). Every public entry point now calls
   ``_ensure_schema(connection)``; a fresh DB walks every migration, an
   existing one applies just the missing ones, and rolling back a release
   leaves the store at a newer version that the older code still reads
   (the base tables are forward-compatible).
2. **Merge mode (closes G2).** ``save_graph(.., mode="merge")`` upserts node
   and edge rows and deep-merges the JSON metadata: dicts merge key-by-key
   (incoming wins on scalar conflicts), lists union with order preserved
   (no duplicates), other types take incoming. This is the shape edge
   metadata naturally has (``evidence: list``, ``note: str``, ``claim: str``)
   so the union is what callers want -- multi-build accumulation no longer
   silently overwrites. The default stays ``"replace"`` so existing callers
   are unchanged; ``--merge`` on ``universe --save`` opts in.
3. **Recursive-CTE multi-hop queries.** ``sql_reachable_dependencies`` and
   ``sql_dependency_paths`` walk in SQLite via ``WITH RECURSIVE``, with
   cycle detection (UNION dedupes the closure; the path query carries a
   ``|id|id|`` string and uses ``instr`` to skip revisits). ``max_depth`` and
   ``max_paths`` bound runtime; the queries are wired into
   ``universe --db --path-from/--path-to`` so the SQL fast path now covers
   chains too, not just one-hop lookups.
4. **Materialized analysis snapshots.** ``save_analysis_snapshot`` /
   ``load_analysis_snapshot`` persist a coverage / vuln / license report
   payload keyed on ``(kind, subject_id)``; older snapshots stay as an audit
   trail, ``load`` returns the most recent. The table is the foundation for
   future "what changed since the last run?" diffs without re-deriving the
   report.

Backward compatibility: every original public function
(``save_graph`` / ``load_graph`` / ``sql_dependents`` / ``sql_dependencies``)
keeps its old signature and default semantics. All 5 original tests pass
unchanged. 9 new tests cover the additions (schema versioning idempotency,
both save modes, deep-merge of edge metadata + node metadata accumulation,
recursive-CTE walks against the in-memory BFS, ``max_depth`` / ``max_paths``
bounds, snapshot most-recent-wins). Suite 263 → 272.

Out of scope: still no concurrency control (single-writer), still no
``sqlite-vec`` similarity overlay (G3; deliberately optional).

---

## D73 - Finish D57: identify / trust-path / vuln / license on the pipeline

D57 introduced ``AnalysisPipeline`` and migrated ``coverage`` first, deferring
the other four commands to follow-ups. This decision closes that loop: each
remaining command builds a ``RunSpec`` from its CLI args and delegates the
load -> enrich -> reconcile portion to ``AnalysisPipeline().run()``, then keeps
its own rendering as before.

What moved per command:

- ``identify``: ``BuildSbomStep`` (when ``--build-sbom`` is given). The CPE,
  errata, payload + dnf steps don't apply to identify's surface today, but the
  pipeline transparently picks them up if they're added later (no change to
  ``identify_command`` needed).
- ``trust-path``: ``BuildSbomStep`` + ``ErrataStep``. To preserve the prior
  "errata defaults to the selected RPM" behaviour, the CLI promotes the
  ``rpm`` / ``package`` selector to ``RunSpec.errata_subject`` when
  ``--errata-subject`` is not given; the pipeline's subject-resolution then
  picks the same RPM the inline code did.
- ``vuln``: ``BuildSbomStep`` + ``VerifyCpeStep`` + ``ErrataStep`` +
  ``PayloadStep``. **Latent bug fixed by the migration**: ``vuln`` ran
  ``verify_cpe`` *before* ``build_sbom``, so a vendor CPE from the SBOM
  overwrote an NVD-verified one. The pipeline's documented order (D57:
  "build_sbom runs before verify_cpe") is the design intent; vuln now uses it.
- ``license``: ``SbomStep`` (the CycloneDX attach). The ``--rpm-licenses`` path
  stays inline; it isn't an enrichment pipeline (it queries dnf for license tags
  and rolls them up, not adding claims).

Verification: byte-identical JSON output for each command on the synthetic
fixture (``--source albs_graph/examples/synthetic_build.json``) before and
after, captured the same way coverage was in D57. No new tests are needed --
the existing pipeline tests already cover the orchestration, the existing
provenance tests cover the analyses, and ``test_cli_help`` already exercises
that ``trust-path --errata`` closes ``has_errata_link`` (the only behaviour
sensitive to subject resolution). Cleanup: 6 now-unused imports removed from
``cli/main.py``; the file shrinks by 23 lines net.

Drive-by fix in the same commit: modern Typer (0.13+) vendors its own
``click`` fork, so ``NoArgsIsHelpError`` raised by ``no_args_is_help=True`` is
*not* a ``click.ClickException`` -- it bypassed ``main()``'s ``except``,
broke ``test_fetch_without_args_shows_help`` and
``test_trust_path_without_args_shows_help``, and would have leaked tracebacks
to users. ``main()`` now catches both ``click.ClickException`` and
``typer._click.exceptions.ClickException`` (with a fallback alias for older
typers). Suite unchanged at 263.

---

## D72 - demo_verbose attaches the build SBOM (consistency with the rest of the run)

User-spotted on a VPS run: ``grep -R sbom examples/demo-build-57810/`` returns
~960 matches across the demo's artifacts, **and yet** one line says
``has_sbom missing``. Tracked down to step 11 in ``example--full.sh``:
``python -m albs_graph.cli.demo_verbose`` re-runs ``trust_path()`` internally
against a freshly-built graph but did not attach the SBOM, so its trust-path
table reported ``has_sbom missing`` while step 1 (and the rest of the run,
which passes ``--build-sbom`` to ``coverage`` / ``vuln`` / ``trust-path``)
reported ``has_sbom ok``. The same console.txt thus simultaneously asserted
the SBOM was present and missing -- confusing.

Fix: ``demo_verbose`` now takes ``--build-sbom PATH``; when supplied, it calls
``enrich_graph_with_build_sbom`` right after ``graph_from_build_metadata`` and
before the internal ``trust_path``. ``example--full.sh`` step 11 passes
``${sbom_args[@]}`` (already populated from ``SBOM_FILE``), so the inner
trust-path's ``has_sbom`` check now matches the outer one whenever the SBOM
file exists. Regenerated console.txt confirms: ``has_sbom`` now reads ``ok``
on both trust-path tables (lines 31 and 530). Suite unchanged at 263.

---

## Cross-cutting decisions

- **Layering.** `adapters → provenance.reconcile` was confirmed acyclic
  (`provenance` imports no adapters), so the header adapter may emit claims
  directly. The reconciliation *algorithm* stays in `provenance`; the
  `DependencyClaim` primitive + `add_dependency_claim` live alongside it.
- **Offline tests.** Network adapters are tested by serving a hand-built RPM byte
  structure through a fake range fetcher (`tests/test_rpm_header.py`). No test
  touches the network, per the repo rule.
- **CLI surface.** A single new `coverage` command reconciles evidence and prints
  the five axes; `--with-rpm-headers` performs the live range reads. It works
  offline from cached ALBS JSON (`--source`) or live (`--build-id`).
- **Commit hygiene.** Commits carry no AI attribution; a local
  `.git/hooks/commit-msg` hook strips any `Co-Authored-By: Claude` / "Generated
  with Claude" lines as a safety net.

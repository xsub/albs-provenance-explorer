# Decisions

> **Note on D-numbering across branches.** This `InvestigationWorkbenchApp`
> branch and `max` diverged at `fc5b647` and then numbered new decisions
> independently, so D-numbers above ~D79 mean **different things** on each
> branch (e.g. here `D80` is "Workbench timeline tree" and `D90` is the
> HTML-fallback cache, whereas on `max` `D80` is "Reject empty SPA-shell caches"
> and the fallback-cache decision is `D81`). When cross-referencing a decision
> between branches, match it by **title**, not by number; do not merge the two
> `decisions.md` files without reconciling the overlap.

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

## D73 - App-facing services for the PyQt investigation workbench branch

The ``InvestigationWorkbenchApp`` branch starts by extracting a service layer
before adding any GUI. The goal is the final architecture: PyQt calls backend
services directly, and the CLI uses the same services rather than growing a
second orchestration path.

Added ``albs_graph.services``:

- ``analysis.py`` wraps graph loading, optional repograph acquisition,
  ``AnalysisPipeline`` execution, reconciliation, coverage, identity
  breakdown, and non-fatal warnings.
- ``queries.py`` exposes typed node/edge summaries, artifact listing, and
  metadata-aware node search for inspectors and search boxes.
- ``slices.py`` exposes focused graph projections for trust path, source build,
  dependency evidence, security context, and universe traversal.
- ``findings.py`` turns coverage gaps, reconciliation conflicts, cross-distro
  issues, and missing trust checks into UI-friendly finding records.

The ``coverage`` command now uses ``AnalysisService`` for base graph loading,
repograph resolution, pipeline execution, coverage, and identity breakdown. Its
rendering stays in the CLI. This is intentionally incremental: command output
remains unchanged, but orchestration now has an app-facing entrypoint.

The workbench plan is recorded in
``docs/plan-pyqt5-investigation-workbench-app.md``. Tests +6 cover the service
facade, repograph warning path, graph queries, graph slices, dependency-evidence
projection, and findings. Suite now 269.

---

## D74 - First runnable PyQt workbench shell

Added the first showable desktop entrypoint:

- ``albs-graph-workbench`` script and ``python -m albs_graph.gui``.
- Optional ``gui`` extra: ``pip install -e '.[gui]'`` installs PyQt5.
- A PyQt5 main window that opens ALBS build metadata JSON (or a live
  ``--build-id``), runs ``AnalysisService`` in a background Qt worker, lists
  binary RPM artifacts, renders the selected graph slice as SVG, and exposes
  node metadata/edges plus findings.
- Three initial modes: Trust Path, Dependency Evidence, and Security Context.
  Each mode uses ``GraphSlices`` rather than reconstructing graph logic in the
  UI.
- A fallback launcher message when PyQt5 is not installed, so the default
  developer/test environment remains usable without Qt.

This is intentionally still a workbench shell, not the final app. The important
milestone is that the GUI now exercises the same service API as the CLI and can
show a real graph slice once PyQt5 is present. Tests +2 cover the GUI parser and
default source path. Suite now 271.

---

## D75 - Workbench dark mode and readable graph renderer

The first PyQt shell worked, but macOS dark mode exposed two presentation
problems:

- Qt picked up some dark-mode controls while the app stylesheet forced other
  panels to light colors, producing black inputs beside light tables and
  low-contrast headers.
- The workbench reused the CLI DOT renderer, whose long RPM/CAS labels were
  tuned for exported artifacts rather than an interactive viewport. Worse, the
  GUI labels were double-escaped, so Graphviz rendered literal ``\n`` instead
  of line breaks, making nodes wide and unreadable.

Fix: add ``albs_graph.gui.render`` as a GUI-specific renderer. It preserves the
stable CLI SVG output, but gives the workbench wrapped node labels, shorter RPM
/ CAS / build-task summaries, less noisy edge labels, larger spacing, and
separate light/dark color palettes. The PyQt window now detects the active Qt
palette, applies a coherent dark/light stylesheet to panels, inputs, tables,
tabs and docks, and renders graph SVG with the matching palette. The SVG scroll
area no longer resizes every graph to the viewport; it keeps legible natural
sizes and uses scrolling for larger slices.

Tests +2 cover the dark DOT theme and line-broken workbench labels. Suite now
273.

---

## D76 - Workbench inspector tabs, graph header, and artifact filtering

The first showable workbench still had three rough edges:

- The inspector was one large raw JSON pane, useful for debugging but too
  noisy for investigation.
- The graph canvas had no local context beyond the global toolbar mode.
- The artifact list was dense and hard to narrow once a build had hundreds of
  RPMs.

Fix: split inspection into a small GUI view model (``albs_graph.gui.inspect``)
and four tabs in the PyQt pane: ``Summary``, ``Metadata``, ``Edges`` and
``Raw``. The raw JSON remains available, but common node fields and
incoming/outgoing edges are now scannable tables. The graph canvas also gains
a compact header with the selected artifact, active mode, and node/edge counts
for the focused slice. The left panel gets a filter box and slightly roomier
artifact rows; the header reports visible/total artifact counts while
filtering.

Tests +2 cover the inspector view model and stable raw JSON output. Suite now
275.

---

## D77 - Workbench graph node hit-testing

The workbench needs graph-driven selection: a user should be able to click a
node in the central graph and inspect that exact object, instead of using only
the artifact list or the node table.

Fix: keep the lightweight SVG renderer, but emit Graphviz `cmapx` image-map
coordinates beside the SVG. `albs_graph.gui.hitmap` parses the map into typed
node hit regions, and the PyQt `GraphSvgWidget` maps mouse coordinates back to
the SVG's natural coordinate space. Clicking a node now updates the inspector,
selects the matching row in the slice table, and re-renders the graph with the
selected node highlighted. The fallback SVG path also exposes rectangular node
regions, so the app still has basic click behavior when Graphviz is absent.

Tests +3 cover Graphviz image-map parsing, geometric hit-testing, clickable DOT
URLs, and selected-node styling. Suite now 278.

---

## D78 - Workbench investigation workflow features

After node click selection, the next workbench step is making the surrounding UI
drive investigation instead of passively displaying tables.

Fix: add a small workbench service model for UI projections:
`coverage_rows`, `timeline_rows`, `investigation_recipes`,
`WorkbenchSession`, and `evidence_bundle`. The PyQt window now has finding
navigation, double-click edge navigation in the inspector, double-click
timeline navigation, a one-hop Node Neighborhood graph mode, recipe shortcuts,
a coverage dashboard tab, a timeline tab, JSON evidence-bundle export, and
save/load for lightweight sessions. A first build-comparison helper
(`compare_artifacts`) records added, removed, and changed RPM artifacts by
package/arch key, giving the later compare screen a tested backend entrypoint.

Tests +5 cover node-neighborhood slices, workbench coverage/timeline/recipe
models, session round-tripping, evidence-bundle shape, and artifact comparison.
Suite now 283.

---

## D79 - Workbench edge selection, graph controls, compare, and HTML reports

The workbench's first interactive graph pass handled node selection, but the
next highest-value steps were to make edges inspectable, give users basic graph
controls, expose build comparison in the UI, and produce shareable reports.

Fix: extend Graphviz image-map parsing to distinguish node and edge regions.
Workbench DOT now assigns URLs to edges and can highlight a selected edge.
`edge_inspector_view` gives edges the same Summary / Metadata / Raw treatment as
nodes, while the PyQt graph widget emits node or edge selections based on the
clicked SVG region. The graph toolbar also gains zoom in/out, fit, reset, and
search controls. The compare tab loads another ALBS metadata JSON and shows
added, removed, and changed artifact rows through the existing
`compare_artifacts` service. The evidence bundle can now carry selected-edge
context, and `evidence_report_html` renders that bundle into a standalone HTML
investigation report.

Tests +4 cover edge hit-map parsing, clickable/highlighted edge DOT output,
edge inspector rendering, and HTML report rendering. Suite now 287.

---

## D80 - Workbench timeline tree from ALBS build analysis

The first Timeline tab was not a timeline: it listed build-task/signature graph
nodes with no real durations, so it did not explain how an ALBS task progressed.

Fix: carry `BuildAnalysis` through `AnalysisResult` whenever a graph is loaded
from raw ALBS metadata (`--source` / build-id fetch). The workbench timeline now
uses `timeline_tree`, a hierarchical view model rooted at build/sign tasks. Each
build task row includes status, wall time, start and finish, and expands into
build performance steps, aggregate test timing, and artifact groups. If only a
graph is available, the old graph-derived timeline is retained as a graceful
fallback. The PyQt tab is now a `QTreeWidget`, so tasks can be expanded like a
job cascade while still carrying graph node ids for navigation.

Tests +2 cover build-analysis attachment in `AnalysisService` and tree timeline
construction from the committed ALBS metadata fixture. Suite now 289.

---

## D81 - Workbench recipe menu sizing

The recipe selector was visually clipped in the toolbar on dark-mode macOS, and
the dropdown inherited the narrow combo-box width, so longer recipe titles were
cut off before the user could read them.

Fix: treat the recipe selector as a fixed-width toolbar control and size its
popup view independently from the button. The button now has enough room for the
`Recipes` label, while the popup width is computed from the longest recipe title
with a minimum width for stable dark-mode rendering. No service behavior changed.

Tests unchanged; this is a PyQt presentation fix. Suite remains 289.

---

## D82 - Workbench Gantt, evidence matrix, build diff, layers, and inspector context

The workbench had enough interaction to navigate a graph, but the next
highest-value workflows needed more analytical structure: the build timeline
needed a visual cascade, artifact evidence needed to be comparable at a glance,
the compare tab needed more than artifact add/remove/change rows, graph density
needed user-controlled layers, and the inspector needed semantic context beyond
raw metadata.

Fix: add service-level view models for the new UI projections instead of
embedding analysis logic directly in Qt:

- `timeline_gantt_rows` flattens the existing timeline tree into offset/duration
  rows for a Gantt-style cascade.
- `evidence_matrix_rows` reports per-binary provenance/security/test evidence
  status and missing evidence.
- `compare_builds` combines artifact deltas, evidence status changes, and
  `BuildAnalysis` task timing changes.
- `graph_layers` / `filter_graph_layers` expose Build, CAS, Sign/Release,
  Tests, Security, and Dependencies as toggleable graph layers.
- The inspector summary now includes relation counts plus semantic rows for
  binary RPM completeness, build-task output/test counts, and CAS authentication
  context.

The PyQt workbench now exposes Tree/Gantt timeline selection, an Evidence tab,
the richer Compare tab, a Layers toolbar menu, and the enhanced inspector
summary while keeping the CLI/backend service boundary intact.

Tests +4 cover Gantt row timing, the evidence matrix, layer filtering, and
combined build comparison. Suite now 293.

---

## D83 - Workbench Gantt PyQt5 compatibility and available graph font

The first Gantt implementation used `QGraphicsScene.addRoundedRect`, which is
not available in PyQt5 and crashed the workbench as soon as analysis populated
the Timeline tab. Qt also warned that the SVG/DOT renderer requested the missing
`Inter` font family, causing font-alias population work during startup/rendering.

Fix: draw Gantt bars with `QPainterPath.addRoundedRect` plus
`QGraphicsScene.addPath`, which is supported by PyQt5. Replace graph renderer
font declarations with `Arial` / `Arial,Helvetica,sans-serif` in both the
workbench renderer and the older generic DOT/SVG renderers so Qt does not need
to resolve a missing font family. No graph semantics changed.

Tests unchanged; render tests now assert DOT output does not request `Inter`.
Suite remains 293.

---

## D84 - Workbench source evidence, graph queries, and finding drill-down

After the Gantt/evidence/layer pass, the next highest-value investigation
workflow was to make the source side and repeated graph questions first-class
UI surfaces. The graph already carried source-package, git repository, commit,
source CAS, and optional source-tree/spec/manifest evidence, but users had to
hunt for those nodes manually. Findings also navigated to a subject, but did not
explain the failed checks around that subject.

Fix: add service-level view models for source and query workflows:

- `source_evidence_rows` summarizes source package, git repository, git commit,
  source CAS, source tree, spec files, manifests, declared dependencies, and
  source/patch references when present.
- `graph_query_presets` / `run_graph_query` provide reusable investigation
  queries for source-to-artifact paths, source evidence, coverage gaps, missing
  SBOM/errata/CAS/signature evidence, all CAS nodes, and dependency conflicts.
- `finding_drilldown_rows` expands a finding into the subject, trust checks, and
  related source evidence.

The PyQt workbench now has Source, Queries, and Finding Detail tabs. Rows keep
node ids attached so double-clicking can navigate back into the graph/inspector.
The evidence bundle and HTML report now include source evidence as well.

Tests +3 cover source-evidence summarization, graph query presets, and finding
drill-down expansion. Suite now 296.

---

## D85 - Workbench bottom dock shrink behavior

The bottom Investigation Output dock became too tall after adding the Gantt
timeline. `TimelineGanttView` had a 260px minimum height, and the bottom
`QTabWidget` inherited the largest page minimum, so users could not shrink the
bottom table enough to give the center graph/slice area more room.

Fix: lower the Gantt view minimum and mark the bottom dock, tab widget, and tab
pages with a shrink-friendly vertical size policy. The Gantt remains scrollable,
but it no longer dictates the minimum height of every bottom tab.

Tests unchanged; this is a PyQt layout sizing fix. Suite remains 296.

---

## D86 - Workbench build SBOM parity with CLI evidence reports

The Evidence matrix uses `trust_path_report`, so an RPM only reports `SBOM ok`
when the graph has an SBOM `DESCRIBED_BY` edge. The CLI already creates those
edges when `--build-sbom FILE` is supplied, but the PyQt worker was always
running with an empty `RunSpec()`. That made the workbench look inconsistent
with `example--full.sh`: the base ALBS graph was loaded correctly, while the
build SBOM enrichment step never ran.

Fix: give the workbench a build-SBOM input path, persist it in saved sessions,
accept `albs-graph-workbench --build-sbom FILE`, and pass it through to
`AnalysisService.analyze(..., RunSpec(build_sbom=...))`. When the field is
empty, the UI cautiously looks for `build-<id>.cyclonedx.json` next to the
opened ALBS JSON and then in the repository `examples/` directory. If both the
source and SBOM filenames expose build ids, mismatches are rejected before
analysis starts.

Tests extend the workbench parser/session checks and assert the service Evidence
matrix reports `SBOM ok` for a graph that already has SBOM evidence. Suite
remains 296.

---

## D87 - Workbench menu bar and compact run context

After adding export, compare, session, zoom, layer, recipe, source and SBOM
controls, the top toolbar no longer fit even on wide displays. It also made
long source/SBOM paths compete with primary investigation controls.

Fix: move file/run/export/session/compare/zoom/restart/exit commands into a
normal menu bar. The toolbar is now a compact run-context strip: source, build
SBOM, build id, mode, recipes, layers, graph search and tests. Full source and
SBOM paths are available through the fields themselves and their tooltips, while
the status bar is reserved for run state.

The menu bar also adds Reload Program and Exit. Window close now clears pending
Qt runnable work before accepting the close event, and terminal Ctrl+C is wired
to `QApplication.quit()` through a lightweight signal timer so CLI-launched
workbench sessions exit cleanly.

Tests unchanged; this is a PyQt shell/layout lifecycle fix. Suite remains 296.

---

## D88 - Build-id Enter launches the classic full CLI runner

The workbench should be able to consume data generated by the established CLI
workflow instead of only fetching ALBS metadata through the in-process service.
When a user types a build id and presses Enter, the PyQt app now launches the
classic `example--full.sh` runner in a subprocess and streams its output into a
large modal console dialog. The dialog uses read-only selectable text, keeps
scrolling with live output, and enables OK only after the subprocess exits.

Runtime details:

- The classic checkout defaults to the sibling `../albs-provenance-explorer`
  worktree (the `max` branch checkout in the local development layout). It can
  be overridden with `ALBS_EXPLORER_CLASSIC_ROOT`.
- The subprocess runs with `cwd` and `PYTHONPATH` pointing at that classic
  checkout, so the shared venv's editable install cannot accidentally import
  the workbench branch.
- Generated files go under
  `/private/tmp/albs-provenance-workbench/build-<id>/`; the cache target is
  `live/build-<id>.albs.json`.
- If `examples/build-<id>.cyclonedx.json` exists in either checkout, it is
  passed as `SBOM_FILE`, preserving the full-demo `--build-sbom` behavior.
- After the user acknowledges the finished console dialog, the workbench opens
  the generated `.albs.json` cache, clears the build-id field, carries over the
  detected build SBOM path, and reruns the normal in-process analysis.

Tests unchanged; this is a UI subprocess integration point and is covered by
offscreen construction plus the existing service/pipeline tests. Suite remains
296.

---

## D89 - Qt-safe SVG font family

The full offscreen workbench smoke test exposed another startup/render warning:
Qt's SVG renderer treated the CSS fallback stack `Arial,Helvetica,sans-serif`
as one missing family (`Arial,,Helvetica,,sans-serif`). DOT rendering already
uses a single available family, so SVG output now does the same and emits
`font-family: Arial`.

Tests extend the renderer assertions to reject both `Inter` and `Helvetica`
fallback-stack output. Suite remains 296.

---

## D90 - Cache ALBS HTML fallback metadata

Build-id acquisition through the classic runner exposed a backend cache gap:
for builds where `/api/v1/builds/<id>/` is unavailable as JSON but the HTML
build page can still be parsed, `fetch_build_metadata(..., cache_path=...)`
returned usable fallback metadata without writing the requested `.albs.json`
cache. `example--full.sh` then failed immediately after the fetch step because
the cache file it expected was absent.

Fix: the HTML fallback path now writes a parseable synthetic raw metadata cache.
`parse_build_page` includes `build_id`, `package`, source repository, commit,
CAS, source RPM, binary RPMs, release repository, arch, source URL and title in
`metadata.raw`, so later commands can load the same fallback evidence through
`parse_build_metadata`.

Tests add an API-miss/HTML-hit sequence that verifies the fallback cache is
written and reused. The same end-to-end run exposed a macOS/bash `set -u`
failure in `example--full.sh` when no `SBOM_FILE` exists; step 11 now uses the
same guarded `sbom_args` expansion as the earlier CLI steps. Suite now 297.

---

## D91 - Port max build-SBOM auto-discovery into the workbench branch

The `max` branch added CLI-side discovery for AlmaLinux build SBOM files: when
a command is run with `--build-id N` and no explicit `--build-sbom`, the CLI can
look for the conventional `build-N.cyclonedx.json` file that `alma-sbom` and
`example--full.sh` produce. The workbench branch already had GUI-side SBOM
suggestion, but its CLI/backend path still required explicit `--build-sbom`.

Ported behavior:

- New `discover_build_sbom(build_id, cache_path=..., search_dirs=("examples",))`
  helper checks the cache sibling, one level above the cache, then search dirs.
- `coverage`, `identify`, `trust-path`, and `vuln` gain
  `--auto-sbom/--no-auto-sbom`; auto-discovery is enabled by default.
- Explicit `--build-sbom FILE` wins and skips discovery.
- `--source`-only commands do not discover because there is no build id.
- Verbose mode logs the discovered file path.

Tests from the `max` change cover discovery precedence, no-hit behavior,
directory-vs-file handling, build-id-specific names, and the CLI resolver
helper. Suite now 308.

---

## D92 - Port the remaining max backend into the workbench branch

After the focused D91 SBOM port, the backend subset of
`InvestigationWorkbenchApp` still lagged behind `max`: pipeline-backed CLI
commands, the richer SQLite store, native language resolvers, live security
feed fetch, and the arch-universe command were present only on `max`.

Decision: port the backend file contents from `max` into the workbench branch
while keeping the branch-specific PyQt GUI, service layer, `pyproject.toml`
entry point, and workbench ignore rules intact.

Ported backend areas:

- CLI orchestration: `identify`, `trust-path`, `vuln`, and `license` share the
  `AnalysisPipeline` path instead of duplicating enrichment logic in each
  command.
- SQLite store: versioned schema migrations, `save_graph(..., mode="merge")`,
  recursive CTE queries (`sql_reachable_dependencies`,
  `sql_dependency_paths`), and materialized analysis snapshots.
- Native resolvers: pip, Maven, and npm join the existing Go/Cargo resolver
  contract; Gradle remains intentionally deferred.
- Security feeds: live NVD CPE dictionary and CVE feed fetching through the
  HTTP cache with TTL and graceful fallback; explicit local files still win.
- Arch universe: `arch-universe` enumerates per-release repositories, runs
  `dnf repograph` per repo, merges the resulting universes, records per-repo
  failures, and can persist through the store.

Backend equality check: after the port, the non-GUI/non-service backend paths
and their tests match `max` for the targeted files. The combined workbench
branch now has the max backend plus the PyQt workbench additions. Ruff, mypy
and the full suite were clean after the port.

---

## D93 - Reject empty ALBS SPA-shell HTML fallback metadata

Loading build 57811 through the workbench exposed a false-success path in the
ALBS HTML fallback. The live API returns `404 {"detail":"Build with
build_id=57811 is not found"}`, while `/build/57811` returns only the generic
single-page application shell (`<title>AlmaLinux Build System</title><div
id=q-app>`). The fallback parser treated that page title as package
`AlmaLinux`, wrote a raw cache with no source RPM, no binary RPMs, `commit:
unknown`, and `unknown-albs-source:AlmaLinux`, then every later command saw a
"fresh" cache and built a useless five-node graph.

Fix:

- `parse_build_page` no longer falls back to the page title as a package name.
  It requires an explicit package/source label or derives the package from an
  RPM link. A generic SPA shell now raises `ValueError` instead of producing
  metadata.
- Existing bad caches from the old parser are recognized by their generic title,
  missing RPMs, unknown commit, and `unknown-albs-source:*` repository, then
  discarded before refetch.
- The workbench's classic runner now prefers the current workbench checkout
  before the sibling `max` checkout. `ALBS_EXPLORER_CLASSIC_ROOT` still
  overrides this, but the default now uses the backend that has already been
  ported into the workbench branch.

Outcome: build 57811 is reported as unavailable/invalid metadata instead of
opening a misleading graph. Valid HTML fallbacks with a package label or RPM
links still cache and reload. Suite now 352.

---

## D94 - Port the live errata source + three-state errata status from max

The backend port (D92) predated max's errata work, so the workbench branch was
missing it. Ported here from max `527f471` so both branches share the backend.

The problem it fixes (max-side observation, equally true here): the trust path's
`has_errata_link` reading "missing" is misleading. Errata is a *queryable* fact,
and for most packages **having no advisory is the normal, complete state** -- a
clean package was being penalised for not being vulnerable. The graph conflated
"never looked" with "no advisory" into one boolean.

Ported pieces:

- `adapters/errata_source.py` -- an `ErrataSource` Protocol with two
  implementations behind `errata_source_for`: `HttpErrataSource` (the AlmaLinux
  errata feed file/URL, through `HttpCache` + TTL, reusing
  `live_feeds._cached_get`) and `DnfErrataSource` (`dnf -q updateinfo list
  --all`, degrades to "not consulted" when dnf is absent). Both expose
  `consulted: bool`.
- `TrustPathReport.errata_status` three-state: `advisory_present` /
  `confirmed_clean` / `not_checked`. `has_errata_link` is satisfied by the first
  two, so a confirmed-clean package with an SBOM is `security_context_complete`;
  only `not_checked` leaves it open.
- Pipeline `ErrataSourceStep` (binary-RPM selector, not one subject) + `RunSpec`
  `errata_source` / `errata_feed` / `errata_url`, and `--errata-source {http,dnf}`
  / `--errata-feed` / `--errata-url` on `coverage` / `vuln` / `trust-path`.

Workbench relevance: the Security Context slice and the Evidence matrix can now
distinguish a package with a real advisory from one that is confirmed clean,
instead of showing a blanket "errata missing" that the running implementation
notes already complained about. The cherry-pick was clean on the backend
(including `cli/main.py`); only max-numbered doc churn was dropped in favour of
this branch-numbered entry. +15 test cases. Suite now 367.

---

## D95 - Consolidate the workbench plan doc (398 architecture + salvaged 301 status)

The PyQt workbench plan existed in two divergent copies: the tracked 301-line
version on this branch, and a 398-line architecture rewrite that lived untracked
in the `max` worktree. The rewrite was strictly better as a *plan* (it added
Graph Interaction Model, typed backend query/slice APIs, an MVP/Later renderer
split, Follow-up Milestones M2-M5, Data/State Boundaries, Why-PyQt5, Risks and
Architectural Payoff sections), but it had dropped the older copy's
"Current branch status" implementation log -- six concrete details with no
equivalent in the rewrite (the Gantt-style timeline cascade, the Evidence
matrix, `compare_artifacts`, the `build-<id>.cyclonedx.json` suggestion,
`BuildAnalysis`-driven timeline, and the Graphviz image-map hit-testing
mechanism).

Decision: the live `plan-pyqt5-investigation-workbench-app.md` is now the merged
superset -- the 398 architecture plus an "Appendix: Current Implementation
Status (as built)" that salvages the dropped implementation log verbatim, so
nothing is lost. Both prior revisions are preserved verbatim alongside it as
`*_deprecated-301.md` (the old status-log version) and `*_deprecated-398.md`
(the architecture rewrite before the merge), in case either is needed again.
A concept-coverage check confirmed all six previously-dropped items are present
in the live doc. This is documentation housekeeping only -- no code change.

---

## D96 - Workbench errata-source toggle (live three-state from the Analyze path)

D94 ported the live errata source + the `confirmed_clean` three-state, and the
first M3 slice surfaced it in the Evidence matrix (`_errata_cell`). But the
matrix could only ever *show* `clean` if a run had actually consulted a source,
and the workbench's own Analyze path never set `RunSpec.errata_source` -- so
`clean` was unreachable from the GUI; you had to drop to the classic CLI runner.
The display supported a state the interactive tool could not produce.

Decision: a compact errata control in the toolbar, mirroring the existing
build-SBOM input -- it affects the *next* Analyze run, not a live re-render.

- An `errata_combo` with three entries whose `userData` is exactly the
  `RunSpec.errata_source` value: `""` (off, the historical not_checked default),
  `"http"` (the AlmaLinux errata feed) and `"dnf"` (host `updateinfo`).
- A companion `errata_feed_edit`. For `http`, `_errata_run_kwargs` treats the
  field as an **offline feed file when it is an existing path** (`errata_feed`),
  otherwise as a **live feed URL** (`errata_url`); an empty field still selects
  `http` and simply degrades to not-consulted (logged), never crashes. `dnf`
  needs no field and degrades to not-consulted off an AlmaLinux host.
- The toggle persists in `WorkbenchSession` (`errata_source` / `errata_feed`),
  so a saved investigation re-runs with the same security context.

`_run_spec` was refactored so the build-SBOM path and the errata path compose
(both can be set on one run) rather than the SBOM short-circuiting. No new
pipeline wiring: `ErrataSourceStep` is already in `DEFAULT_STEPS`, so setting the
spec field is sufficient. +1 GUI test (off -> no fields; http+file -> feed;
http+non-path -> url; dnf -> source only; session round-trip). Suite 370 -> 371.

---

## D97 - Workbench Security panel (CPE browser + errata/CVE posture)

M3's remaining payoff after the Evidence-matrix errata cell (b703443) and the
errata toggle (D96): a dedicated **Security** tab that reads, per binary RPM,
the whole security picture the layers already produce but no single workbench
view surfaced -- identity, errata three-state, addressed CVEs, feed-matched
potentially-affected CVEs, and the caveats that frame a naive version match.

Backend: `services.workbench.security_rows(graph, *, cve_feed=None,
node_selector=None) -> list[SecurityRow]`. It reuses `vulnerability_report`
(F1) for identity / errata / CVE / linkage and keys each assessment back to its
node by `(package, arch)` so the row carries a `node_id` (the panel navigates to
the artifact on activate). On top it adds two things the vuln report does not
expose per row: the **errata three-state** from `trust_path_report().errata_status`
(`advisory` / `clean` / `missing`, consistent with the matrix), and the
**CPE-candidate browser** -- the unverified `cpe_candidates` product/version
guesses from the node's `security_identity`, so a package with no official CPE
still shows what it *might* be (with a `[verified]` marker on a promoted
candidate). The `identity` column collapses `cpe_status` into
`verified` / `vendor-asserted` / `ambiguous` / `candidate` / `none`; `caveats`
joins `backport` (the distro-backport version-match caveat) + `dlopen` +
`static:N` reachability.

GUI: a 9-column `security_table` tab (Package, Arch, Identity, CPE, Candidates,
Errata, Addressed CVEs, Potential CVEs, Caveats), populated in
`_analysis_finished`, colour-tinted (verified/clean green, vendor/candidate/
advisory/backport amber, none/missing red), activate -> navigate to the node.

Scope note: the **Potential CVEs** column needs a live CVE feed at report time;
the workbench does not yet wire one (the errata toggle wires errata, not the CVE
feed), so it reads `-` until a feed source is added -- the column is present and
forward-compatible, and addressed CVEs (via errata) always populate. A
CVE-feed toggle mirroring the errata toggle is the natural follow-up.

+1 backend test (verified/vendor/candidate/backport/clean rows + addressed CVE)
and a GUI assertion that the panel populates. Suite 371 -> 372.

---

## D98 - Workbench Dependency panel (reconciled groups + scope/conflict filters)

Plan milestone M2. The workbench already had a *Dependency Evidence* graph mode
(a focused slice), but no tabular view of the reconciliation the pipeline runs
on every analysis -- the verdicts, conflict kinds and scope/linkage facets were
only reachable from the CLI's verbose output.

Backend: `services.workbench.dependency_rows(graph, *, scope_facets=None,
only_conflicts=False, only_unresolved=False) -> list[DependencyRow]`. Each
`DEPENDENCY_RESOLUTION` node (written by `reconcile_dependency_claims` during
analysis) is one group; its member claims, reached via the `OBSERVED_AS` edges
the reconciler already writes, supply the scope / linkage / resolution-state
facets (aggregated distinct). The row carries the consuming `subject` + the
`coordinate`, the `verdict` (consensus / compatible / conflict /
insufficient_evidence), the `conflict_kinds` (version_drift, range_violation,
...), the cross-distro `context_issue`, the versions and the evidence sources.

Filters mirror the plan: `scope_facets` keeps groups touching one of
`{runtime, build, static, test}` -- "build" maps to the spec scope `buildtime`
and "static" is matched against *linkage*, not scope, since the plan groups them
on one axis; `only_conflicts` keeps reconciler-flagged groups; `only_unresolved`
keeps groups with no resolved version (insufficient evidence, an
unresolvable/ambiguous member, or declared-only).

GUI: a "Dependencies" tab whose header carries a scope combo + "Only conflicts"
/ "Only unresolved" checkboxes (each re-runs the populate), over an 11-column
table (Subject, Coordinate, Ecosystem, Scope, Linkage, State, Verdict, Conflict,
Context, Versions, Evidence), verdict/conflict/context colour-tinted, activate ->
navigate to the consuming RPM. +1 backend test (consensus / version_drift /
declared-only across runtime/build/test, plus every filter) and a GUI
filter-toggle assertion. Suite 372 -> 373.

---

## D99 - Workbench Universe panel (open a SQLite store, search, walk, paths)

Plan milestone M4. The arch-wide universe store (D74) and its recursive-CTE
queries (`sql_dependents` / `sql_dependencies` / `sql_reachable_dependencies` /
`sql_dependency_paths`) existed but were CLI-only; the workbench could not open
a universe and explore it.

Two new store helpers fill the gaps the GUI needs: `sql_search(db, needle,
limit)` (label/id substring search -> `(id, type, label)`, empty needle lists
the first N so an opened store shows something) and `sql_node_labels(db, ids)`
(resolve a path's node ids to labels in one query). A thin read-only services
facade, `services.universe.UniverseStore`, wraps these into typed rows
(`UniversePackageRow`, `UniversePathRow`) -- the store is opened per call, so the
facade is just a path holder and the CTEs still run in SQLite without ever
loading the whole arch graph into memory; `paths()` resolves the raw id chains
to label chains for display.

GUI: a "Universe" tab, independent of the loaded build -- Open Universe (a
SQLite file), a package search box + results table, a selectable focus, three
walks (Dependencies / Dependents / Reachable), a target box + Find Paths
(label-resolved chains with a hop count), and a Favourites combo that captures
the current (store, search, focus, target) so a useful exploration can be
re-run. A bad file degrades to a logged error rather than crashing. +2 backend
tests (search/labels; facade search/traverse/paths) and a GUI
open/search/traverse/paths/favourite test. Suite 373 -> 376.

---

## D100 - Workbench session + report export (Markdown, PNG, reproducibility)

Plan milestone M5, the last of the workbench roadmap. The workbench could export
SVG / a JSON evidence bundle / an HTML report and save a (thin) session; M5
rounds that out.

- **Reproducibility appendix.** `evidence_bundle` now carries a
  `reproducibility` block -- the inputs (source / build id / build SBOM / errata
  source / mode), the graph size, and the runtime (tool version via
  `importlib.metadata`, Python version, an injectable timestamp so tests stay
  deterministic). It rides in the JSON bundle and renders as a section in both
  the HTML and the new Markdown report, so a report stands on its own.
- **Markdown report.** `evidence_report_markdown(bundle)` mirrors the HTML
  renderer's sections (slice / coverage / evidence matrix / source / findings /
  timeline / selected node + edge) as GitHub-flavoured Markdown tables + fenced
  JSON, minus the inline SVG (a Markdown report is meant to be read/diffed as
  text), plus the reproducibility appendix. New File -> Export -> Markdown.
- **PNG slice export.** `export_png` rasterises the current slice SVG through
  `QtSvg.QSvgRenderer` -> `QImage` (white background, falling back to the
  default size when the SVG declares none). New File -> Export -> PNG.
- **Richer session.** `WorkbenchSession` gained the M2 dependency filters
  (`dep_scope` / `dep_only_conflicts` / `dep_only_unresolved`) and the M4
  universe state (`universe_store` + `universe_favourites`), so a saved
  investigation restores the dependency view and re-opens the universe with its
  favourites. `_current_bundle` was extracted to stop the three exporters
  duplicating the bundle build.

+5 test cases (reproducibility appendix; Markdown render; session round-trip;
GUI markdown+png export via a monkeypatched save dialog; GUI session capture +
restore). Suite 376 -> 381. This completes M2-M5; the workbench roadmap's
remaining items are the orthogonal quality follow-ups (deeper qt_app coverage,
targeted mypy, splitting the god-object) and the M3 CVE-feed toggle.

---

## D101 - Workbench CVE-feed + CPE-verify toggles (Potential CVEs populates)

The Security panel (D97) shipped a *Potential CVEs* column that always read `-`
because the workbench never fed `security_rows` a CVE feed. Closing that needs
two coordinated inputs, because matching a CVE feed needs a *resolved official*
CPE -- a vendor-asserted SBOM CPE (`almalinux:...`) rarely lines up with the NVD
vendor/product tokens a feed keys on:

- **CPE verify (analyze-time).** A toolbar `cpe_dict_edit` -> `_run_spec`:
  a file path becomes `RunSpec.verify_cpe`, anything else `verify_cpe_url`. The
  pipeline's `VerifyCpeStep` (already in `DEFAULT_STEPS`, run off-thread in the
  worker) resolves candidates to official CPEs, so packages carry a vendor/
  product/version a feed can match. Affects the next Analyze, like the build
  SBOM and errata toggles.
- **CVE feed (report-time).** A toolbar `cve_feed_edit` -> `_ensure_cve_feed`
  loads a `CveFeed` via `live_feeds.fetch_cve_feed_or_none` (a path is a file;
  else a live URL, cached on disk; crash-safe), cached by source string so it
  loads once. `_populate_security_table` passes it to `security_rows(graph,
  cve_feed=...)`, and `vulnerability_report` matches the resolved CPE's version
  against the feed's affected ranges, minus CVEs an errata already addresses.
  Because it is a report-time input (not a graph enrichment), editing the field
  re-renders just the Security panel (`editingFinished -> _refresh_security_
  table`) without re-running the analysis.

Both sources persist in `WorkbenchSession` (`verify_cpe` / `cve_feed`). +2 test
cases (backend feed match incl. an out-of-range CVE excluded; GUI verify-cpe
run_spec kwargs + the panel's Potential CVEs cell populating from a feed file).
Suite 381 -> 383. This closes the last functional gap in the M3 Security
workbench.

---

## D102 - Extract the Universe panel into a typed module (first god-object split)

Quality follow-up. `gui/qt_app.py` is a single ~2.6k-line `WorkbenchWindow`
class under a blanket `# mypy: ignore-errors`; removing that blanket surfaces
~150 *real* errors (PyQt5 5.15 ships `.pyi` stubs, so the Qt types are real, not
`Any`: `union-attr` on `Optional` returns like `horizontalHeader()` /
`currentItem()`, enum access, missing annotations). Scattering ~150 per-line
ignores would be noise; the principled retirement of the blanket ignore is to
**split the window into smaller panels that each type-check on their own**.

First extraction: `gui/universe_panel.py` -- a `UniversePanel(QWidget)` that owns
the M4 universe widgets, the open store, the focus and the favourites, plus all
the open/search/walk/paths/favourite handlers. It is the natural first cut
because it is self-contained (it queries a separate SQLite universe store via the
`UniverseStore` facade and never touches the loaded build graph), so it needs
only two injected callbacks from the host -- `log` and `show_error` -- and
exposes a tiny session API (`store_path()`, `favourites()`, `restore()`). The
new module type-checks under **mypy strict with no ignore** (the Qt `Optional`
returns are guarded, `Qt.ItemDataRole.UserRole` replaces the flattened
`Qt.UserRole`). `qt_app.py` drops ~225 lines (3 state attrs + 8 methods +
the builder); the host now holds `self.universe_panel = UniversePanel(...)` and
delegates session capture/restore to it.

No behaviour change and no test-count change -- the two universe GUI tests were
repointed at `window.universe_panel.*` and still pass. This establishes the
template; the remaining panels (security / dependency / timeline / inspector)
can follow the same pattern to retire the blanket ignore incrementally. Suite
stays 386; mypy now checks 86 files (the new typed module included).

---

## D103 - Extract the Security panel into a typed module (god-object split #2)

Second cut after D102, applying the same template to the M3 Security panel.
`gui/security_panel.py` is a `SecurityPanel(QWidget)` that owns its 9-column
table and the colour-tinting, and renders the per-RPM security posture
(`security_rows`: CPE identity, the errata three-state, addressed/potential CVEs,
caveats). It needs only one injected callback -- `navigate(node_id)` -- and a
single `populate(graph, *, cve_feed=None)` entry point.

The one coupling worth noting: the **CVE feed is a report-time input loaded from
a toolbar field the host owns** (`_ensure_cve_feed`, D101), so the host keeps
that loader and passes the resolved feed into `populate`; the panel stays free of
the toolbar. `qt_app.py` drops the security table widget, the
`_populate_security_table` body (now a one-line delegate), `_tint_security_cell`
and `_security_activated`, plus the now-unused `security_rows` import (2393 ->
2331 lines). The new module type-checks under **mypy strict with no ignore**
(same `horizontalHeader()` Optional guard and `Qt.ItemDataRole.UserRole` as the
Universe panel).

No behaviour change, no test-count change -- the smoke test and the D101
Potential-CVEs test were repointed at `window.security_panel.table`. Suite stays
386; mypy now checks 87 files. Two of four panels extracted; dependency /
timeline / inspector remain before the blanket ignore on `qt_app.py` can go.

---

## D104 - Extract the Dependency panel into a typed module (god-object split #3)

Third cut, applying the D102 template to the M2 Dependency panel.
`gui/dependency_panel.py` is a `DependencyPanel(QWidget)` that owns the scope /
only-conflicts / only-unresolved **filters** as well as its 11-column table.
Unlike the Security panel (which is re-driven by the host on each populate), the
Dependency panel caches the last graph it was given so a *filter change
re-renders itself* -- the host only calls `populate(graph)` once per analysis
and the filter signals are wired internally.

Its session coupling is handled with a small symmetric API: `filters() ->
(scope, only_conflicts, only_unresolved)` for capture and `restore(scope,
only_conflicts, only_unresolved)` for load (mirroring the universe panel's
`store_path` / `restore`). The host's `_set_dep_scope` helper and the three
`dep_*` widget attributes are gone; `_current_session` unpacks `filters()` and
`load_session` calls `restore()`. `qt_app.py` drops the table + three filter
widgets + the panel assembly + `_populate_dependency_table`'s body (now a
one-line delegate) + `_tint_dependency_cell` + `_dependency_activated` + the
now-unused `dependency_rows` import. The new module type-checks under mypy
strict with no ignore.

No behaviour change, no test-count change -- the three GUI tests that poked
`window.dep_scope_combo` / `dep_only_conflicts` / `dependency_table` /
`_set_dep_scope` were repointed at `window.dependency_panel.*` (`scope_combo`,
`only_conflicts`, `table`, `restore`). Suite stays 386; mypy now checks 88 files.
Three of four panels extracted -- only the timeline/inspector cluster remains
before the blanket ignore on `qt_app.py` can be retired.

---

## D105 - Extract the Timeline panel into a typed module (god-object split #4)

Fourth and largest cut. `gui/timeline_panel.py` bundles the whole build-task
timeline that was scattered across `qt_app.py`: the `TimelineGanttView` (a
custom ~100-line `QGraphicsView` that draws the Gantt cascade), the tree view,
the Tree/Gantt switch + stacked widget, the recursive tree-item builder, the
two activation paths, and the module-scope `_format_seconds` / `_gantt_palette`
helpers. The host drives it with `populate(graph, build_analysis, *, dark)` (the
dark flag comes from the window's detected palette) and one `navigate` callback;
both views call it.

This is the first extraction where the **"targeted ignores, not blanket"** half
of the quality goal showed up concretely. The Gantt drawing hits two genuine
PyQt5-stub frictions: `QGraphicsScene.addText/addPath` are typed `Optional`
(never None in practice) and `mousePressEvent`'s arg is `QMouseEvent | None` in
the supertype. Rather than a blanket ignore, the module stays strict-clean with
*real* fixes -- a one-line `_scene_text` assert-helper concentrates the
Optional-narrowing, the path item is None-guarded, and the override takes the
nullable arg and early-returns. No `# type: ignore` was needed at all.

`qt_app.py` drops the `TimelineGanttView` class, the timeline widget assembly,
`_populate_timeline`'s body (now a delegate), `_timeline_item`,
`_timeline_activated`, the `timeline_*` minimum-height fix-ups, the two
module helpers, the `GANTT_MIN_HEIGHT` constant and the `timeline_tree` /
`timeline_gantt_rows` imports -- **2331 -> 2023 lines**. No behaviour change, no
test-count change (the view-switch test repointed at
`window.timeline_panel.view_combo`). Suite stays 386; mypy now checks 89 files.

**All four panels are now extracted** (universe / security / dependency /
timeline), each a typed `QWidget` with no ignore. What remains before the
blanket `# mypy: ignore-errors` on `qt_app.py` can actually be removed is the
residual main-window *shell* -- the toolbar/menus, the artifact list + graph
SVG widget, the inspector tables, the queries / source / evidence / compare
tabs, navigation and session -- which still carries the same Optional/enum
frictions and is the bulk of the file. Retiring the blanket ignore is therefore
a follow-up in its own right, not a free consequence of the panel split.

---

## D106 - Retire the blanket `# mypy: ignore-errors` on `qt_app.py`

The follow-up D105 flagged: with the four panels extracted, the residual
main-window shell was made to type-check under **mypy strict** and the blanket
`# mypy: ignore-errors` was deleted. Removing it surfaced **122 real errors**
(PyQt5 5.15 ships `.pyi` stubs, so the Qt types are real, not `Any`); all were
fixed -- *not* by scattering 122 per-line ignores, the noise D102 set out to
avoid, but by category:

- **~40 flattened-enum `attr-defined`** -> scoped enum access
  (`Qt.UserRole` -> `Qt.ItemDataRole.UserRole`, `QStyle.SP_*` ->
  `QStyle.StandardPixmap.SP_*`, `QProcess.NotRunning` ->
  `QProcess.ProcessState.NotRunning`, ...); both forms work at runtime in 5.15.
- **54 `union-attr`** on Optional Qt accessors -> one generic
  `_require(x: T | None) -> T` narrower (a single assert) wrapped around
  `menuBar()` / `horizontalHeader()` / `style()` / `statusBar()` /
  `QThreadPool.globalInstance()` / `bottom.widget(i)` / `list.item(i)` /
  `combo.view()` / `svg_widget.renderer()` / `scroll.viewport()` etc.
- **6 `override`** -> event handlers (`mousePressEvent` / `mouseMoveEvent` /
  `leaveEvent` / two `closeEvent`s) take the supertype's nullable arg with a
  guard.
- **12 `arg-type` from `RunSpec(**dict[str, object])`** -> the
  `_errata_run_kwargs` / `_verify_cpe_run_kwargs` helpers now return
  `dict[str, Any]`, so `**`-unpacking type-checks.
- the classic-runner `dict[str, object]` -> a `_ClassicRequest` `TypedDict`
  (fixing the `cwd`/`environment` `arg-type` and the `.exists()` `attr-defined`).
- the remaining handful -> `self.findings: list[Finding]`, two parameter
  annotations, `_current_bundle -> dict[str, Any]`, and a
  `Qt.TextInteractionFlags(...)` construction.

**Exactly one** `# type: ignore[arg-type]` remains -- connecting `QWidget.close`
(which returns `bool`) to a void `triggered` signal, an idiomatic PyQt pattern
the stubs reject; that is the "targeted ignore" the goal explicitly endorsed
over the blanket one. `qt_app.py` (now 2062 lines) type-checks under
`mypy --strict` with the rest of the package; no behaviour change (the asserts
narrow values that are never None here, enum scoping is runtime-equivalent, the
guards cover only the never-taken None branches) and the full suite stays 386.
The whole `gui/` package is now strict-typed -- no module carries a blanket
ignore.

---

## D107 - Workbench usability fixes (toolbar overflow, Enter, file load)

Field-reported regressions made the workbench "barely usable":

1. **Toolbar overflow.** The M3 security inputs (errata combo + feed, CPE dict,
   CVE feed) were appended to the single already-full toolbar, pushing the later
   widgets (Tests, search) into Qt's `>>` extension menu where they were hard to
   reach. Fix: the security feed inputs move to a **second toolbar row**
   (`addToolBarBreak()` + a dedicated "Security sources" `QToolBar` with
   `Errata` / `CPE dict` / `CVE feed` labels); the Source/SBOM fields shrink
   (320->240 / 240->180) and the primary row leads with explicit **Open** and
   **Analyze** action buttons (previously menu-only, so users fell back to
   Enter).
2. **Enter launched the classic subprocess.** `build_id` Enter was wired to
   `run_classic_build_pipeline` (D88) -- it shells out to `example--full.sh`,
   which needs the classic checkout + network + dnf/rpmkeys and dies with a scary
   subprocess dialog off an AlmaLinux host. Fix: Enter in `build_id` **and**
   `source` now runs the normal in-app analysis; the classic runner is an
   explicit **Run > Run Classic Pipeline** menu action instead of the default.
3. **Loading a build JSON didn't populate artifacts.** The loader prefers
   `build_id` over `source`, so a stale build id silently shadowed a chosen
   file, and `open_source` only filled the field without analysing. Fix:
   `open_source` clears the build id and **auto-runs** so the artifacts appear
   immediately; Enter-in-Source (`_analyze_source`) likewise drops a stale build
   id so "load this file" wins. (Verified there was no parse bug -- a cached
   build loads its real 90 RPMs through the service.)

+2 GUI regression tests (security inputs on a separate toolbar; a real cached
build loads into its actual RPMs, stale build id dropped). Suite 386 -> 388.

---

## D108 - Make the live errata.almalinux.org fetch actually work (and default)

"Why is errata shown as missing?" -- because the three-state default is
``not_checked``: no source had been consulted. D79/D94 built the `http` source,
but pointing it at the real feed surfaced three blockers, all now fixed so the
official feed *just works*:

1. **Default URL + version.** `errata_source="http"` with no feed/URL now
   defaults to the canonical AlmaLinux feed for the *build's own* distro:
   `almalinux_major_version(graph)` reads the dominant `.elN` token out of the
   RPM releases and `almalinux_errata_feed_url(version)` builds
   `https://errata.almalinux.org/<N>/errata.full.json`. The workbench toggle's
   feed field can stay blank.
2. **User-Agent.** `errata.almalinux.org` returns **403** to the default
   `Python-urllib` agent; `live_feeds._default_http_get` now sends a descriptive
   `User-Agent` (`HTTP_USER_AGENT`). (Helps the NVD feeds too.)
3. **macOS TLS.** macOS framework Python has no system CA bundle, so the fetch
   then failed `CERTIFICATE_VERIFY_FAILED`. The fetcher uses a **certifi**-backed
   `ssl` context when available (certifi is declared explicitly now, and already
   arrives via `requests`), falling back to the system store on Linux.

Plus an **all-architecture** scope for errata: the default enrichment selector
keeps only `x86_64`+`noarch` (right for the expensive header/payload rungs), so a
`ppc64le`/`aarch64` build's RPMs stayed `not_checked` even after consulting the
feed. Errata is build-wide security context and a cheap dict lookup, so the step
now checks every arch unless one is pinned. Our existing `_index_feed` parser
already handled the real `errata.full.json` shape (`{"schema_version","data":[
{id,type,severity,packages:[{name,epoch,version,release,arch}],references:[{id,
type}]} ]}`) unchanged.

Verified end to end against the live feed (build 17812, el9): the source is
consulted across all **90** RPMs and every one resolves to `confirmed_clean`
(its exact NEVRAs are newer than the advisories in the feed -- correctly *not*
falsely flagged; matching stays exact-NEVRA). +4 test cases (version inference,
URL builder, the http default-URL wiring, the User-Agent). Suite 388 -> 392.

---

## D109 - A mismatched build SBOM must not block analysis

Field-reported: with `Build id 57812` but a `build-57810` Source + SBOM still in
the fields, `_run_spec` raised "Build SBOM appears to be for build 57810, but the
current source is build 57812" and `run_analysis` turned that into a **modal that
stopped the whole run** -- so e.g. flipping the errata toggle and re-analysing
never happened, and the stale (errata-less) result stayed on screen.

The build SBOM is *auxiliary* evidence (it adds vendor CPEs); a mismatch should
never prevent loading the build. Two changes:

- `_autofill_build_sbom` now **re-discovers** when the current SBOM is for a
  different build than the one being loaded: it drops the stale one and looks for
  the right `build-<id>.cyclonedx.json`, so switching builds does not get stuck.
- `_run_spec` no longer raises on a surviving mismatch (e.g. a hand-picked SBOM):
  it **drops the SBOM with a log note and analyses anyway**.

Also a readability fix flagged in the same screenshot: the errata-source combo
was too narrow to read its selection ("Errata c..."). The "Errata" toolbar label
already gives context, so the items shorten to `off` / `http (almalinux.org)` /
`dnf (host)` with a minimum width, so the chosen mode is always legible. +1 GUI
regression test (a 57810 SBOM under build 57812 yields a RunSpec with the SBOM
dropped and the errata source still set). Suite 392 -> 393.

---

## D110 - run.sh template, source badges, and an Inspect-Build-Id menu

Three workbench-driving improvements requested together:

- **`run.sh` (full-inspection template).** A new top-level `run.sh <build_id>`
  runs a *complete* inspection pulling from every source the host supports --
  it fetches the ALBS metadata then runs `coverage` (with `--with-rpm-headers`,
  `--with-rpm-payloads` when zstandard is present, `--use-dnf
  --resolve-sonames` when dnf is present, `--verify-signatures` when rpmkeys is
  present, `--errata-source http`, and optional `--verify-cpe-url`) plus `vuln`,
  `license` and `slsa`, writing JSON artifacts to `OUT_DIR`. Env knobs
  (`ARCH` / `ALL_ARCHS` / `ERRATA_SOURCE` / `VERIFY_CPE_URL` / `CVE_FEED_URL`)
  parameterise it; the only required input is the build id. It is the focused
  production counterpart to the narrated `example--full.sh` demo.

  The workbench's old "Run Classic Pipeline" (which shelled out to
  `example--full.sh` in a separate *max* checkout via the `_classic_root` /
  `_ClassicRequest` machinery) is replaced by **`run_full_inspection`** ->
  `bash run.sh <id>` from this repo (this branch already ships the CLI), then
  loads the produced cache. The dead classic-checkout discovery
  (`_classic_root` / `_classic_sbom_file` / `_ClassicRequest` / the
  `ALBS_EXPLORER_CLASSIC_ROOT` env) is removed.

- **Status-bar source badges.** After a run, small coloured badges (`ALBS`,
  `SBOM`, `ERRATA`, `DNF`, `SIG`, `CPE`) appear in the status bar for exactly the
  external sources that run contacted; hovering a badge reveals the resource URI
  -- the live ALBS build URL, the SBOM path, the resolved
  errata.almalinux.org feed URL, etc. Built from the load/run spec stored when
  the analysis started.

- **`Run > Inspect Build Id…`.** A menu action that prompts for a build id and
  analyses it in-app (the fast path, no subprocess), so build-id inspection is a
  first-class menu entry, not only the toolbar field.

+2 GUI tests (badges reflect the contacted sources with URIs; the menu action
sets the build id, clears a stale source and starts an analysis). Suite
393 -> 395.

---

## D111 - Report a missing ALBS build plainly; run.sh report flags

Field-reported: inspecting build 57809 popped "ALBS HTML fallback for build
57809 did not contain build metadata". The ALBS API actually returns a clean
`404 {"detail":"Build with build_id=57809 is not found"}` -- the build just does
not exist (a valid build like 57810 fetches fine). The adapter treated *any*
non-200 as "API JSON unavailable" and fell through to the HTML fallback (D90/D93,
for when the SPA is up but the API is down), which then failed with that
confusing message. `fetch_build_metadata` now special-cases a **404**: it raises
the API's own "...is not found" detail (or a plain "build N not found") and never
touches the HTML fallback. +1 offline test (a 404 raises plainly and the
fallback URL is never fetched). The HTML fallback still covers genuine
API-unavailable cases.

Also fixed `run.sh`'s downstream report flags, found by running it live on el10:
`coverage` prints its report to stdout (no `--format`/`--output`; the cache is
written via `--cache`), `vuln`/`license` take `--format` only, `license`
requires `--rpm-licenses` (or `--sbom`), and `slsa` takes `--output`. run.sh now
pipes coverage/vuln/license through `tee` (shown in the GUI subprocess dialog and
saved) and the three downstream reports are best-effort (`|| echo …continuing`)
so one failing does not abort the inspection. Suite 395 -> 396.

---

## D112 - Fix graph hit-testing (the "barely clickable" nodes/edges)

Field-reported: clicking nodes/edges in the rendered graph barely reacted -- a
hit registered near the top-left but almost nowhere else. Root cause: the
clickable image map and the SVG are two `dot` renders of the same graph in
*different coordinate spaces*. Graphviz emits SVG in 72-dpi **points** (the
`viewBox` is e.g. `0 0 1897 554`) but `cmapx` at ~96 dpi (its regions ran to
~2496x704). `GraphSvgWidget` maps a click into the SVG's point space and tests
it against the cmapx regions, so the ~1.3x-larger regions only overlapped near
the origin -- hence "sometimes hits, mostly not".

Fix: render the image map at the SVG's dpi -- `_run_dot(dot, "cmapx",
"-Gdpi=72")` (`_run_dot` now takes extra dot flags). The regions then share the
SVG's point space (measured: `25..1872 x 25..528` inside `1897x554`), so the
existing click transform lines up and every node/edge is reliably clickable. +1
test (graphviz-gated) asserting all region coordinates fall within the SVG
viewBox. Suite 396 -> 397.

---

## D113 - Inspect Binary action (host-RPM-gated)

A `File > Inspect Binary (RPM)…` action that picks a local `.rpm` and runs the
CLI `inspect-rpm` on it (package/provide/require + header facts) in the existing
subprocess console dialog. It is **enabled only on an AlmaLinux / RHEL-family
host with rpm** -- `_is_almalinux_family_host()` checks `shutil.which("rpm")`
plus the `/etc/os-release` `ID` / `ID_LIKE` tokens against
`{almalinux, rhel, centos, rocky, fedora, el}`. On macOS / other distros the
action greys out with an explanatory tooltip rather than failing at click time.
The os-release parsing is split into a pure `_os_release_ids` for testability.
+1 test (the EL-family recognition + the no-rpm greyed-out case). Suite
397 -> 398.

---

## D114 - Interactive, cache-aware source badges (click a source to fetch it)

Field request: the status-bar badges should not just *report* what a finished
run happened to contact (D110) -- they should **represent each build-id source,
grey out when its data is stale or absent, and fetch that one source on click**.
"Build id + Enter fetches everything in sequence; build id + click on a badge
fetches just that resource."

This **supersedes the static-badge bullet of D110**. The badges are now
persistent, clickable `QToolButton`s created once for the three sources that a
build id alone can pull:

- **ALBS** -- the build metadata. State comes from the on-disk metadata cache
  (`_workbench_cache_path`, the same `INSPECTION_TMP_ROOT/build-<id>/` convention
  `run.sh` uses): a pure `_cache_file_state` returns `active` (fresh JSON whose
  embedded id matches), `stale` (present but older than the TTL) or `missing`
  (absent / wrong build id) -- the same guard `fetch_build_metadata` applies. To
  give the badge a file to probe, `_load_spec` now caches build-id fetches under
  that path; a click sets `refresh_cache` to force a refetch.
- **ERRATA** -- `active` once the result graph carries `errata` nodes, else
  `missing`; a click selects the `http` errata source (the default
  errata.almalinux.org feed) and re-runs.
- **SBOM** -- `active` when `discover_build_sbom` (D78) finds a
  `build-<id>.cyclonedx.json`, else `missing`; a click clears the field to
  re-discover by convention.

Greying = amber for a stale cache, grey for missing; the tooltip carries the
resource URI plus a one-line "click to fetch / refresh" hint. The badges
recolour on every build-id keystroke and after each run. `DNF` / `SIG` / `CPE` /
`CVE` are **not** in the row -- they need host tooling or an external dictionary,
not a build id, so they stay toolbar-driven enrichments (visible in the log and
the Security panel). `Enter` in the build-id field now calls `_fetch_all_sources`
(turn the optional sources on, one sweeping run); a badge click calls
`_fetch_source` (that source only, additive). The now-unused `_last_load_spec` /
`_last_run_spec` handles were dropped. +1 net GUI test (cache-state probe +
click-fetch guard; the old contacted-sources test was rewritten). Suite
398 -> 399.

---

## D115 - A build-id fetch-all pulls every host-available enrichment in-app

Field report: typing a build id and pressing Enter did not reproduce the rich
result a `run.sh` full inspection produces -- "there must be a way that allows
the GUI to fetch all data for a given build id." (The triggering screenshot used
build 17811, which genuinely 404s; 17812 is the committed fixture. The reported
"not found" is correct, D111.)

A build-id fetch-all (Enter, `_fetch_all_sources`) now sets a one-shot
`_deep_fetch` flag that `_run_spec` consumes to merge
`_host_enrichment_kwargs()` into the `RunSpec`: **RPM headers always** (an HTTP
range read, light), plus **`dnf` repoquery + soname resolution** and **`cas`
authentication** *only when the host tool is present* (`shutil.which`), so the
run degrades gracefully off an AlmaLinux box -- the same gating `run.sh` uses.
This is on top of the always-present ALBS base load, the errata(http) default
and SBOM autodiscovery, so one keystroke pulls everything the host can.

The two **heavy full-RPM-download rungs are deliberately excluded** from the
one-keystroke path -- payloads/ELF (rung 4) and signature `--checksig` -- as is
SBOM *generation* (`alma-sbom`); those remain in `Run > Run Full Inspection
(run.sh)`. The flag is captured-and-cleared at the top of `_run_spec` (and on the
`run_analysis` `ValueError` path) so a later plain run stays light. The richest
fully-automatic path is still `run.sh` (it adds the heavy rungs + generates the
SBOM); the in-app fetch-all is the snappy "as much as this host can" version.

Also in this change: the Timeline **Tree/Gantt view switch** was rendering
clipped to "Ga" in a narrow dock -- `view_combo` got a `setMinimumWidth(96)` +
`AdjustToContents`. And the README workbench screenshot caption was refreshed
(trust path + errata/CVE + the live source badges) and the stale "live errata
fetch is still future" limitation corrected (it shipped in D108). +2 GUI tests
(fetch-all merges the host enrichments + resets; the view combo is not clipped).
Suite 399 -> 401.

---

## D116 - The primary Analyze action fetches all for a build id

Follow-up to D115. The sparse result in the field screenshot came from the
toolbar **Analyze** button (and `Ctrl+R`), which ran a plain `run_analysis`
(errata off, no enrichment) -- only Enter triggered the fetch-all. The Analyze
action is now context-sensitive (`_analyze_or_fetch_all`): a live **build id ->
`_fetch_all_sources`** (every host-available source), a cached **source file ->
a plain offline run**, so working from a local `.albs.json` never triggers a
surprise network pull. `_select_errata_http` was tightened to respect an
explicit errata choice -- it only switches `off -> http`, never clobbering a
host `dnf` selection. +1 GUI test (build id fetches all, cached file stays
light + does not override errata). Suite 401 -> 402.

---

## D117 - Errata default is host-aware: dnf on AlmaLinux, http elsewhere

When a fetch-all turns errata on it now picks the source the host is best placed
to answer with, rather than always the HTTP feed: `_default_errata_source()`
returns **`dnf`** on an AlmaLinux / RHEL-family host with `dnf`
(`shutil.which("dnf") and _is_almalinux_family_host()`) -- the local
`dnf updateinfo` is the authoritative, already-configured advisory source there
-- and **`http`** (errata.almalinux.org) otherwise (e.g. macOS, where there is
no `dnf`). `_select_default_errata` applies that default but still respects an
explicit combo choice (only switches from `off`), and the ERRATA badge tooltip
reads `dnf updateinfo (host)` when dnf is selected. The combo's startup default
stays `off` so the offline synthetic-fixture launch never reaches for the
network. +1 GUI test (the host-aware default both ways + the explicit-choice
guard); two badge/analyze tests pin `_is_almalinux_family_host -> False` so their
`http` assertions are host-independent on an AlmaLinux CI box. Suite 402 -> 403.

---

## D118 - A missing build is "not found", not "Analysis failed"

Field report ("pobranie po numerze builda sie wali"): entering build 57809 popped
a red **Analysis failed**. But 57809 genuinely does not exist -- ALBS build ids
are **sparse**, not sequential (verified live: 57808/57809/57811 -> HTTP 404,
57810/57812 -> 200). The fetch worked; the id was empty. The scary "failed"
framing (plus the previous build's graph still on screen) read as a tool crash.

`fetch_build_metadata` now raises a dedicated **`BuildNotFoundError`** on a 404
(a `ValueError` subclass, so every existing `except ValueError` and the D111
"report a 404 plainly" behaviour keep working). The GUI worker catches it and
emits a separate **`build_not_found`** signal carrying the id; the window's
`_build_not_found` handler shows a calm status ("Build 57809 not found") + an
**information** dialog that explains ids are sparse and to check
build.almalinux.org -- *not* the red failure path. The previous result stays so
the user does not lose their place. +2 GUI tests (the worker routes
`BuildNotFoundError` to `build_not_found`; the handler is informational, not a
failure) and the albs 404 test now asserts the `BuildNotFoundError` type.
Suite 403 -> 405.

---

## D119 - Errata cross-check: web feed vs dnf, mark the advisories both confirm

Manual errata toggling (off / http / dnf) and the host-aware default (D117)
already let you choose a source. The new ask: an **option to cross-check the
two and mark when they agree**. AlmaLinux publishes advisories twice -- the
`errata.almalinux.org` feed and the host `dnf updateinfo` -- so corroboration
across both is a real signal that an advisory match is correct.

A fourth errata mode **`both`** consults *both* sources and records, per
(RPM, advisory), which sources reported it:
`attach_errata_cross_checked(graph, sources)` writes `sources=[...]` and a
`cross_checked` boolean onto **both the ERRATA node and the per-RPM `FIXES`
edge** -- `True` when >= 2 sources agree, `False` for a single-source
discrepancy. An RPM every consulted source agrees is advisory-free is
`confirmed_clean` with `errata_cross_checked=True` (a corroborated clean). The
unified `_attach_advisory` carries the sources tuple + optional flag, so the
single-source path is byte-for-byte unchanged. It **degrades gracefully**: if
dnf is unreachable the cross-check runs on the feed alone (nothing is marked
corroborated). The three-state contract (advisory_present / confirmed_clean /
not_checked, D79) is untouched -- cross-check only *adds* metadata.

`ErrataSourceStep` grows a `both` branch; `RunSpec.errata_source` accepts
`"both"` (no model change). In the workbench the errata combo gains
**"both (cross-check)"**, the Security panel's Errata cell shows a
`[x-checked]` suffix when the two agreed, the ERRATA badge tooltip reads
"web feed + dnf updateinfo (cross-checked)", and the node/edge inspector shows
the `cross_checked` + `sources` metadata. +5 cases (agreement + single-source +
corroborated-clean + graceful degrade + the step's `both` routing; the GUI
option feeds the RunSpec). Suite 405 -> 410.

---

## D120 - A cached catalog of real build numbers (browse + autocomplete)

The recurring sparse-id pain (D118: 57809/17811 do not exist) has a structural
fix: **don't make the user guess**. ALBS exposes a list endpoint
(`/api/v1/builds/?pageNumber=N` -> `{builds: [...]}`, ~10 newest per page), so
the workbench can offer real, existing ids to pick from.

`adapters.albs` gains `fetch_build_list` + `parse_build_list` + a `BuildSummary`
(build id, created/finished, owner, source packages from the tasks' git/SRPM
refs, platforms). A `services.BuildCatalog` persists these as a small JSON db
under `default_cache_root()` (`~/.cache/albs-provenance-explorer/`,
`$ALBS_HTTP_CACHE`-overridable), upsert-by-id, newest first, tolerant of a
missing/corrupt file (-> empty, never fatal). The GUI:

- a **Builds menu** -- *Browse Builds…* (a `QInputDialog` picker of
  `id  package  platform  date`, which fills the build id and analyses it) and
  *Refresh Build List from ALBS* (fetch the recent page, merge, save);
- a **`QCompleter`** on the build-id field seeded from the catalog (MatchContains)
  so a real id is a keystroke away;
- **record-on-analysis**: a build the user actually analyzed is upserted into the
  catalog (so it stays even after it ages off the recent page).

Startup stays offline (the catalog loads from disk; refresh is an explicit
action). +7 cases (parse/fetch via injected requests; catalog merge/record/load
tolerance; the GUI refresh feeds the completer; browse picks an id and runs). An
autouse fixture points `$ALBS_HTTP_CACHE` at a temp dir so a test analysing a
build never writes the developer's real `~/.cache`. Suite 410 -> 417.

---

## D121 - Build catalog: a filterable list, time-sorted, configurable last-N

Follow-up to D120. Browsing was a plain `QInputDialog` dropdown of one page
(~10) of builds. Three improvements, on request:

- **A filterable list with a short description.** `_BuildPickerDialog` is a
  `QListWidget` where each row reads `<id>   <package>[ +N]   <platform>
  <YYYY-MM-DD HH:MM>   · <owner>` (`_describe_build`), with an in-place filter
  over id / package / platform / owner and double-click-to-open. `browse_builds`
  routes through `_pick_build` (the dialog) so it stays headlessly testable.
- **Sorted by build time.** `BuildCatalog.load` now sorts by `created_at`
  descending (falling back to the build id, which tracks time, for a recorded
  build with no timestamp); `_record_analyzed_build` preserves a build's known
  `created_at` so upserting one you analyzed does not drop it down the list.
- **Configurable last-N.** `fetch_recent_builds(base_url, limit=N)` pages the
  10-per-page list endpoint until N builds are collected (de-duped, newest
  first; first-page error propagates, a later-page error keeps the partial,
  with a hard page cap). The Builds menu's **Refresh from ALBS ▸ Last
  50 / 100 / 200 / 500** picks N and remembers it (`build_list_limit`,
  default 100).

The fetch stays synchronous behind a wait cursor -- an explicit, bounded
action. +2 cases (the paging stops on a short page + caps at the limit; the
picker describes + filters in place). Suite 417 -> 419.

---

## D122 - Start launcher, verified build-id entry, identifier badges

Three connected entry/identity improvements, on request.

**A start launcher.** A bare launch (no `--source` / `--build-id`) now opens
`_StartDialog` instead of auto-loading: *Open Saved Session*, *Inspect by ALBS
Build ID*, *Inspect by ALBS Build ID (choose from list)*, *Inspect by ALBS file
(build metadata JSON)*, *Inspect by ALBS package (local RPM)*, and *the offline
demo (synthetic fixture)*. `_dispatch_start_choice` routes each to its existing
entry point; the package option greys out off an AlmaLinux host (same gate as
Inspect Binary, D113). It is also reachable any time from **File ▸ Start…**.
`entry.py`'s `--source` default dropped to `None` so the launcher, not the
synthetic fixture, is the bare-launch default.

**Verified build-id entry.** *Inspect by ALBS Build ID* takes an **arbitrary
number** and **verifies it against ALBS up front** -- `fetch_build_summary`
(the per-build detail endpoint, summarised by the list parser) returns the
build's name/desc, so `_InspectBuildIdDialog` shows e.g. "Verified: 57810
nghttp2 +12  AlmaLinux-10" and only enables *Inspect* once verification
succeeds; a 404 reads "not found", editing re-locks it. The cached catalog
(D120) answers instantly; an unknown id is verified live and recorded.

**Identifier badges.** The status-bar badges now name their source inline:
**ALBS: \<build-id\>** (always, so you can see which build a grey/active badge
is for), **SBOM: \<serial-hash or build-id\>** and **ERRATA: \<advisory count\>**
once present. +6 cases (fetch_build_summary verify + 404; the launcher options +
dispatch + host gating; the verify-before-enable dialog; catalog-then-live
verification; the badge identifier text). Suite 419 -> 425.

---

## D123 - Build-list fetch shows live progress in the status bar

A "last N" refresh (D121) pages the list endpoint synchronously (up to 50 GETs
for 500), which looked frozen with only a static "Fetching…". `fetch_recent_builds`
now takes an `on_progress(fetched, limit)` callback (alongside the textual
`progress` log one), called after each page; `refresh_build_list` feeds it
`_build_fetch_progress`, which writes **"Fetching builds… 30/100 (30%)"** to the
status bar and `processEvents()` so it repaints mid-loop. A `_refreshing_builds`
guard ignores re-entrant clicks while a fetch is in flight. +1 case (the counter
+ percentage text). Suite 425 -> 426.

---

## D124 - Timeline: no column overlap; clicking a node reveals it

Two timeline fixes.

**Column overlap.** The Timeline tree's long "Stage" labels (e.g.
`build_done_stats.logs_processing`) overflowed into "Status" because
`resizeColumnToContents` ran before the panel was laid out and under-sized
column 0. Column 0 is now `ResizeToContents` (auto-fits its content, indentation
included) and the tree elides (`ElideRight`), so columns never overlap.

**Reveal on click.** Clicking a graph node now also locates it in the timeline:
`TimelinePanel.reveal_node(node_id)` selects + scrolls the tree
(`QTreeWidgetItemIterator` find, `scrollToItem` centred) and centres the Gantt on
the matching row (`TimelineGanttView.reveal_node` scans the scene items by their
stored node id). `_graph_node_clicked` calls it after `_show_node`; an
off-timeline node is a no-op. +2 cases (column 0 resize/elide; a fixture node
reveals + an off-timeline node is safe). Suite 426 -> 428.

---

## D125 - Badges: errata NET/DNF, a CAS badge, an AlmaLinux host badge

On request, the status-bar badges (D114/D122) gained source identity.

- **ERRATA names its source**: `ERRATA: NET` (errata.almalinux.org feed) /
  `ERRATA: DNF` (host updateinfo) / `ERRATA: NET+DNF` (cross-check), derived from
  the attached errata evidence's `source` metadata when present, else the combo
  selection (`_errata_source_label`).
- **A CAS badge**, added only when the `cas` tool is on the host
  (`shutil.which("cas")`). It greys out until CAS attestations are *externally
  verified* (`externally_verified` on the `cas_attestation` nodes), then shows
  `CAS: <count>`; clicking it sets a one-shot that runs with `use_cas=True`.
- **An AlmaLinux indicator badge**, last on the right, shown only on an
  AlmaLinux / RHEL-family host (`_is_almalinux_family_host`) -- a static label,
  not a source.

The badge set is now host-dependent, so a `_baseline_host` autouse test fixture
pins `shutil.which -> None` (no cas, real `_is_almalinux_family_host` -> False)
for deterministic construction regardless of the CI box; the new test overrides
it to assert the CAS + AlmaLinux badges and the NET/DNF/NET+DNF errata labels.
+1 case. Suite 428 -> 429.

---

## D126 - Show the log while fetching; errata "checked-clean"; dedup CVE edges

Three field-reported fixes.

- **Switch to Log on fetch.** When an analysis starts, `run_analysis` now selects
  the bottom **Log** tab so the user watches the progress stream live instead of
  a stale results table.
- **ERRATA badge: checked vs not-fetched.** The badge greyed out whenever no
  advisory matched -- even though errata *was* consulted and the build is simply
  clean (confirmed_clean). It is now **active once errata was consulted**
  (`_errata_consulted`: any errata node *or* any RPM with an `errata_status`),
  and reads `ERRATA: NET (clean)` / `ERRATA: NET (3)` so "checked, none" no
  longer looks like "not loaded". (SBOM staying grey is correct -- the GUI cannot
  synthesise a build SBOM; that needs `alma-sbom` / run.sh.)
- **Dedup advisory→CVE edges.** `_attach_advisory` added the `errata -> cve`
  `FIXES` edge on every call, i.e. once per RPM the advisory ships -- so a CVE
  fixed by an advisory covering N RPMs sprouted N identical edges (dozens
  converging on one red CVE node). The advisory→CVE edge (and the rpm→errata
  edge) is now added once, guarded by `_has_fixes_edge`. +3 cases (the Log
  switch; the consulted-clean badge; one advisory over two RPMs -> a single
  CVE edge). Suite 429 -> 432.

---

## D127 - Clicking a node actually scrolls the Gantt to it

The D124 reveal centred the Gantt with `centerOn` -- but the Gantt was usually
the hidden sub-view (size 0) or in a non-active bottom tab when a graph node was
clicked, so the scroll never took. Reworked to be reliable:

- the Gantt keeps a `node id -> row-label item` map and a **`_pending_node`**
  that is (re)applied via `ensureVisible` on **`showEvent` / `resizeEvent`**, so
  the scroll lands once the view gets its real size;
- `TimelinePanel.reveal_node` now **switches the Tree/Gantt switch to Gantt** and
  calls `scroll_to_node` (recording the pending target);
- `_graph_node_clicked` **brings the Timeline tab forward** when the node is on
  the timeline, so the Gantt is visible for the scroll. A Gantt mouse press
  clears `_pending_node` (the user is navigating), so a later window resize does
  not yank the view back. The D124 reveal test was strengthened (sub-view switch
  + pending target + the wired tab-forward); no net test-count change.

---

## D128 - Rich colour in the GUI subprocess console dialog

"Use Rich everywhere there is console output." The CLI (`cli/main.py`,
`demo_verbose.py`) already does -- `console.print` + Rich tables + markup for
humans, plain `json.dumps` to stdout for pipes. The gap was the **workbench's
`ConsoleProcessDialog`** (run.sh / inspect-rpm / inspect-binary): a `QProcess`
is a pipe, so Rich dropped the colour and the dialog showed plain text.

Now the dialog runs the subprocess with **`FORCE_COLOR=1`** (Rich emits ANSI
even down a pipe) and `COLUMNS=160`, switches its widget to a `QTextEdit`, and
renders the accumulated output as **coloured HTML** inside a `<pre>` via a new
pure `gui/ansi.py::ansi_to_html`. That converter turns SGR sequences (reset,
bold, italic, underline, the 16 basic foreground colours + 256/truecolour) into
`<span>`s, HTML-escapes the text, and strips other control sequences (cursor
moves, line clears, `\r`, OSC) so progress redraws do not pile up. +7 cases
(the converter: basic colours / reset+attrs / HTML-escape / stripping /
256+truecolour / plain passthrough; the dialog forces colour + renders ANSI as
HTML). Suite 432 -> 439.

---

## D129 - Centre the graph on the highlighted node

Mirrors the timeline reveal (D127) for the graph: when a node is highlighted
(navigated to from a table / finding / search / slice list), the graph view
**scrolls to centre it -- but only when the graph does not already fit the
viewport**. `NodeRegion.center()` gives a region's centre in SVG coordinates;
`GraphSvgWidget.node_center` maps it to widget coordinates (the inverse of the
hit-test scaling); `_load_svg` then defers `_do_center_graph_on_selected_node`
(via `singleShot(0)`, so the scroll area's scrollbar ranges have updated after
the widget was resized), which `ensureVisible`s the node's centre with
half-viewport margins (centred, clamped at the edges). It is a no-op when the
graph fits, nothing is selected, or the widgets are gone (guarded for test
teardown). +3 cases (`NodeRegion.center` rect/circle/poly; `node_center` maps
SVG->widget; the centre call is safe without a render). Suite 439 -> 442.

---

## D130 - Gantt timeline: scale to the short majority, clip the long tail

The build-task Gantt fitted its time scale to the *longest* row
(`span = max(offset + duration)`), so a single long sign/build task squashed
every few-minute step into an invisible sliver, and the stage-name text items
(drawn onto the scene with no eliding) overran the status column. Reworked the
`TimelineGanttView` rendering:

- **Duration bars from a shared baseline.** Each row's bar now starts at the same
  left edge and its width is the row's own duration, so the eye compares how long
  each step took rather than where it sat on the absolute wall clock (the precise
  start/finish stays in the Tree view and in the bar's tooltip).
- **Scale fitted to the majority.** `_duration_scale` takes a high percentile
  (`_SCALE_PERCENTILE = 0.90`) of the durations as the display cap, so ~90% of
  the (short) tasks fill a readable share of the width. Bars longer than the cap
  clip to the full width, are flagged with a "…", and show their real duration
  past the end; the axis suffixes its last tick `+` and prints a note ("scale
  fitted to X · N longer task(s) clipped (max Y)").
- **Elided columns.** `_elided_text_item` right-elides the stage name and the
  status to fixed pixel budgets, so a long `build_done_stats.*` label can never
  overwrite the status column; the full text + timing moves to the row tooltip.
- **Tracks the window.** The timeline width is derived from the viewport (not a
  fixed 920px canvas) and the chart re-lays-out on show/resize, so it fills the
  window instead of forcing a horizontal scroll. The reveal-on-click scroll
  (D127) still re-applies after a relayout (the row is looked up by node id).

+3 cases (the percentile cap fits the bulk + flags the clip count; long names
elide with "…"; the columns never cross into the status column and the bars stay
in the band). Suite 442 -> 445.

---

## D131 - Gantt default, clip-note placement, and a status-bar step counter

Follow-ups to D130 from using it on a real build:

- **Gantt is the default timeline sub-view.** The graph<->timeline jump is the
  main way the timeline is used (click a node on the graph and it scrolls the
  Gantt to that task/step; click a Gantt bar and the graph navigates + centres on
  the node), so the panel now opens on the Gantt instead of the Tree (which stays
  one click away for exact per-step start/finish times). The reveal/jump wiring
  was already two-way (`_graph_node_clicked` -> `reveal_node`; the Gantt's
  `nodeActivated` -> `_navigate_to_node`); defaulting to the Gantt just makes it
  land where the user is looking.
- **Clip note moved off the axis labels.** D130's "scale fitted to X · N longer
  task(s) clipped (max Y)" caption sat on the same band as the axis tick labels
  and overwrote "0.00s". The top band was enlarged (`_TOP` 42 -> 64) so the note
  gets its own line at the very top and the tick labels sit just above the axis
  line, clear of it.
- **Status-bar step counter.** A long fetch/enrich run showed a frozen
  "Analyzing…". The window now also feeds the pipeline's `on_progress` stream
  (the same one the log gets) to `_analysis_progress`, which keeps a running
  count and shows "Analyzing… step N: <latest message>" -- and the messages
  already carry the quantities ("build SBOM matched 456 RPMs", "analyzed N ELF
  objects"), so the counter doubles as a processed-items readout.

+3 cases (the Gantt is the default sub-view; the clip note no longer intersects
the tick labels; the status bar shows a growing step counter). Suite 445 -> 448.

---

## D132 - Remember the window size/position across runs

The workbench opened at a fixed default size every launch. It now persists its
geometry with `QSettings`: `_save_window_state` writes `saveGeometry()` +
`saveState()` in `closeEvent`, and `_restore_window_state` (called at the end of
`__init__`, after the toolbars/dock exist) restores them, so the size, position,
maximised/fullscreen state and the toolbar/dock layout come back on the next
launch. The two toolbars and the bottom dock were given `objectName`s so
`saveState()` can address them; the state carries a version (`_WINDOW_STATE_VERSION`)
to bump if that structure changes.

`QSettings` is constructed with `IniFormat` / `UserScope` so the store is
redirectable -- on macOS it lands under `~/Library/Preferences`, on Linux under
`~/.config`, and the tests point it at a temp dir (`_isolate_qsettings`) so a run
never touches the developer's real preferences. Missing or foreign values (first
run, a future version bump) are ignored, leaving the default geometry. +1 case
(geometry saved on close is restored by the next instance). Suite 448 -> 449.

---

## D133 - Timeline search/filter

The build timeline can run to many hundreds of rows, so the panel got a live
filter: a `QLineEdit` on the **left** of the header row (at the height of the
Gantt/Tree switch, which stays on the right). Typing filters **both** views to the
matching rows, case-insensitively, over each row's stage label / status / kind /
node id / detail:

- **Gantt:** `TimelineGanttView.set_filter` stores the query and re-lays-out from
  `_visible_rows()` (the matching subset); the time scale is fitted to the visible
  rows, and an empty result shows "No matching timeline rows".
- **Tree:** `_filter_tree_item` recurses depth-first and hides a row unless it (or
  a descendant) matches, so a matching child step keeps its parent task visible
  rather than being orphaned under a hidden parent.

`populate` resets the filter so a fresh build starts unfiltered. +2 cases (the
Gantt keeps only matching rows, case-insensitive + trimmed; the panel search
hides non-matches in both views and clearing restores them). Suite 449 -> 451.

---

## D134 - On-demand CVE details in the inspector

A `cve` node carried only its id (+ a `severity` from errata). The inspector grew
a **CVE** tab with a *Show CVE details* button: selecting a CVE node enables it
(and brings the tab forward), and clicking fetches a human-readable record off the
UI thread and renders the description, CVSS and references (clickable links).

- **Source (`security/cve_details.py`).** `fetch_cve_details(cve_id, *, fetcher)`
  tries the **NVD** CVE 2.0 API first (`parse_nvd_cve`: English description, CVSS
  v3.1/3.0/2 score+severity+vector, references); when NVD has nothing usable it
  falls back to **OSV** (osv.dev, `parse_osv_vuln`), which aggregates AlmaLinux
  (ALSA) advisories and CVEs. Both route through the shared `HttpCache` and reuse
  the live-feed GET (macOS-safe SSL + descriptive User-Agent). Canonical NVD +
  AlmaLinux page links are always appended, so even fully offline the tab still
  hands the user somewhere to go. The fetcher is injectable, so the parsers and
  the NVD-first / OSV-fallback logic are tested entirely offline.
- **GUI (`gui/cve_details.py` + `qt_app`).** `CveDetailsView` is a dumb widget
  (emits `fetchRequested`, renders a `CveDetails`); the window runs the fetch in a
  `CveDetailsWorker` (QRunnable on the thread pool) and feeds the result back,
  detaching the worker's signals on close like the analysis worker.

+7 cases (the NVD/OSV parsers; NVD-preferred + OSV-fallback + offline-degraded
fetch; the view enables/requests/renders; the window wires the CVE tab). Suite
451 -> 458.

---

## D135 - Graph frame colour + quiet the macOS accessibility noise

Two small GUI papercuts from real use:

- **No colour seam around the graph.** The global stylesheet painted the graph's
  `QScrollArea` (and its viewport) the panel colour, so a colour seam showed
  around the SVG whenever the graph did not fill the view. `render.graph_background(dark)`
  now exposes the graph canvas colour (`#171A1F` dark / `#FFFFFF` light, the
  SVG's own `bgcolor`), and `_apply_style` paints the scroll area + viewport +
  SVG widget that colour so the frame and the graph are one continuous surface.
- **Quiet the macOS Qt accessibility warnings.** Clicking the Security/CVE tables
  spammed stderr with `QCocoaAccessibility … invalid element` /
  `QAccessibleTable::child: Invalid index at: -249` -- a known Qt 5 macOS
  accessibility bug, harmless but noisy. `run()` installs a
  `qInstallMessageHandler` that drops exactly those messages
  (`_is_qt_accessibility_noise`) and forwards everything else, so real warnings
  still show and the accessibility bridge stays enabled.

+3 cases (`graph_background` matches the theme; the frame is painted the graph
colour; the a11y noise is filtered while a real warning passes). Suite 458 -> 461.

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

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

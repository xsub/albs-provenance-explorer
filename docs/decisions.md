# Decisions

This document records the architecture and design decisions made while extending
`albs-provenance-explorer` from a read-only metadata explorer toward a
**maximal, conflict-aware provenance + dependency graph** over ALBS data.

All work landed on branch `max` in two commits:

- `1339b8e` — conflict-aware dependency reconciliation, resolver contract, coverage axes.
- `f5b6bdd` — public-data rungs: RPM header range reads, linkage claims, `coverage` CLI.

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

## D1 — "Could not resolve" is a first-class outcome

**File:** `albs_graph/dependency/model.py`

Added `ResolutionState.UNRESOLVABLE`, `AMBIGUOUS`, `RESOLUTION_SKIPPED` and a
`resolution_note` field on `DependencySpec`.

**Why.** A tool that only ever reports success lies about its coverage. A failed
or skipped resolution must be distinguishable from a merely `DECLARED` one, and
must carry *why* (e.g. "uv: no version of X satisfies >=9999"). Downstream
consumers (security, compliance) need to know which trees are evidence-only.

---

## D2 — Model the disagreement (do not collapse evidence)

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
resolved tree, reproducibility reads the lockfile-vs-artifact triple — one
graph, three projections.

---

## D3 — Typed resolver contract; never reimplement a solver

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

## D4 — Five-axis coverage with honest residue

**File:** `albs_graph/provenance/coverage.py`

`coverage_report(graph)` computes orthogonal axes: `resolution`, `linkage`,
`identity`, `provenance`, `security_context`. `identity` counts only
**verified** CPEs (unverified candidates deliberately do not count).

**Why.** "All three consumers equally" means no axis may be sacrificed. A sparse
graph honestly reports low coverage on axes nothing has fed yet (today: linkage,
identity, resolution) while provenance stays high. The report is the deliverable;
the residue is part of it.

---

## D5 — The cost ladder, and choosing rung 3 for public access

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
no ELF parse** — only the first tens of KB of the file. `repo.almalinux.org` /
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

## D6 — `PRESENCE_UNDECLARED` requires subject-level declaration context

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

## D7 — The reconciler does not evaluate version ranges

`reconcile.py` detects only cross-source disagreement it can establish soundly:
`VERSION_DRIFT` (different concrete versions, exact inequality), `LINKAGE_MISMATCH`
(static vs dynamic), `PRESENCE_UNDECLARED` (set logic). `RANGE_VIOLATION` is
surfaced only when a resolver **asserts** it via a `range_satisfied=False` claim
flag.

**Why.** Deciding whether `3.0.9` satisfies `>=3.2` is per-ecosystem version
math — the authoritative resolver's job (D3). Doing it in the reconciler would
re-introduce exactly the solver-reimplementation mistake we are avoiding.

---

## D8 — Reported ≠ verified stays labelled

Every fact carries the provenance of *how* it was established:

- Header sonames are tagged `evidence="rpm_header_soname"` — RPM's recorded
  dependency facts, not an independent ELF parse.
- CAS hashes remain `externally_verified: false` until an explicit `cas` step
  records verification.
- CPE stays `null` with unverified `cpe_candidates`; the identity coverage axis
  counts only verified CPEs.

**Why.** "We maximized coverage" must never silently mean "we asserted things we
didn't check."

---

## D9 — CycloneDX-from-file SBOM claims

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
artifact `alma-sbom` produces) rather than fabricating a fetch — the tractable
step under current public access.

Two reconciler refinements were required to make SBOM + header evidence coexist
honestly:

- **`"sbom"` evidence is classified `resolved`, checked before the `"bom"`
  artifact token** — otherwise "sbom" would be mis-read as ELF binary analysis
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

## D10 — Rung 4: full payload ELF analysis

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
  decompresses real artifact bytes — the deliberate step beyond the PoC's
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

## D11 — Optional, crash-proof CAS verification (`--use-cas`)

**Files:** `albs_graph/adapters/cas.py`, `cli/main.py` (`coverage --use-cas`),
`example--almalinux.sh`

CAS verification is strictly opt-in and never required. The `cas` binary is
frequently uninstallable now (Codenotary changed product lines; the public
installer/releases 404), so `verify_hash` / `verify_graph_cas` return a recorded
`unavailable` status instead of raising, and `example--almalinux.sh` no longer
`exit 1`s when `cas` is missing — it reports the ALBS hashes and skips
verification with a clear "reported, not verified" note.

Only a successful `cas authenticate` flips a CAS node's `externally_verified`
from false to true — the single sanctioned place to assert CAS evidence was
independently verified, per the "reported, not verified" rule. The runner is
injectable so the whole path is tested offline without the binary.

---

## D12 — AlmaLinux-native resolution via `dnf repograph` / `rpmgraph`

**Files:** `albs_graph/adapters/rpmgraph.py`, `provenance/trust.py`
(`make_binary_rpm_selector`), `cli/main.py` (`coverage --repograph-dot` + arch/
package selectors)

`dnf repograph` (dnf-plugins-core) and `rpmgraph` (rpm) ship on AlmaLinux and
emit a package dependency graph in Graphviz dot — a *real* RPM resolution via
libsolv/rpm, i.e. rung 5 for the RPM ecosystem using the authoritative tooling
rather than a reimplemented solver. The adapter parses dot edges and emits
resolved dependency claims (`evidence="repograph"`/`"rpmgraph"`,
`resolution_state=RESOLVED`, namespace `almalinux` so they align with ALBS PURLs
and reconcile against SBOM claims). NEVRA node labels yield a version (counts
toward the resolution axis); bare names do not.

Sub-decisions:

- **dot-ingest is the tested path; live run is host-only.** `--repograph-dot
  FILE` ingests output the user generated on an AlmaLinux host
  (`dnf repograph --repo appstream > repo.dot` — repo via `--repo`, not a
  positional argument), so the parser is fully
  offline-testable. `run_repograph` / `run_rpmgraph` shell out when present and
  raise `RpmgraphUnavailable` (treated as "skipped") otherwise — never crash.
- **Enrichment is scoped by a selector.** `make_binary_rpm_selector` filters by
  `--package` and `--arch`, defaulting to x86_64 + noarch so a plain run does not
  fan out across every architecture; `--all-archs` widens it. The same selector
  scopes header (rung 3) and payload (rung 4) enrichment, exposed as
  `--package` / `--arch` / `--all-archs` / `--all-packages`.

---

## D13 — Deep `dnf repoquery` extraction + portable/native example split

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

- `example.sh` — **portable** (any OS): synthetic fixture, offline coverage,
  trust path, rung-3 header reads, rung-4 payload (if the `payload` extra is
  installed). No AlmaLinux-native tools required; optional steps degrade.
- `example--almalinux-native.sh` — **AlmaLinux-native**: detects
  dnf/rpm/rpmgraph/cas/zstandard and exercises `--use-dnf`, `--repograph`,
  rung 3/4, and `--use-cas`, each skipped gracefully when its tool is absent.
  `FULL=1` runs the full `--all-packages --all-archs` matrix.

(`example--almalinux.sh`, the CAS-focused demo, remains and is now crash-proof.)

---

## D14 — Soname -> providing-package resolution

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

## D15 — `identify`: file -> full provenance lineage

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

## D16 — The dependency "universe" + traversal (scaling)

**Files:** `albs_graph/provenance/universe.py`, `cli/main.py` (`universe`)

A cross-package, traversable graph — the first concrete step on the scaling
vision. Two builders:

- `universe_from_dot(dot)` — from a `dnf repograph` / `rpmgraph` dot of a whole
  repo: one node per package, `requires` edges between them. `libc`/`glibc` ends
  up with an incoming edge from every package that links it.
- `build_universe(graph)` — collapses an enriched provenance graph's per-subject
  dependency *claims* into shared capability nodes, so a single `libc.so.6` node
  is shared by every artifact (carrying linkage/evidence), and `soname_provider`
  claims add `package -PROVIDES-> soname` bridges.

Traversal helpers: `dependents_of` (who links libc), `dependencies_of`,
`reachable_dependencies`, `dependency_paths` (chains from any node to a target).
Direction matters: `dependents_of`/`dependencies_of` follow only *requires*
edges; PROVIDES is followed only during reachability/path walks so a soname
bridges to its provider — getting this wrong made `glibc` look like a *dependent*
of `libc.so.6` (caught by a test).

CLI: `universe --repograph-dot FILE --dependents-of glibc` / `--dependencies-of
nginx-core` / `--path-from X --path-to Y`, or render the universe as dot/svg/json.

---

## D17 — Python language dependencies (requirements.txt + imports)

**Files:** `albs_graph/adapters/pylang.py`, `cli/main.py`
(`coverage --requirements`)

The graph is not RPM-only. `pylang` turns Python `requirements.txt` lines and
top-level `import` statements into PyPI dependency claims that reconcile
alongside RPM/SBOM/dnf claims: a pinned `==` requirement is a LOCKED claim with a
version (counts toward resolution), a range/bare name is DECLARED, and an
`import foo` is a DECLARED, version-less claim. It records evidence, not
resolution — running a real pip/uv resolve is rung 5 for PyPI. CLI:
`coverage --requirements FILE [--requirements-subject RPM]`.

This is the template for other language ecosystems (npm/Cargo/Go/Maven): a
manifest parser emitting normalized claims, with the real resolver deferred to
rung 5 behind the existing `ResolverResult` contract.

---

## D18 — Arch-wide universe merge

**Files:** `albs_graph/provenance/universe.py`, `adapters/rpmgraph.py`,
`cli/main.py` (`universe --repograph-dot` repeatable + `--source` repeatable)

Combines many sources into one arch-wide universe. The enabling decision is
**canonical node ids**: `build_universe` now re-keys packages to `pkg:<name>`
(keeping the original RPM id in `rpm_node_id`), matching `universe_from_dot`. So
when `merge_graphs` unions several universes, a package appearing in several
repos is one node and cross-repo edges connect — appstream's `nginx-core`
reaches baseos's `glibc` and on to `filesystem`.

`build_arch_universe(dots=..., graphs=..., arch=...)` builds a component universe
per repograph dot and per enriched build graph, then merges them. CLI:
`universe --repograph-dot baseos.dot --repograph-dot appstream.dot
--dependents-of glibc` lists every package across the arch that links glibc.

Fixed along the way: `parse_dot_edges` used `re.search` per line and captured
only the first edge on a line; switched to `finditer` over the whole text so
multiple edges per line are all captured (regression test added).

---

## D19 — Visualizing traversal (focused subgraphs)

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

## D20 — Low-footprint SQLite persistence (stay small)

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
overlay (`sqlite-vec`/vector) is left to the bigger-system plan in `plan.md` —
this stays a single small module so the low-footprint path keeps working with
zero dependencies.

---

## D21 — Full cpio file lists (any file is identifiable)

**Files:** `albs_graph/adapters/rpm_payload.py`, `provenance/identify.py`

Rung-4 payload analysis now records the **full file list** of each RPM (not just
ELF objects) on the binary RPM node under `files`, captured in the same single
decompress pass (`payload_contents` returns both ELF info and all paths).
`identify` then resolves ownership from these stored lists first, so any file —
configs, docs, anything — is traceable offline from graph data, no host
`rpm -qf` needed. File lists can be large, so they are populated only when
payload analysis runs.

---

## D22 — Errata/CVE ingest wired into coverage (`security_context` axis)

**Files:** `albs_graph/adapters/errata.py` (existing), `cli/main.py`
(`coverage --errata`)

`security_context_complete` needs an SBOM **and** an errata/CVE link. The errata
adapter existed but was never exposed; `coverage --errata FILE [--errata-subject
RPM]` now attaches an errata (with its CVEs via `FIXES` edges) to a subject, so a
package with both an SBOM and errata reaches `security_context_complete` and the
axis moves off 0.00. Errata is ingested from a provided JSON file (parallel to
`--sbom`); a live errata.almalinux.org fetch is left as future work.

---

## D23 — CPE verification + distro-backport flag (`identity` axis)

**Files:** `albs_graph/security/cpe.py`, `cli/main.py` (`coverage --verify-cpe`)

Closes the standing rule that the graph must not assert an official CPE without
verification. `verify_graph_cpe` matches each binary's `cpe_candidates` (product)
against a supplied CPE dictionary (`(vendor, product)` pairs from NVD cpe:2.3
strings): a single matching vendor flips the candidate to `verified=True` and
sets `cpe`; multiple vendors are recorded as `ambiguous_vendor` and deliberately
**not** asserted. Only verified CPEs count toward the `identity` axis.

It also flags `distro_backport=true` for AlmaLinux releases (`.elN`), because the
upstream version in the CPE (e.g. `1.20.1`) is shipped with backported patches —
so naive version-vs-CVE matching is misleading. That flag feeds the
vulnerability-applicability report.

The dictionary is supplied (`--verify-cpe FILE`), so verification is offline and
testable; pointing it at a real NVD CPE export is a drop-in.

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

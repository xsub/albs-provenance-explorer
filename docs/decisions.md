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
  (`dnf repograph almalinux-appstream > repo.dot`), so the parser is fully
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

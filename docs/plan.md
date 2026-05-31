# Plan

The target: a unified, scalable provenance + dependency graph over ALBS builds
that **resolves** dependencies (not merely declares them), disambiguates identity
(PURL/CPE/CAS), captures static vs dynamic linkage, and serves three consumers
equally - vuln triage, license compliance, reproducibility - while reporting the
irreducible residue honestly.

This file describes the whole intended system. What is built today is a subset;
see the status markers and `limitations.md`.

---

## 1. Objective function - five coverage axes

Success is measurable. Each axis is computed per build and aggregated; the goal
is to push each toward 1.0 and enumerate what remains.

| Axis | Meaning | Primary consumer |
|------|---------|------------------|
| `resolution` | declared deps resolved to concrete versions, per context | compliance, reproducibility |
| `linkage` | binary artifacts with linkage facts (dynamic + static) | vuln triage |
| `identity` | artifacts with PURL resolved **and** CPE verified | vuln triage |
| `provenance` | build/source/signature/release + CAS evidence intact | reproducibility |
| `security_context` | SBOM + errata/CVE attached | vuln triage, compliance |

No axis may be sacrificed for another ("design for the union").

---

## 2. Two committed design stances

- **All three consumers equally.** One conflict-aware graph that each consumer
  projects differently, rather than three pipelines.
- **Model the disagreement.** When manifest / lockfile / resolver / artifact
  disagree, record all of them as distinct evidence and emit a typed conflict -
  never pick a single "source of truth" and discard the rest.

---

## 3. Data model (three layers)

1. **Provenance backbone** (immutable, append-only): source → git commit → build
   task → SRPM/RPM → signature → release → CAS/SBOM attestation. *(Pre-existing,
   works against live ALBS.)*
2. **Dependency facts / claims** (normalized envelope + raw ecosystem payload):
   one `DependencyClaim` per evidence source, reconciled into a
   `DEPENDENCY_RESOLUTION` verdict without collapsing the claims. *(Built.)*
3. **Resolver outputs** (per ecosystem, per context, cached): the concrete tree
   the authoritative tool produces. *(Contract built; real resolvers are wired
   for RPM, Go, Cargo, PyPI, Maven and npm; Gradle remains a seam.)*

The handoff between layers is typed (`ResolverRequest`/`ResolverResult`), so
adapters and consumers depend on the contract, not on each other.

---

## 4. The cost ladder

Acquire only as much as a question needs; climb when the objective rewards it.

| Rung | Acquires | Cost | Yields | Status |
|------|----------|------|--------|--------|
| 1 | ALBS metadata | ~free | provenance backbone | done (pre-existing) |
| 2 | git checkout: spec + manifests | cheap | declared deps, BuildRequires | done (pre-existing) |
| 3 | RPM header via HTTP Range | tens of KB | **dynamic-linkage claims** | **done** |
| 4 | full payload ELF | MBs | **RPATH/RUNPATH, dlopen, static, toolchain, Go module BOM** | **done** (Rust module BOM n/a) |
| 5 | resolver execution (pip/mvn/npm/cargo/go/libsolv) | compute + sandbox | resolved trees | **RPM, Go, Cargo, PyPI, Maven and npm done**; Gradle deferred |

Rung 3 is the maximal rung reachable with **current public access** because the
RPM header already carries `DT_NEEDED` sonames - no payload, no ELF parse needed.

---

## 5. Status - what is implemented

- ✅ Conflict-aware claim/reconcile model (`provenance/reconcile.py`).
- ✅ `ResolutionState` failure outcomes + `resolution_note`.
- ✅ Typed resolver contract + `NullResolver` (`dependency/resolver.py`).
- ✅ Five-axis coverage report (`provenance/coverage.py`).
- ✅ Rung 3: RPM header parser (`adapters/rpm_header.py`) + Range reader,
  vault-URL reconstruction, soname→linkage claims (`adapters/rpm_remote.py`).
- ✅ CycloneDX-from-file SBOM claims (`adapters/sbom.py`): components become
  versioned dependency claims that raise the resolution axis and drift-check
  against other sources.
- ✅ Rung 4: full payload ELF analysis (`adapters/elf.py`, `rpm_payload.py`) -
  own dependency-free ELF parser; recovers confirmed `DT_NEEDED`, RPATH/RUNPATH,
  dynamic-vs-static, `dlopen`, and Go/Rust toolchain. NEEDED claims corroborate
  rung-3 header sonames.
- ✅ Optional, crash-proof CAS verification (`adapters/cas.py`, `--use-cas`).
- ✅ AlmaLinux-native RPM resolution: `dnf repograph` / `rpmgraph` dot ingest
  (`adapters/rpmgraph.py`) emits resolved RPM dependency claims (rung 5 for RPM).
- ✅ Native non-RPM resolvers behind the same contract: Go (`go list -m all`),
  Cargo (`cargo metadata`), PyPI (`pip install --dry-run --report`), Maven
  (`mvn dependency:list`) and npm (`npm ls --json --all`). Tools are optional
  and failures become `UNRESOLVABLE` evidence rather than command crashes.
- ✅ Deep `dnf repoquery` extraction (`adapters/dnf.py`): versioned RUNTIME
  deps, weak (recommends/suggests) deps as OPTIONAL, conflicts/obsoletes facts,
  and `--whatprovides` for the soname->package mapping. `coverage --use-dnf`.
- ✅ Enrichment selectors: `--package`, `--arch`, `--all-archs`, `--all-packages`.
- ✅ One comprehensive demo script: `example--full.sh` (every command + feature
  end to end; each step gated, skipping gracefully when a tool/file/network is
  absent). It superseded the earlier per-facet scripts.
- ✅ `albs-graph coverage [--with-rpm-headers] [--with-rpm-payloads] [--use-cas]
  [--sbom FILE] [--repograph-dot FILE] [--package P] [--arch A] [--all-archs]`.
- ✅ Soname → package resolution (`coverage --resolve-sonames` / `--provides-map`)
  bridging the soname↔package coordinate gap.
- ✅ `identify <filepath>` - traces a file to every element behind its creation
  and installation (source → commit → build → RPM → signature → release → deps).
- ✅ Dependency **universe** + traversal (`universe` command): `universe_from_dot`
  builds a repo-wide graph (libc connected to everything that links it);
  `dependents_of` / `dependencies_of` / `dependency_paths` traverse it.
- ✅ Python language deps (`adapters/pylang.py`, `coverage --requirements`):
  requirements.txt + import scanning -> PyPI claims (pinned == counts toward
  resolution). Template for other language ecosystems.
- ✅ Multi-language source-tree import scanning (`adapters/source_imports.py`,
  `source-evidence` default-on / `--no-scan-imports`): walks the checked-out
  tree, detects each file's language by extension (with shebang fallback), and
  emits per-language declared-dependency claims for Python, Go, Rust, C/C++,
  JS/TS, Java, Ruby. Stdlib filtered per language; project-internal references
  (`require_relative`, `./relative` JS imports, `self::`/`super::`/`crate::` in
  Rust) excluded. Records what the *code* says it depends on, distinct from the
  manifest-file discovery that `source.py` does.
- ✅ Arch-wide universe merge (`merge_graphs` / `build_arch_universe`; repeatable
  `universe --repograph-dot` + `--source`): canonical `pkg:<name>` ids let many
  repograph dots / builds merge into one cross-repo universe. `arch-universe`
  also fetches each well-known repo for an arch, merges per-repo `dnf repograph`
  output, records skip reasons, and can persist the result.
- ✅ Traversal visualization: `universe --path-from/--path-to` (or
  `--dependents-of` / `--dependencies-of`) with `--format dot|svg|json` renders
  the focused subgraph (`path_subgraph` / `neighborhood_subgraph`).
- ✅ Low-footprint SQLite persistence (`albs_graph/store.py`,
  `universe --save` / `--db`): build once, query later; one-hop and recursive
  multi-hop queries run in SQL without loading the whole graph. The store has
  versioned migrations, replace/merge save modes, deep metadata merge, and
  materialized analysis snapshots. Stdlib only, no graph DB.
- ✅ Full cpio file lists (`identify` works for any file); errata ingest
  (`coverage --errata`, `security_context` axis); CPE verification +
  distro-backport flag (`coverage --verify-cpe` or cached `--verify-cpe-url`,
  `identity` axis); the **`vuln`** vulnerability-applicability report; and
  **CVE-feed matching** (`vuln --cve-feed` or cached `--cve-feed-url`) with
  rpmvercmp version ranges.
- ✅ Semantic version comparison in the reconciler (`VERSION_DRIFT` /
  `RANGE_VIOLATION` via rpmvercmp) and **GPG signature verification**
  (`coverage --verify-signatures`, real provenance verification now CAS is gone).
- ✅ **Desktop investigation workbench** (this `InvestigationWorkbenchApp`
  branch). An `albs_graph/services` facade -- `AnalysisService` over the
  pipeline, typed graph queries, focused graph slices, findings, build
  comparison -- is the shared backend for both CLI and a PyQt5 app
  (`albs_graph/gui`, launched with `albs-graph-workbench`). It opens a cached
  or live build, lists artifacts, renders clickable focused slices (SVG +
  Graphviz image-map hit-testing), inspects nodes/edges, and shows a coverage /
  evidence matrix, a build-task timeline (tree + Gantt), reusable graph
  queries, finding drill-down, and a classic-CLI runner. SBOM auto-discovery
  (D78) and the errata three-state (D79) are surfaced through it. The full
  design and milestone roadmap live in `docs/plan-pyqt5-investigation-workbench-app.md`.
- ✅ Offline tests for all of the above (426 tests; ruff + mypy --strict clean),
  including multi-build coverage confirming the pipeline is not specific to any
  single build. The PyQt5 GUI tests run headless (`QT_QPA_PLATFORM=offscreen`),
  including a workbench-window smoke test that exercises construction +
  result-handling + slice rendering + the inspector.

Demonstrated end to end on the real AlmaLinux 10 ALBS build 57810 (a 13-source
batch), focused on `nginx-core`: 456 binary RPMs, provenance 1.00. On an `el10`
host `dnf repoquery` resolved 6 runtime + 1 weak dep, soname resolution mapped
6/6 sonames to providers, a live header read added 8 dynamic-linkage claims, the
payload ELF confirmed 6 `DT_NEEDED`, and the RPM GPG signature verified. The
reconciler reached `consensus` on 6 runtime packages (two sources agreeing on
one el10 release) and left 8 bare sonames / header requires as
`insufficient_evidence`, with no conflicts - and because the deps were resolved
on the build's own distro, that consensus is the build's actual dependency set.
Agreement and build-context validity are separate axes: an el9 build resolved on
the same el10 host still reaches honest `consensus`, but the resolution carries a
`cross_distro` context issue and is dropped from resolution coverage, so host
packages are never passed off as the build's deps. Licenses are real too: `nginx-core`'s
`BSD-2-Clause` comes
from the RPM `License:` header tag, and `license --rpm-licenses` rolls up the
subject + 6 runtime deps into 6 distinct licenses via `dnf repoquery %{license}`.
AlmaLinux's `alma-sbom` generates a real CycloneDX build SBOM anonymously (457
components, real PURL/CPE/hash, no licenses); applied with `--build-sbom` it
enriches the build's own 456 RPMs with their vendor CPEs, moving the `identity`
axis **0.00 -> 1.00**, flipping the trust path's `has_sbom` to `ok`, and
resolving the `vuln` identities to `verified`. Nothing is fabricated.

---

## 6. Roadmap - what is next

Ordered by value-per-effort and tractability under public access.

### Near term (no credentials required)
1. ✅ **CycloneDX-from-file SBOM claims** and ✅ **soname → providing-package
   resolution** (`coverage --resolve-sonames` / `--provides-map`): header/ELF
   sonames (`libz.so.1`) now resolve to package claims (`zlib`) that corroborate
   SBOM/dnf/repograph claims. The identity-axis follow-up is also done: a build
   SBOM's vendor CPE and NVD `--verify-cpe` both populate the subject's identity
   (item 6).
2. ✅ **CAS verification recorder.** Done as opt-in `--use-cas`
   (`adapters/cas.py`): wraps `cas authenticate --signerID
   cloud-infra@almalinux.org --hash <cas_hash>` when present and flips
   `externally_verified=true` only on success. Crash-proof when `cas` is absent
   (records `unavailable`). Mirrors AlmaLinux's `cas_wrapper`
   (`git.almalinux.org/almalinux/cas_wrapper`). Note: `cas` is now effectively
   uninstallable (Codenotary changed product lines), so this mostly records
   `unavailable` until a host has the binary.
3. **Vault URL resolver hardening.** ✅ live-repo (non-vault) paths for current
   builds are now generated alongside vault paths (D37), so range reads work for
   current el10 builds. Remaining: i686/module/CRB layouts, debug repos, and a
   small on-disk header cache so repeated `coverage` runs don't refetch.

### Medium term
4. ✅ **Rung 4 - payload ELF analysis.** Done - downloads the payload, parses
   ELF `DT_NEEDED`/RPATH/RUNPATH/dlopen/linkage/toolchain, **and** reads
   `.go.buildinfo` so a static Go binary contributes a real module BOM
   (`go_static_claims` emits STATIC RESOLVED claims). Rust has no comparable
   embedded BOM, so it stays toolchain-detected.
5. ✅ **Rung 5 - real resolvers behind the contract.** RPM via
   `dnf repograph`/`rpmgraph`; **Go** (`go list -m all`), **Cargo**
   (`cargo metadata`), **PyPI** (`pip install --dry-run --report`), **Maven**
   (`mvn dependency:list`) and **npm** (`npm ls --json --all`) via
   `resolver_for` + the `resolve` command. Remaining: Gradle, repograph results
   through `ResolverResult` rather than direct dot ingest, and sandbox/cache on
   `(ecosystem, manifest, lockfile, context)`.
6. ✅ **CPE verification adapter.** `coverage --verify-cpe FILE` matches
   `cpe_candidates` against a supplied NVD cpe:2.3 dictionary and populates `cpe`
   / flips `verified` only on a confirmed match (a product mapping to several
   vendors stays `ambiguous_vendor`, uncounted); a vendor build SBOM sets
   `vendor_asserted` CPEs. Either lifts `identity` off 0.00, and the AlmaLinux
   backport case is handled (shipped version below the upstream range but patched
   → `RANGE_VIOLATION`, not "vulnerable"). The dictionary/feed can be supplied as
   files or fetched live with TTL through the HTTP cache; live failure degrades
   gracefully.

### Scale
7. **Thousands-of-apps scale.** The dependency **universe** is built,
   traversable, mergeable across repos, and now **persistable** via a
   low-footprint SQLite store (`--save` / `--db`, one-hop and recursive SQL
   queries without a full load). ✅ **Header/payload/sig fetches now cached +
   parallelised**
   (D63/D64): content-addressed disk cache shared by `rpm_remote` /
   `rpm_payload` / `rpmsig` (one download serves both ELF analysis and
   `rpmkeys --checksig`), with bounded concurrency via
   `ThreadPoolExecutor(max_workers=spec.max_concurrency)`. ✅ **Live arch
   universe** is available through `arch-universe`, which fetches + repographs
   every known repo for an arch and merges the result. Still to do: a heavier
   backend only if the SQLite store is outgrown (Postgres / graph store, or a
   `sqlite-vec` similarity overlay); incremental re-reconciliation; SBOM-fetch
   batching; registry-state cache invalidation (yanks/deletions), not age.

---

## 7. Process / consensus plan

- **Contract first.** Publish the dependency-fact envelope and node/edge
  vocabulary as a versioned contract; adapters and consumers depend on it.
- **One adapter at a time.** Ship one ecosystem adapter against the contract
  before adding more - adapter #2 is what reveals where the contract was wrong.
- **"Couldn't resolve" is a deliverable.** Always report the unresolved /
  unverified residue; never claim 100% coverage.

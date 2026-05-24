# Plan

The target: a unified, scalable provenance + dependency graph over ALBS builds
that **resolves** dependencies (not merely declares them), disambiguates identity
(PURL/CPE/CAS), captures static vs dynamic linkage, and serves three consumers
equally — vuln triage, license compliance, reproducibility — while reporting the
irreducible residue honestly.

This file describes the whole intended system. What is built today is a subset;
see the status markers and `limitations.md`.

---

## 1. Objective function — five coverage axes

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
  disagree, record all of them as distinct evidence and emit a typed conflict —
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
   the authoritative tool produces. *(Contract built; real resolvers are a seam.)*

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
| 4 | full payload ELF | MBs | **RPATH/RUNPATH, dlopen, static detection, toolchain** | **done** (Go/Rust module BOM pending) |
| 5 | resolver execution (uv/mvn/cargo/go/libsolv) | compute + sandbox | resolved trees | **RPM done via `dnf repograph`/`rpmgraph`**; other ecosystems contract-only |

Rung 3 is the maximal rung reachable with **current public access** because the
RPM header already carries `DT_NEEDED` sonames — no payload, no ELF parse needed.

---

## 5. Status — what is implemented

- ✅ Conflict-aware claim/reconcile model (`provenance/reconcile.py`).
- ✅ `ResolutionState` failure outcomes + `resolution_note`.
- ✅ Typed resolver contract + `NullResolver` (`dependency/resolver.py`).
- ✅ Five-axis coverage report (`provenance/coverage.py`).
- ✅ Rung 3: RPM header parser (`adapters/rpm_header.py`) + Range reader,
  vault-URL reconstruction, soname→linkage claims (`adapters/rpm_remote.py`).
- ✅ CycloneDX-from-file SBOM claims (`adapters/sbom.py`): components become
  versioned dependency claims that raise the resolution axis and drift-check
  against other sources.
- ✅ Rung 4: full payload ELF analysis (`adapters/elf.py`, `rpm_payload.py`) —
  own dependency-free ELF parser; recovers confirmed `DT_NEEDED`, RPATH/RUNPATH,
  dynamic-vs-static, `dlopen`, and Go/Rust toolchain. NEEDED claims corroborate
  rung-3 header sonames.
- ✅ Optional, crash-proof CAS verification (`adapters/cas.py`, `--use-cas`).
- ✅ AlmaLinux-native RPM resolution: `dnf repograph` / `rpmgraph` dot ingest
  (`adapters/rpmgraph.py`) emits resolved RPM dependency claims (rung 5 for RPM).
- ✅ Deep `dnf repoquery` extraction (`adapters/dnf.py`): versioned RUNTIME
  deps, weak (recommends/suggests) deps as OPTIONAL, conflicts/obsoletes facts,
  and `--whatprovides` for the soname->package mapping. `coverage --use-dnf`.
- ✅ Enrichment selectors: `--package`, `--arch`, `--all-archs`, `--all-packages`.
- ✅ Two example scripts: `example.sh` (portable) and
  `example--almalinux-native.sh` (native dnf/rpm/rpmgraph/cas stack).
- ✅ `albs-graph coverage [--with-rpm-headers] [--with-rpm-payloads] [--use-cas]
  [--sbom FILE] [--repograph-dot FILE] [--package P] [--arch A] [--all-archs]`.
- ✅ Soname → package resolution (`coverage --resolve-sonames` / `--provides-map`)
  bridging the soname↔package coordinate gap.
- ✅ `identify <filepath>` — traces a file to every element behind its creation
  and installation (source → commit → build → RPM → signature → release → deps).
- ✅ Dependency **universe** + traversal (`universe` command): `universe_from_dot`
  builds a repo-wide graph (libc connected to everything that links it);
  `dependents_of` / `dependencies_of` / `dependency_paths` traverse it.
- ✅ Python language deps (`adapters/pylang.py`, `coverage --requirements`):
  requirements.txt + import scanning -> PyPI claims (pinned == counts toward
  resolution). Template for other language ecosystems.
- ✅ Arch-wide universe merge (`merge_graphs` / `build_arch_universe`; repeatable
  `universe --repograph-dot` + `--source`): canonical `pkg:<name>` ids let many
  repograph dots / builds merge into one cross-repo universe.
- ✅ Traversal visualization: `universe --path-from/--path-to` (or
  `--dependents-of` / `--dependencies-of`) with `--format dot|svg|json` renders
  the focused subgraph (`path_subgraph` / `neighborhood_subgraph`).
- ✅ Low-footprint SQLite persistence (`albs_graph/store.py`,
  `universe --save` / `--db`): build once, query later; one-hop queries run in
  SQL without loading the whole graph. Stdlib only, no graph DB.
- ✅ Full cpio file lists (`identify` works for any file); errata ingest
  (`coverage --errata`, `security_context` axis); CPE verification +
  distro-backport flag (`coverage --verify-cpe`, `identity` axis); the **`vuln`**
  vulnerability-applicability report; and **CVE-feed matching** (`vuln
  --cve-feed`) with rpmvercmp version ranges, reporting potentially-affected CVEs
  beyond those an errata addresses.
- ✅ Offline tests for all of the above (136 tests; ruff + mypy --strict clean),
  including multi-build coverage confirming the pipeline is not 17812-specific.

Demonstrated end to end on the real ALBS build 17812 (nginx): 90 binary RPMs,
provenance 1.00; live vault header reads added real sonames (`libssl.so.3`,
`libcrypto.so.3`, `libperl.so.5.32`, …) lifting linkage 0.00 → 0.06; a CycloneDX
SBOM attached to `nginx-core` resolved 5 package versions (resolution 0.25 over
the 20 reconciled deps) — SBOM packages and header sonames coexisting with
**zero** false conflicts.

---

## 6. Roadmap — what is next

Ordered by value-per-effort and tractability under public access.

### Near term (no credentials required)
1. ✅ **CycloneDX-from-file SBOM claims** and ✅ **soname → providing-package
   resolution** (`coverage --resolve-sonames` / `--provides-map`): header/ELF
   sonames (`libz.so.1`) now resolve to package claims (`zlib`) that corroborate
   SBOM/dnf/repograph claims. Remaining follow-up: extract the root component's
   CPE into the subject's identity candidates (to move the `identity` axis).
2. ✅ **CAS verification recorder.** Done as opt-in `--use-cas`
   (`adapters/cas.py`): wraps `cas authenticate --signerID
   cloud-infra@almalinux.org --hash <cas_hash>` when present and flips
   `externally_verified=true` only on success. Crash-proof when `cas` is absent
   (records `unavailable`). Mirrors AlmaLinux's `cas_wrapper`
   (`git.almalinux.org/almalinux/cas_wrapper`). Note: `cas` is now effectively
   uninstallable (Codenotary changed product lines), so this mostly records
   `unavailable` until a host has the binary.
3. **Vault URL resolver hardening.** Cover i686/module/CRB layouts, debug repos,
   and live-repo (non-vault) paths for current builds; add a small on-disk header
   cache so repeated `coverage` runs don't refetch.

### Medium term
4. ✅ **Rung 4 — payload ELF analysis.** Done — downloads the payload, parses
   ELF `DT_NEEDED`/RPATH/RUNPATH/dlopen/linkage/toolchain. Remaining follow-up:
   parse `.go.buildinfo` to enumerate a static Go binary's module graph (Rust
   metadata likewise), turning "toolchain detected" into a static dependency BOM.
5. **Rung 5 — real resolvers behind the contract.** RPM is done via
   `dnf repograph` / `rpmgraph` (native libsolv/rpm). Next: feed those resolver
   results through the typed `ResolverResult` contract rather than direct dot
   ingest, then language ecosystems via their own tools (uv, mvn, cargo, go),
   sandboxed, against mirrored registries, cached on `(ecosystem, manifest,
   lockfile, context)`.
6. **CPE verification adapter.** Match `cpe_candidates` against the NVD CPE
   dictionary; populate `cpe` / flip `verified` only on confirmed match. Moves
   `identity` off 0.00. Handle the AlmaLinux backport case explicitly (shipped
   version below the upstream range but patched → `RANGE_VIOLATION`, not
   "vulnerable").

### Scale
7. **Thousands-of-apps scale.** The dependency **universe** is built,
   traversable, mergeable across repos, and now **persistable** via a
   low-footprint SQLite store (`--save` / `--db`, one-hop SQL queries without a
   full load). Still to do: drive it from *live* repos (fetch + repograph every
   repo of an arch in one command) rather than supplied dots; a heavier backend
   only if the SQLite store is outgrown (Postgres recursive CTEs / a graph
   store, or a `sqlite-vec` similarity overlay); batch + parallelize
   header/payload/SBOM fetches; incremental re-reconciliation; registry-state
   cache invalidation (yanks/deletions), not age.

---

## 7. Process / consensus plan

- **Contract first.** Publish the dependency-fact envelope and node/edge
  vocabulary as a versioned contract; adapters and consumers depend on it.
- **One adapter at a time.** Ship one ecosystem adapter against the contract
  before adding more — adapter #2 is what reveals where the contract was wrong.
- **"Couldn't resolve" is a deliverable.** Always report the unresolved /
  unverified residue; never claim 100% coverage.

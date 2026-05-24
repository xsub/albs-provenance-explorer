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
| 4 | payload ELF | MBs | RPATH/RUNPATH, dlopen, static BOM | planned |
| 5 | resolver execution (uv/mvn/cargo/go/libsolv) | compute + sandbox | resolved trees | contract only |

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
- ✅ `albs-graph coverage [--with-rpm-headers]` CLI command.
- ✅ Offline tests for all of the above (58 tests; ruff + mypy --strict clean).

Demonstrated end to end on the real ALBS build 17812 (nginx): 90 binary RPMs,
provenance 1.00; live vault header reads added real sonames (`libssl.so.3`,
`libcrypto.so.3`, `libperl.so.5.32`, …) and lifted linkage 0.00 → 0.06 with
zero false conflicts.

---

## 6. Roadmap — what is next

Ordered by value-per-effort and tractability under public access.

### Near term (no credentials required)
1. **CycloneDX-from-file SBOM claims.** Upgrade the existing `sbom.py` import to
   emit dependency *claims* (evidence `sbom`) and extract PURL/CPE into security
   identity. Raises `security_context`; lets the reconciler compare SBOM vs
   header sonames (real `presence` and `version` reconciliation). Tractable
   because it consumes a *provided* CycloneDX file — no immudb read.
2. **CAS verification recorder.** Wrap `cas authenticate --signerID
   cloud-infra@almalinux.org --hash <cas_hash>` when `cas` is present; flip
   `externally_verified=true` on the CAS node. Mirrors `example--almalinux.sh`.
3. **Vault URL resolver hardening.** Cover i686/module/CRB layouts, debug repos,
   and live-repo (non-vault) paths for current builds; add a small on-disk header
   cache so repeated `coverage` runs don't refetch.

### Medium term
4. **Rung 4 — payload ELF analysis.** Stream-decompress the cpio payload
   (early-abort once the target file is seen) to extract RPATH/RUNPATH, dlopen
   sites, and static BOMs (Go buildinfo, Rust metadata). Emits `linkage=STATIC`
   and richer linkage facts. This crosses the "metadata-only" boundary and is the
   step that makes `linkage` approach 1.0.
5. **Rung 5 — real resolvers behind the contract.** libsolv for RPM first (it is
   what DNF uses), then language ecosystems via their own tools, sandboxed,
   against mirrored registries, cached on `(ecosystem, manifest, lockfile,
   context)`. Moves `resolution` off 0.00.
6. **CPE verification adapter.** Match `cpe_candidates` against the NVD CPE
   dictionary; populate `cpe` / flip `verified` only on confirmed match. Moves
   `identity` off 0.00. Handle the AlmaLinux backport case explicitly (shipped
   version below the upstream range but patched → `RANGE_VIOLATION`, not
   "vulnerable").

### Scale
7. **Thousands-of-apps scale.** Batch + parallelize header/SBOM fetches; persist
   the graph (Postgres recursive CTEs or a graph store) instead of in-memory;
   incremental re-reconciliation; registry-state-driven cache invalidation
   (yanks/deletions), not age.

---

## 7. Process / consensus plan

- **Contract first.** Publish the dependency-fact envelope and node/edge
  vocabulary as a versioned contract; adapters and consumers depend on it.
- **One adapter at a time.** Ship one ecosystem adapter against the contract
  before adding more — adapter #2 is what reveals where the contract was wrong.
- **"Couldn't resolve" is a deliverable.** Always report the unresolved /
  unverified residue; never claim 100% coverage.

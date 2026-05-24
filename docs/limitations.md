# Limitations

An honest register of what the system does **not** do today, why, and what would
lift each limit. Stating the residue explicitly is part of the design goal — a
tool that hides its gaps is worse than one that names them.

Coverage axes referenced below are defined in `plan.md`.

---

## Coverage axes that are intentionally low

These are not bugs; they are unfed axes. The code refuses to fabricate the
evidence that would raise them.

### `security_context` = 0.00 — no SBOM ingest from the ledger
AlmaLinux SBOMs live in Codenotary's immudb and are retrieved with the
`alma-sbom` utility / `cas` CLI, which require an API key and login. There is no
documented anonymous read path. We therefore did **not** wire a ledger fetch.
- **Today:** `adapters/sbom.py` can ingest a *provided* CycloneDX/SPDX file, but
  nothing produces one automatically.
- **Lift:** the "CycloneDX-from-file SBOM claims" item in `plan.md` (consumes a
  file you already fetched), and/or a credentialed `alma-sbom`/`cas` adapter.

### `identity` = 0.00 — CPE is never asserted as verified
The graph stores `cpe: null` plus unverified `cpe_candidates`. The identity axis
counts only **verified** CPEs, and no verification adapter exists yet.
- **Why:** asserting an official CPE without matching the NVD dictionary is the
  exact failure mode the security-identity layer forbids.
- **Lift:** a CPE-verification adapter (NVD dictionary match), including explicit
  handling of AlmaLinux backports (shipped version below the upstream range but
  patched).

### `resolution` ≈ 0.00 — sonames carry no version
Header-derived soname claims have no package version (the symbol version lives in
the name, not a NEVRA), so each reconciles to `INSUFFICIENT_EVIDENCE`. The
resolution axis only rises once a version-resolving source (SBOM or a real
resolver) is added.
- **Lift:** rung 5 resolvers and/or SBOM ingest.

---

## Rungs not yet implemented

### Rung 4 — payload ELF analysis (RPATH/RUNPATH, dlopen, static BOM)
Only the RPM **header** is read today, which yields dynamic `DT_NEEDED` sonames
but **not** `DT_RPATH`/`DT_RUNPATH`, `dlopen` call sites, or static-link BOMs
(Go buildinfo, Rust metadata). Those require the actual ELF bytes from the
compressed cpio payload.
- **Note:** a compressed payload defeats random-access range reads; the best
  achievable is stream-decompress-and-early-abort, not "fetch one file."
- **Consequence:** statically linked dependencies are invisible; `linkage` is
  capped well below 1.0 and reflects only dynamic linkage.

### Rung 5 — real per-ecosystem resolvers
Only `NullResolver` exists (it marks everything `RESOLUTION_SKIPPED`). The typed
contract (`ResolverRequest`/`ResolverResult`/`DependencyResolver`) is in place,
but no resolver actually shells out to uv/pip-tools, Maven/Gradle, `cargo
metadata`, `go list`, or libsolv. Resolution is therefore evidence-only.

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

By deliberate design (see `decisions.md` D7), the reconciler:
- **does not evaluate version ranges** — `RANGE_VIOLATION` only appears when a
  resolver asserts it via `range_satisfied=False`. With no resolver, range
  violations are invisible.
- detects `VERSION_DRIFT` by **exact string inequality** of concrete versions,
  not semantic version comparison; `1.0` vs `1.0.0` would read as drift.
- does **not** auto-detect `IDENTITY_MISMATCH` (the enum exists for resolver/CPE
  adapters to populate, but nothing emits it yet).
- treats `context` as part of the grouping key via a string serialization; two
  contexts that differ only in field ordering are normalized, but exotic context
  values are compared as strings.

---

## Verification vs. reporting

CAS hashes are **reported, not verified**: `externally_verified` stays `false`
because no `cas authenticate` step runs in this environment. The build-17812
provenance score of 1.00 reflects *evidence present and well-formed*, not
*cryptographically re-verified*.

---

## Scale and performance

The current implementation targets correctness and demonstrability, not the
stated "thousands of applications":
- The graph is **in-memory only**; there is no persistence or query backend.
- Header fetches are **sequential and uncached** — each `coverage --with-rpm-
  headers` run refetches; there is no on-disk header cache and no parallelism.
- Reconciliation is a single full pass; there is no incremental re-reconciliation
  as new evidence arrives.
- Cache invalidation for resolver results is specified (registry-state driven,
  not age) but not implemented, since no resolver runs.

---

## Testing boundary

Per the repo rule, tests never hit the network. The remote RPM path is exercised
by serving a hand-built RPM byte structure through a fake range fetcher, so the
parser, incremental fetch loop, and claim generation are covered — but **live
vault/mirror behavior** (redirects, `Accept-Ranges` quirks, 404s, throttling) is
only validated manually, not in CI.

---

## Process note: branch history

All work is on branch `max`. A concurrent Claude Desktop session (from an earlier
`/desktop` transfer) interleaved unrelated README/demo commits between the two
feature commits (`1339b8e`, `f5b6bdd`). History was intentionally **not** rebased
to avoid clobbering that concurrent work; the feature commits remain intact and
`main` is untouched.

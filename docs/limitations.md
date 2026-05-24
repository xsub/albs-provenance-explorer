# Limitations

An honest register of what the system does **not** do today, why, and what would
lift each limit. Stating the residue explicitly is part of the design goal — a
tool that hides its gaps is worse than one that names them.

Coverage axes referenced below are defined in `plan.md`.

---

## Coverage axes that are intentionally low

These are not bugs; they are unfed axes. The code refuses to fabricate the
evidence that would raise them.

### `security_context` axis = 0.00 even with an SBOM attached
Two distinct facts here:

- **No ledger auto-fetch.** AlmaLinux SBOMs live in Codenotary's immudb and are
  retrieved with the `alma-sbom`/`cas` tooling, which require an API key and
  login. There is no documented anonymous read path, so nothing fetches an SBOM
  automatically. `coverage --sbom FILE` ingests a *provided* CycloneDX file (the
  artifact `alma-sbom` produces) — that path is implemented; the credentialed
  fetch is not.
- **The axis is binary-complete and needs errata too.** `security_context_complete`
  requires *both* an attached SBOM **and** an errata/CVE link. Attaching an SBOM
  sets `has_sbom` but not `has_errata_link`, so the axis stays 0.00 until errata
  ingest also runs for the same subject. (SBOM ingest *does* raise the separate
  `resolution` axis.)
- **Lift:** attach errata/CVE alongside the SBOM, and/or a credentialed
  `alma-sbom`/`cas` adapter.

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

### Rung 4 — payload ELF analysis (implemented, with caveats)
Implemented: full RPM download → cpio payload → ELF parse of confirmed
`DT_NEEDED`, `DT_RPATH`/`DT_RUNPATH`, dynamic-vs-static linkage, a best-effort
`dlopen` flag, and Go/Rust toolchain detection. Remaining limits:
- **Whole-RPM download, no early-abort.** A compressed payload defeats
  random-access range reads, and the current reader downloads the entire RPM
  rather than stream-decompressing with early-abort. Bounded at 256 MB.
- **zstd needs an optional dependency.** Real el9 payloads are zstd; install
  `pip install '.[payload]'`. gzip/xz/bzip2 work out of the box.
- **Static BOM is detected, not enumerated.** A static Go/Rust binary is flagged
  by toolchain, but its embedded module graph is not parsed (`.go.buildinfo` /
  Rust metadata). So static binaries contribute a linkage *fact* but no static
  dependency *claims* yet.
- **`dlopen` is a heuristic.** It scans the dynamic symbol table for
  `dlopen`/`dlmopen` imports; a binary that reaches `dlopen` only transitively,
  or is fully stripped of section headers, may be missed.
- **Section-header dependence.** Analysis uses ELF section headers (present in
  distro RPM binaries); objects stripped of sections return `is_elf=True` with
  empty analysis. 32-bit and big-endian are handled but exercised less.

### Rung 5 — real per-ecosystem resolvers
RPM resolution is available via `dnf repograph` / `rpmgraph` (see below). For the
language ecosystems, only `NullResolver` exists (marks everything
`RESOLUTION_SKIPPED`); the typed contract is in place but nothing yet shells out
to uv/pip-tools, Maven/Gradle, `cargo metadata` or `go list`.

### `dnf repoquery` caveats
- **Host tool, many subprocess calls.** `coverage --use-dnf` runs several
  `dnf repoquery` invocations *per selected package* (requires + weak relations
  + conflicts/obsoletes). Scope it with `--package`/`--arch`/`--limit`; the full
  matrix is slow. Absent `dnf`, it records `available=false` and changes nothing.
- **Weak deps collapse to one scope.** `recommends`/`suggests` both map to
  `DependencyScope.OPTIONAL` (the precise relation is kept in the claim's raw).
  RPM also has `supplements`/`enhances` (reverse weak deps) which are not yet
  emitted as claims.
- **`--whatprovides` is not auto-wired into reconciliation.** The function
  exists (and resolves a soname to its providing package), but header/ELF soname
  claims are not yet rewritten to the providing package, so the soname↔package
  cross-validation remains manual. That is the next step (see `plan.md`).

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

## Verification vs. reporting

CAS hashes are **reported, not verified** by default: `externally_verified`
stays `false` unless `--use-cas` runs a successful `cas authenticate`. The
build-17812 provenance score of 1.00 reflects *evidence present and well-formed*,
not *cryptographically re-verified*.

`--use-cas` is opt-in and crash-proof, but in practice the `cas` binary is now
**uninstallable** (Codenotary changed product lines; `getcas.codenotary.io` and
the GitHub releases 404). So on most hosts CAS verification records `unavailable`
and changes nothing — by design, never an error. If you have a host that still
has `cas`, `--use-cas` will use it.

---

## Python language dependencies
`coverage --requirements FILE` parses requirements.txt and (best-effort) imports
into PyPI claims, but:
- **Module name ≠ package name.** `import foo` records the *module*; mapping it
  to its distribution (e.g. `cv2` -> `opencv-python`) is not done.
- **Markers are recorded, not evaluated.** A `; python_version < "3.8"` marker is
  kept in the claim's raw but does not gate the claim by context.
- **requirements.txt + imports only.** `pyproject.toml`/Poetry/Pipfile and other
  languages (npm/Cargo/Go/Maven manifests) are not parsed yet; and no real
  pip/uv resolve runs (that is rung 5 for PyPI, behind the resolver contract).

## `identify` ownership resolution
`identify <filepath>` walks the provenance graph fully offline, but mapping a
file to its owning package depends on:
- `--owner` (explicit), or an `owner_lookup`, or ELF paths from rung-4 payload
  analysis, then host `rpm -qf` (installed files), then `dnf repoquery --file`
  (repo files — works even when the package is not installed locally).
- Full RPM **file lists are not stored** in the graph, so a file that is neither
  installed nor in the enabled repos (and not a rung-4 ELF path) needs
  `--owner`. Recording complete cpio file lists during payload analysis would
  make any file resolvable offline — a planned enhancement.

## `dnf repograph` repo selection
`dnf repograph` selects a repo with the global `--repo` flag, **not** a
positional argument (`dnf repograph appstream` is rejected). `run_repograph` and
`universe --repograph <repo>` use `--repo`; for a manual dot, run
`dnf repograph --repo appstream > appstream.dot`.

## Dependency universe
`universe_from_dot` / `build_universe` / `build_arch_universe` + traversal exist,
but:
- **Sources are supplied, not fetched.** `build_arch_universe` merges many
  repograph dots / builds you provide, but there is no one-command "fetch +
  repograph every repo of an arch" yet — you generate the dots on a host.
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
The `albs_graph/store.py` persistence is intentionally minimal:
- **One-hop SQL only.** `sql_dependents` / `sql_dependencies` run without loading
  the graph, but multi-hop paths and rendering still `load_graph` the whole
  store into memory.
- **Substring/exact name matching** (label / `pkg:<name>` / `cap:%<name>`), same
  trade-off as the in-memory traversal.
- **Single-writer, replace-on-save.** `save_graph` rewrites the file; there is no
  incremental update, concurrency control, or migration story.
- **No vector/similarity.** A `sqlite-vec` overlay is noted in the plan but not
  implemented.

## Scale and performance

The current implementation targets correctness and demonstrability, not the
stated "thousands of applications":
- Beyond the SQLite store, there is **no heavier query backend**; multi-hop
  traversal still happens in memory after a full load.
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

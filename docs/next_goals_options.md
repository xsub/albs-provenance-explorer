# Next-goal options

Candidate next directions, not commitments. Each item notes what it buys (which
coverage axis it moves, which `limitations.md` gap it closes, or which consumer
it serves), a rough effort, and dependencies. The most honest place to aim is
the coverage report itself: two axes (`identity`, `security_context`) currently
sit at a flat **0.00**.

(The **live arch builder** — one command that runs `dnf repograph --repo X` for
every repo of an arch, merges, and persists — remains an option too; it is
tracked in `plan.md` §7. This file collects the *alternatives* to it.)

---

## A. Move the flat-zero coverage axes (highest signal)

- **A1 — CPE verification → `identity` axis.** ✅ Done —
  `coverage --verify-cpe FILE` matches `cpe_candidates` against a CPE dictionary,
  flips `verified` / sets `cpe` (single-vendor match), records `ambiguous_vendor`
  without asserting, and flags `distro_backport` on `.elN` releases for the vuln
  report. *(decisions.md D23)*
- **A2 — Errata/CVE ingest → `security_context` axis.** ✅ Done —
  `coverage --errata FILE [--errata-subject RPM]` attaches an errata + its CVEs,
  so SBOM + errata together reach `security_context_complete` (axis moves off
  0.00). File-based ingest; live errata.almalinux.org fetch is future.
  *(decisions.md D22)*

## B. Finish half-done things (cheap, high utility)

- **B1 — Store full cpio file lists during rung 4.** ✅ Done — `payload_contents`
  records every path; `identify` resolves ownership from the stored list first,
  so any file (configs, docs) is traceable offline. *(decisions.md D21)*
- **B2 — Real version comparison in the reconciler.** `VERSION_DRIFT` is
  exact-string today and `RANGE_VIOLATION` only fires on a resolver flag. Add RPM
  `labelCompare`-style version math so drift/range conflicts fire on real data.
  *Effort: medium.*
- **B3 — Python module → package mapping** (`cv2` -> `opencv-python`) so import
  claims resolve to distributions. *Effort: low-medium.*

## C. Complete rung 4 (static linkage is invisible today)

- **C1 — Go `.go.buildinfo` / Rust metadata module extraction.** Turn "toolchain
  detected" into actual static dependency *claims*. Statically-linked deps
  currently contribute a flag but no edges, capping the `linkage` axis.
  *Effort: medium-high (binary buildinfo parsing).*

## D. Real verification (CAS is gone; this is the verification story now)

- **D1 — GPG signature verification of RPMs.** ALBS gives us signature *nodes*,
  but the actual RPM signature is never verified. `rpm --checksig` / python moves
  `provenance` from "well-formed" to "cryptographically verified", replacing the
  now-defunct CAS path. *Effort: medium.*

## E. Real resolvers behind the existing contract (rung 5, non-RPM)

- **E1 — Wire `uv`/pip-tools, `cargo metadata`, `go list -m all`,
  `mvn dependency:tree`** as shell-out-if-present resolvers, exactly like `dnf`.
  The `ResolverResult` contract already exists; this moves `resolution` for the
  language ecosystems. *Effort: medium per ecosystem.*

## F. The "why does this exist" payoff — a consumer report

- **F1 — Vulnerability-applicability report.** ✅ Done — the `vuln` command
  combines addressed CVEs (errata) + verified CPE + distro-backport caveat +
  linkage (`dlopen` / static) per package. *(decisions.md D24)*
- **F2 — License-compliance rollup** from SBOM license fields + resolved trees.
- **F3 — SLSA / in-toto provenance export** of the backbone the graph already
  holds.

## G. Scale / performance (without the live builder)

- **G1 — Parallelize + cache header/payload fetches.** They are sequential and
  uncached today — the real "thousands of apps" bottleneck. Thread pool / asyncio
  + an on-disk header cache.
- **G2 — Incremental store updates** instead of replace-on-save in
  `albs_graph/store.py`.
- **G3 — `sqlite-vec` similarity overlay** ("find packages like this") — optional,
  adds a loadable-extension dependency, so deliberately deferred.

---

## Recommendation

**A (both)** is the strongest: it turns the two embarrassing zeros into real
numbers and unlocks **F1** (the consumer payoff). Fold in **B1** as a cheap,
low-risk quick win that immediately improves `identify`.

Suggested sequence:

```
B1 (full file lists)  ->  A2 (errata)  ->  A1 (CPE + backport)  ->  F1 (vuln report)
```

✅ **Done** — the full sequence landed (decisions.md D21–D24). The flat-zero
axes now move (`identity`, `security_context`), any file is identifiable, and
the `vuln` command is the consumer deliverable. Remaining open items above:
**B2** (version compare), **B3** (py module→package), **C1** (Go/Rust static
BOM), **D1** (GPG signature verification), **E1** (language resolvers),
**F2/F3** (license / SLSA export), **G** (scale/perf), and the live arch builder.

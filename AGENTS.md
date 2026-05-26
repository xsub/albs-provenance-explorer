# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project

`albs-provenance-explorer` is a read-only Python CLI/PoC that builds provenance-aware graphs over AlmaLinux Build System (ALBS), RPM, SBOM, CAS attestation and errata data. It is not a package-manager resolver, not a rebuilder, and has no write path back into ALBS.

## Environment / commands

Python 3.11+. Editable install with dev extras:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
```

SVG rendering requires Graphviz on PATH (`dot -V`).

Common commands:

```bash
pytest                              # full test suite
pytest tests/test_trust.py          # single test file
pytest tests/test_trust.py::test_x  # single test
ruff check albs_graph tests         # lint
mypy albs_graph                     # strict typing (configured in pyproject.toml)
albs-graph --help                   # CLI entrypoint (also: python -m albs_graph.cli.main)
./example--verbose.sh               # regenerate demo artifacts for build 17812
VERIFY_GIT=1 ./example--verbose.sh  # also verify git source commit
./example.sh                        # portable demo (any OS; no native tools)
./example--almalinux-native.sh      # native dnf/rpm/rpmgraph/cas stack (AlmaLinux host)
./example--almalinux.sh             # CAS hash verification (opt-in; crash-proof if cas absent)
```

CAS (`--use-cas`) and the native RPM/DNF integrations (`--use-dnf`,
`--repograph`, `--repograph-dot`, `--with-rpm-payloads`) are all optional and
degrade gracefully when the tool is missing - never required, never fatal.

The verbose demo caches raw ALBS metadata in `examples/live-build-17812/build-17812.albs.json`. That one file is committed (un-ignored in `.gitignore`) because the `build_analysis` tests use it as a fixture and build 17812 is a finished, immutable build; every *other* `*.albs.json` cache stays gitignored. Cache TTL defaults to 5 minutes; override with `CACHE_TTL=<seconds>`. Force a refetch with `--refresh-cache` on CLI commands.

## Architecture

The codebase is layered intentionally - keep concerns separate when extending.

**`albs_graph/model/`** - Graph core. `Node`/`Edge` are frozen dataclasses; `NodeType` and `Relation` are `StrEnum`s with a fixed canonical vocabulary (`source_package`, `git_commit`, `cas_attestation`, `build_task`, `srpm`, `binary_rpm`, `signature`, `repository_release`, `errata`, `cve`, `sbom`, `source_tree`, etc.). `ProvenanceGraph` exposes typed lookups (`find_by_type`) and `trust_path_report`. Adding new node/edge kinds means extending these enums first.

**`albs_graph/adapters/`** - Ingestion. Each adapter converts an external evidence source into the graph contract: `albs.py` fetches from `build.almalinux.org` (with on-disk cache + TTL), `rpm.py` reads local RPM headers via `rpmfile`, `sbom.py` imports SPDX/CycloneDX JSON, `errata.py` attaches errata/CVE, `source.py` checks out the exact git commit referenced by ALBS and walks the source tree for `.spec` files and ecosystem manifests (`package.json`, `Cargo.toml`, `go.mod`, `pyproject.toml`, `pom.xml`, Gradle). Adapters must not embed resolver semantics - they record evidence, not resolved dependencies.

**`albs_graph/dependency/`** - Normalized dependency-fact model (ecosystem, scope, linkage, resolution state, context). Stores ecosystem-specific raw metadata alongside the normalized fact so future resolver adapters can plug in without changing the graph contract.

**`albs_graph/provenance/`** - Analysis on top of the graph. `trust.py` produces source-to-artifact trust paths for a binary RPM and the focused subgraph used by SVG demos; `inventory.py` and `build_analysis.py` derive the artifact matrix and per-task timing/processing analysis from raw ALBS metadata.

**`albs_graph/render/`** - Output formats: `json_export.py`, `dot.py`, `svg.py` (Graphviz). The CLI's `--format` flag maps directly to these.

**`albs_graph/cli/main.py`** - Single Typer app with all commands: `fetch` / `fetch-build`, `inspect-rpm`, `import-sbom`, `trust-path`, `checkout-source`, `source-evidence`, `fixture` / `render-fixture` / `inspect-fixture`. The CLI is where `--cache`, `--cache-ttl`, `--refresh-cache` and `--verbose` are wired up; deeper layers do not know about the filesystem cache.

### Identity and trust semantics - load-bearing design rules

These distinctions show up across the code and must be preserved when adding adapters or analyses:

- **PURL ≠ CPE ≠ CAS.** PURL = package coordinates (live ALBS RPMs use `pkg:rpm/almalinux/...` with `arch`, `distro`, version/release qualifiers). CPE = security-applicability identity; the graph stores `cpe: null` plus unverified `cpe_candidates` and must not assert an official CPE match without a verification adapter. CAS = build/source/artifact evidence; CAS nodes preserve fields like `build_id`, `alma_commit_sbom_hash`, `git_url`, `git_ref`, `git_commit`, `build_host`, `built_by`.
- **Trust completeness has two axes.** `provenance_complete` covers ALBS build linkage, signature, release context, source/artifact CAS evidence. `security_context_complete` covers attached SBOM and errata/CVE linkage. `complete` requires both. Do not collapse these - the live `nginx-core` demo intentionally shows provenance complete while security context is missing.
- **Evidence vs. resolution.** Source-manifest discovery records that a `package.json` or `go.mod` exists; it does NOT run Pip/Poetry/Maven/Gradle/npm/Cargo/Go resolution. Adding that is a separate future layer that consumes manifests and emits resolved dependency facts back into the graph.
- **CAS hashes are reported, not verified.** `alma_commit_cas_hash` and artifact `cas_hash` reflect what ALBS reports. Only mark CAS evidence as externally verified when an explicit verification step (e.g. `example--almalinux.sh` running `cas`) records that fact.
- **RPM `requires`/`provides` are facts in the graph, not its organizing principle.** Provenance edges (`built_by`, `produces`, `signed_as`, `released_to`, `authenticated_by`, `derived_from`) are primary; `requires_runtime` is secondary.

## Testing

Tests live in `tests/` and cover graph correctness, trust-path semantics, SBOM import, render output, ALBS metadata parsing and cache behavior, artifact inventory, build analysis, security identity (PURL/CPE shape), and source evidence. Tests rely on the synthetic fixture (`albs_graph/fixtures.py`, `albs_graph/examples/`) and do not hit the network - keep it that way when adding tests.

## Conventions (must follow)

These are standing rules for every change in this repository:

- **Keep `docs/` in sync on every commit.** Any commit that changes behavior, architecture, scope, or limitations MUST also update the relevant files under `docs/` (`decisions.md`, `plan.md`, `limitations.md`) in the same commit. Docs are part of the change, not an afterthought.
- **No AI attribution in commit messages.** Never add a `Co-Authored-By: Codex` trailer (or any "Generated with Codex / Codex" line) to commits. A local `.git/hooks/commit-msg` hook strips these as a safety net, but do not rely on it - omit them in the first place.
- **Test-count figures are cross-checked.** A bare "N tests" figure in `README.md` or `docs/*.md` always means the full suite and must equal `pytest --collect-only`. `scripts/check-test-count.sh` enforces this and is wired as a pre-commit hook; install it on a fresh clone with `ln -sf ../../scripts/check-test-count.sh .git/hooks/pre-commit`. It skips gracefully when pytest is unavailable; bypass once with `SKIP_TESTCOUNT=1 git commit`. Mention a subset some other way (e.g. "N test cases for X").

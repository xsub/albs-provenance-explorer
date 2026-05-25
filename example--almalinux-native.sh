#!/usr/bin/env bash
#
# AlmaLinux-native demo: exercises the native RPM/DNF stack as deeply as the
# host allows. Every step is gated on tool availability and skips gracefully -
# the script never hard-fails because a tool is missing.
#
# Native sources used:
#   dnf repoquery   -> resolved runtime + weak (recommends/suggests) deps  (--use-dnf)
#   dnf repograph   -> whole-repo dependency graph                         (--repograph REPO)
#   rpmgraph        -> dependency graph among local RPMs                   (REPO/dot path)
#   RPM headers     -> dynamic sonames (rung 3)                            (--with-rpm-headers)
#   RPM payloads    -> ELF RPATH/RUNPATH/dlopen/static (rung 4)            (--with-rpm-payloads)
#   cas             -> CAS hash verification (now usually unavailable)     (--use-cas)
#
# Env:
#   BUILD_ID (default 17812)  PACKAGE (default nginx-core)  ARCH (default x86_64)
#   REPO     (e.g. baseos/appstream; enables live `dnf repograph REPO`)
#   FULL=1   run the full --all-archs --all-packages matrix (heavy; network)
#   VERBOSE   (default 1) run steps with --verbose (per-claim reconciliation
#             detail in coverage); set VERBOSE=0 for concise one-line summaries

set -uo pipefail

BUILD_ID="${BUILD_ID:-17812}"
PACKAGE="${PACKAGE:-nginx-core}"
ARCH="${ARCH:-x86_64}"
REPO="${REPO:-}"
LIVE_DIR="${LIVE_DIR:-examples/live-build-$BUILD_ID}"
CACHE="${CACHE:-$LIVE_DIR/build-$BUILD_ID.albs.json}"
VERBOSE="${VERBOSE:-1}"
verbose_flag=""
[ "$VERBOSE" = "1" ] && verbose_flag="--verbose"

mkdir -p "$LIVE_DIR"

if command -v python3 >/dev/null 2>&1; then PYTHON_BIN=python3; else PYTHON_BIN=python; fi
run() {
  if command -v albs-graph >/dev/null 2>&1; then albs-graph "$@"; else "$PYTHON_BIN" -m albs_graph.cli.main "$@"; fi
}
step() { printf '\n==> %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

printf '==> AlmaLinux-native albs-provenance-explorer demo\n'
printf 'build: %s  package: %s  arch: %s\n' "$BUILD_ID" "$PACKAGE" "$ARCH"
printf 'tools: dnf=%s rpm=%s rpmgraph=%s cas=%s zstandard=%s\n' \
  "$(have dnf && echo yes || echo no)" \
  "$(have rpm && echo yes || echo no)" \
  "$(have rpmgraph && echo yes || echo no)" \
  "$(have cas && echo yes || echo no)" \
  "$("$PYTHON_BIN" -c 'import zstandard' >/dev/null 2>&1 && echo yes || echo no)"

step "Fetch ALBS build metadata (cached ${CACHE})"
run fetch --build-id "$BUILD_ID" --cache "$CACHE" --cache-ttl 300 --format json \
  -o "$LIVE_DIR/build-$BUILD_ID.json" $verbose_flag || true
if [[ ! -f "$CACHE" ]]; then
  printf 'ERROR: no cached metadata at %s (need network for the first run).\n' "$CACHE" >&2
  exit 1
fi

step "Baseline five-axis coverage (offline)"
run coverage --source "$CACHE" $verbose_flag

if have dnf; then
  step "Native dnf repoquery resolution for ${PACKAGE} (runtime + weak deps)"
  run coverage --source "$CACHE" --use-dnf --package "$PACKAGE" --arch "$ARCH" $verbose_flag
else
  step "dnf not found; skipping native repoquery resolution"
fi

if have dnf && [[ -n "$REPO" ]]; then
  step "Whole-repo dependency graph via 'dnf repograph ${REPO}'"
  run coverage --source "$CACHE" --repograph "$REPO" --arch "$ARCH" $verbose_flag
else
  step "Skipping repograph (set REPO=baseos|appstream to enable live 'dnf repograph')"
fi

step "Rung 3: RPM header range reads -> dynamic sonames"
run coverage --source "$CACHE" --with-rpm-headers --arch "$ARCH" --limit 5 $verbose_flag || true

if "$PYTHON_BIN" -c 'import zstandard' >/dev/null 2>&1; then
  step "Rung 4: RPM payload ELF analysis (RPATH/RUNPATH/dlopen/static)"
  run coverage --source "$CACHE" --with-rpm-payloads --package "$PACKAGE" --arch "$ARCH" --limit 2 $verbose_flag || true
else
  step "Rung 4 skipped (install zstd:  pip install -e '.[payload]')"
fi

step "CAS verification (opt-in; records 'unavailable' if cas is missing)"
run coverage --source "$CACHE" --use-cas --format summary $verbose_flag || true

if [[ "${FULL:-0}" == "1" ]]; then
  step "FULL matrix: every package and arch (heavy; network + dnf)"
  run coverage --source "$CACHE" --use-dnf --with-rpm-headers --with-rpm-payloads \
    --all-packages --all-archs --use-cas --format json -o "$LIVE_DIR/coverage-full.json" || true
  printf '   wrote %s\n' "$LIVE_DIR/coverage-full.json"
fi

printf '\n==> Done.\n'

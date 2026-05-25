#!/usr/bin/env bash
#
# Portable demo (any OS): exercises the parts of albs-provenance-explorer that
# need NO AlmaLinux-native tooling (no dnf / rpm / rpmgraph / cas).
#
# What it shows:
#   1. synthetic fixture graph + trust path        (fully offline)
#   2. ALBS build metadata fetch + offline coverage (network, cross-platform)
#   3. rung 3: RPM header range reads               (network, cross-platform)
#   4. rung 4: RPM payload ELF analysis             (network; needs the
#                                                    'payload' extra for zstd)
#
# Network steps degrade gracefully; the script never hard-fails on an optional
# step. For the AlmaLinux-native stack (dnf repoquery / repograph / rpmgraph /
# cas) see example--almalinux-native.sh.

set -uo pipefail

BUILD_ID="${BUILD_ID:-17812}"
PACKAGE="${PACKAGE:-nginx-core}"
ARCH="${ARCH:-x86_64}"
LIVE_DIR="${LIVE_DIR:-examples/live-build-$BUILD_ID}"
CACHE="${CACHE:-$LIVE_DIR/build-$BUILD_ID.albs.json}"
LIMIT="${LIMIT:-5}"
VERBOSE="${VERBOSE:-1}"

# Verbose by default: the albs-graph steps run with --verbose, so coverage prints
# the per-claim reconciliation detail (coordinate -> verdict [evidence], grouped
# by subject) and fetch/trust-path print step progress. Set VERBOSE=0 for the
# concise one-line summaries.
verbose_flag=""
[ "$VERBOSE" = "1" ] && verbose_flag="--verbose"

mkdir -p "$LIVE_DIR"

if command -v python3 >/dev/null 2>&1; then PYTHON_BIN=python3; else PYTHON_BIN=python; fi
run() {
  if command -v albs-graph >/dev/null 2>&1; then albs-graph "$@"; else "$PYTHON_BIN" -m albs_graph.cli.main "$@"; fi
}
step() { printf '\n==> %s\n' "$1"; }
optional() { "$@" || printf '   (skipped: step failed or offline)\n'; }

printf '==> Portable albs-provenance-explorer demo (no AlmaLinux-native tools)\n'
printf 'build: %s  package: %s  arch: %s\n' "$BUILD_ID" "$PACKAGE" "$ARCH"

step "Synthetic fixture: node counts and two-axis trust"
run inspect-fixture synthetic

step "Fetch ALBS build metadata (cached ${CACHE}, 5 min TTL)"
optional run fetch --build-id "$BUILD_ID" --cache "$CACHE" --cache-ttl 300 --format json \
  -o "$LIVE_DIR/build-$BUILD_ID.json" $verbose_flag

if [[ ! -f "$CACHE" ]]; then
  printf '\nERROR: no cached metadata at %s and fetch failed (offline?).\n' "$CACHE" >&2
  printf 'Re-run with network access to populate the cache.\n' >&2
  exit 1
fi

step "Five-axis coverage (offline, from cached metadata)"
run coverage --source "$CACHE" $verbose_flag

step "Trust path for ${PACKAGE} (${ARCH})"
optional run trust-path --source "$CACHE" --rpm "$PACKAGE" --arch "$ARCH" $verbose_flag

step "Rung 3: range-read real RPM headers -> dynamic-linkage claims (network)"
optional run coverage --source "$CACHE" --with-rpm-headers --arch "$ARCH" --limit "$LIMIT" $verbose_flag

step "Rung 4: download RPM payloads -> ELF analysis (network; needs '.[payload]')"
if "$PYTHON_BIN" -c "import zstandard" >/dev/null 2>&1; then
  optional run coverage --source "$CACHE" --with-rpm-payloads --package "$PACKAGE" --arch "$ARCH" --limit 2 $verbose_flag
else
  printf '   (skipped: install the payload extra for zstd:  pip install -e ".[payload]")\n'
fi

printf '\n==> Done. For the AlmaLinux-native stack run example--almalinux-native.sh\n'

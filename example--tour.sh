#!/usr/bin/env bash
#
# Grand tour: exercises most of albs-provenance-explorer end to end on one build
#   1. provenance      - source-to-artifact trust path
#   2. identify        - point at a binary FILE -> full creation+install lineage
#   3. coverage        - five axes up the cost ladder (headers, payload ELF,
#                        dnf repoquery, soname -> providing package)
#   4. slsa            - in-toto / SLSA provenance attestation
#   5. vuln            - vulnerability-applicability report
#   6. universe        - whole-repo dependency graph (dnf repograph), persisted
#                        to SQLite and traversed
#
# Every step is gated and degrades gracefully: missing tools (dnf, zstd) or no
# network just skip, they never hard-fail the tour.
#
# Env:
#   BUILD_ID (default 57810)   PACKAGE (default nginx-core)   ARCH (default x86_64)
#   FILE  (default /usr/sbin/nginx)   OWNER (default $PACKAGE)  -- for `identify`
#   REPO  (default appstream)  whole-repo universe via `dnf repograph` (AlmaLinux)
#   VERBOSE (default 1) per-claim reconciliation detail; VERBOSE=0 for summaries
#   SBOM_FILE (default examples/build-<id>.cyclonedx.json) real alma-sbom CycloneDX;
#             attached to trust-path/coverage/vuln when present -> closes the trust
#             path's has_sbom and lifts the identity axis to 1.00. Regenerate with:
#             alma-sbom --file-format cyclonedx-json build --build-id <id> -o SBOM_FILE
#   ERRATA_FILE (optional, no default) real errata JSON {id,type,severity,cves};
#             attached to trust-path/coverage/vuln when set -> closes has_errata_link.
#             Nothing is fabricated, so without a real file the errata link stays open.
#
# Retarget examples:
#   VERBOSE=0 ./example--tour.sh
#   BUILD_ID=58167 PACKAGE=libsndfile FILE=/usr/lib64/libsndfile.so.1 OWNER=libsndfile ./example--tour.sh
#
set -uo pipefail

BUILD_ID="${BUILD_ID:-57810}"
PACKAGE="${PACKAGE:-nginx-core}"
ARCH="${ARCH:-x86_64}"
FILE="${FILE:-/usr/sbin/nginx}"
OWNER="${OWNER:-$PACKAGE}"
REPO="${REPO:-appstream}"
VERBOSE="${VERBOSE:-1}"
LIVE_DIR="${LIVE_DIR:-examples/live-build-$BUILD_ID}"
CACHE="${CACHE:-$LIVE_DIR/build-$BUILD_ID.albs.json}"
SBOM_FILE="${SBOM_FILE:-examples/build-$BUILD_ID.cyclonedx.json}"
ERRATA_FILE="${ERRATA_FILE:-}"

mkdir -p "$LIVE_DIR"

verbose_flag=""
[ "$VERBOSE" = "1" ] && verbose_flag="--verbose"

# Security-context inputs: a real build SBOM (closes has_sbom + lifts identity) and
# an optional real errata file (closes has_errata_link). Both degrade to no-ops when
# absent -- nothing is fabricated.
sbom_args=()
[ -f "$SBOM_FILE" ] && sbom_args=(--build-sbom "$SBOM_FILE")
errata_args=()
[ -n "$ERRATA_FILE" ] && [ -f "$ERRATA_FILE" ] && errata_args=(--errata "$ERRATA_FILE")

if command -v python3 >/dev/null 2>&1; then PYTHON_BIN=python3; else PYTHON_BIN=python; fi
run() {
  if command -v albs-graph >/dev/null 2>&1; then albs-graph "$@"; else "$PYTHON_BIN" -m albs_graph.cli.main "$@"; fi
}
step() { printf '\n==> %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
optional() { "$@" || printf '   (skipped: step failed or offline)\n'; }

printf '==> albs-provenance-explorer grand tour\n'
printf 'build: %s  package: %s  arch: %s  file: %s\n' "$BUILD_ID" "$PACKAGE" "$ARCH" "$FILE"

step "Fetch ALBS build metadata (cached ${CACHE})"
optional run fetch --build-id "$BUILD_ID" --cache "$CACHE" --cache-ttl 300 --format json \
  -o "$LIVE_DIR/build-$BUILD_ID.json" $verbose_flag
if [[ ! -f "$CACHE" ]]; then
  printf '\nERROR: no cached metadata at %s (need network for the first run).\n' "$CACHE" >&2
  exit 1
fi

step "1. Provenance: source-to-artifact trust path for ${PACKAGE}"
optional run trust-path --source "$CACHE" --rpm "$PACKAGE" --arch "$ARCH" \
  ${sbom_args[@]+"${sbom_args[@]}"} ${errata_args[@]+"${errata_args[@]}"} $verbose_flag

step "2. Point at a binary file: full creation + installation lineage of ${FILE}"
optional run identify "$FILE" --source "$CACHE" --owner "$OWNER" --arch "$ARCH"

step "3. Five-axis coverage up the cost ladder (headers + payload ELF + native resolution)"
cover=(--source "$CACHE" --with-rpm-headers --package "$PACKAGE" --arch "$ARCH")
if "$PYTHON_BIN" -c 'import zstandard' >/dev/null 2>&1; then
  cover+=(--with-rpm-payloads)
fi
if have dnf; then
  cover+=(--use-dnf --resolve-sonames)
fi
cover+=(${sbom_args[@]+"${sbom_args[@]}"} ${errata_args[@]+"${errata_args[@]}"})
optional run coverage "${cover[@]}" $verbose_flag

step "4. SLSA / in-toto provenance attestation for ${PACKAGE}"
optional run slsa "$PACKAGE" --source "$CACHE" --arch "$ARCH" -o "$LIVE_DIR/$PACKAGE.intoto.json"
[[ -f "$LIVE_DIR/$PACKAGE.intoto.json" ]] && printf '   wrote %s\n' "$LIVE_DIR/$PACKAGE.intoto.json"

step "5. Vulnerability-applicability report for ${PACKAGE}"
optional run vuln --source "$CACHE" --package "$PACKAGE" --arch "$ARCH" \
  ${sbom_args[@]+"${sbom_args[@]}"} ${errata_args[@]+"${errata_args[@]}"} $verbose_flag

if have dnf && [[ -n "$REPO" ]]; then
  step "6. Dependency universe via 'dnf repograph ${REPO}' (build, persist, traverse)"
  dot="$LIVE_DIR/$REPO.dot"
  db="$LIVE_DIR/universe-$REPO.db"
  if dnf repograph --repo "$REPO" > "$dot" 2>/dev/null && [[ -s "$dot" ]]; then
    # Build + persist; the summary now ranks the most-depended-upon packages.
    optional run universe --repograph-dot "$dot" --save "$db"
    # Then traverse both directions for the top (most-referenced) package.
    top=$(grep -oE '"[^"]+"' "$dot" | tr -d '"' | grep -vE '[ ]' | sort | uniq -c | sort -rn | head -1 | sed -E 's/^ *[0-9]+ +//')
    if [ -n "$top" ]; then
      printf '\n   blast radius -- packages that directly require %s (first 8):\n' "$top"
      run universe --db "$db" --dependents-of "$top" 2>/dev/null | head -9
      printf '   ...and what %s itself requires:\n' "$top"
      run universe --db "$db" --dependencies-of "$top" 2>/dev/null | head -9
    fi
  else
    printf '   (skipped: dnf repograph --repo %s produced no graph)\n' "$REPO"
  fi
else
  step "6. Universe skipped (needs dnf + REPO; set REPO=appstream on an AlmaLinux host)"
fi

printf '\n==> Done. VERBOSE=0 for concise output; set BUILD_ID/PACKAGE/FILE/OWNER/REPO to retarget.\n'

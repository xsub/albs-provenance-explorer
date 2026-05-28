#!/usr/bin/env bash
#
# THE comprehensive demo: exercises every albs-provenance-explorer command and
# feature end to end on one build/package, writing README-ready artifacts into
# OUT_DIR. Every step is gated and skips gracefully when a tool, file, or the
# network is missing -- all data is observed from public sources; nothing is
# fabricated.
#
# Commands covered: fetch, trust-path, identify, coverage, license, vuln,
# import-sbom, resolve, checkout-source, source-evidence, inspect-rpm, slsa,
# universe, fixture / render-fixture / inspect-fixture, plus the verbose
# build-intelligence view (artifact matrix + build/signing/processing timing).
#
# Artifacts in OUT_DIR: console.txt, build-<id>.svg, <pkg>-<id>-trust.svg,
# <pkg>-source-build-<id>.svg, universe-<pkg>-deps-<id>.svg, <pkg>.intoto.json,
# build-<id>-artifact-inventory.json, build-<id>-processing-analysis.json.
#
# Defaults to AlmaLinux 10 build 57810 / nginx-core. Override via env:
#   BUILD_ID PACKAGE ARCH FILE OWNER REPO OUT_DIR SBOM_FILE FIXTURE_PKG
# Optional inputs (each step skips cleanly without them, fabricating nothing):
#   ERRATA_FILE                       real errata JSON {id,type,severity,cves}
#                                     -> closes the trust path's has_errata_link
#   CPE_FILE                          CPE dictionary JSON -> NVD-verified identity
#   RESOLVE_ECOSYSTEM+RESOLVE_MANIFEST  language-native resolution (go/cargo/pypi/npm)
#   RPM_FILE                          a local .rpm to inspect with inspect-rpm
#
# SVG rendering needs Graphviz (dot) on PATH. The SBOM step reads a committed
# real alma-sbom output (SBOM_FILE); regenerate on an AlmaLinux host with:
#   alma-sbom --file-format cyclonedx-json build --build-id 57810 -o SBOM_FILE
#
set -uo pipefail

BUILD_ID="${BUILD_ID:-57810}"
PACKAGE="${PACKAGE:-nginx-core}"
ARCH="${ARCH:-x86_64}"
FILE="${FILE:-/usr/sbin/nginx}"
OWNER="${OWNER:-$PACKAGE}"
REPO="${REPO:-appstream}"
SBOM_FILE="${SBOM_FILE:-examples/build-$BUILD_ID.cyclonedx.json}"
ERRATA_FILE="${ERRATA_FILE:-}"
CPE_FILE="${CPE_FILE:-}"
RESOLVE_ECOSYSTEM="${RESOLVE_ECOSYSTEM:-}"
RESOLVE_MANIFEST="${RESOLVE_MANIFEST:-}"
RPM_FILE="${RPM_FILE:-}"
FIXTURE_PKG="${FIXTURE_PKG:-demo-pkg}"
LIVE_DIR="${LIVE_DIR:-examples/live-build-$BUILD_ID}"
OUT_DIR="${OUT_DIR:-examples/demo-build-$BUILD_ID}"
CACHE="${CACHE:-$LIVE_DIR/build-$BUILD_ID.albs.json}"
export COLUMNS="${COLUMNS:-200}"

mkdir -p "$OUT_DIR" "$LIVE_DIR"

if command -v python3 >/dev/null 2>&1; then PYTHON_BIN=python3; else PYTHON_BIN=python; fi
run() {
  if command -v albs-graph >/dev/null 2>&1; then albs-graph "$@"; else "$PYTHON_BIN" -m albs_graph.cli.main "$@"; fi
}
step() { printf '\n========== %s ==========\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
opt() { "$@" || printf '   (skipped: step failed or offline)\n'; }

main() {
  printf '== albs-provenance-explorer :: comprehensive demo ==\n'
  printf 'build=%s  package=%s  arch=%s  file=%s  repo=%s\n' \
    "$BUILD_ID" "$PACKAGE" "$ARCH" "$FILE" "$REPO"
  printf 'tools: dnf=%s rpmkeys=%s cas=%s dot=%s git=%s zstandard=%s\n' \
    "$(have dnf && echo yes || echo no)" "$(have rpmkeys && echo yes || echo no)" \
    "$(have cas && echo yes || echo no)" "$(have dot && echo yes || echo no)" \
    "$(have git && echo yes || echo no)" \
    "$("$PYTHON_BIN" -c 'import zstandard' >/dev/null 2>&1 && echo yes || echo no)"

  step "Fetch ALBS build metadata (cached ${CACHE})"
  opt run fetch --build-id "$BUILD_ID" --cache "$CACHE" --cache-ttl 86400 \
    --format json -o "$LIVE_DIR/build-$BUILD_ID.json" --verbose
  if [[ ! -f "$CACHE" ]]; then
    printf 'ERROR: no cached metadata at %s (need network for the first run).\n' "$CACHE"
    return 1
  fi

  # Optional security-context + identity inputs, threaded into the report steps
  # below when present. Nothing is fabricated -- absent files are simply skipped.
  local sbom_args=() errata_args=() cpe_args=()
  [[ -f "$SBOM_FILE" ]] && sbom_args=(--build-sbom "$SBOM_FILE")
  [[ -n "$ERRATA_FILE" && -f "$ERRATA_FILE" ]] && errata_args=(--errata "$ERRATA_FILE")
  [[ -n "$CPE_FILE" && -f "$CPE_FILE" ]] && cpe_args=(--verify-cpe "$CPE_FILE")

  step "1. Provenance: source-to-artifact trust path for ${PACKAGE}"
  opt run trust-path --source "$CACHE" --rpm "$PACKAGE" --arch "$ARCH" \
    ${sbom_args[@]+"${sbom_args[@]}"} ${errata_args[@]+"${errata_args[@]}"} --verbose

  step "2. Point at a binary file: full lineage of ${FILE}"
  opt run identify "$FILE" --source "$CACHE" --owner "$OWNER" --arch "$ARCH" \
    ${sbom_args[@]+"${sbom_args[@]}"}

  step "3. Five-axis coverage up the cost ladder (headers, payload ELF, dnf, sonames, GPG sigs, CAS, CPE)"
  local cover=(--source "$CACHE" --package "$PACKAGE" --arch "$ARCH" --with-rpm-headers)
  "$PYTHON_BIN" -c 'import zstandard' >/dev/null 2>&1 && cover+=(--with-rpm-payloads)
  have dnf && cover+=(--use-dnf --resolve-sonames)
  have rpmkeys && cover+=(--verify-signatures)
  have cas && cover+=(--use-cas)
  cover+=(${sbom_args[@]+"${sbom_args[@]}"} ${errata_args[@]+"${errata_args[@]}"} ${cpe_args[@]+"${cpe_args[@]}"})
  opt run coverage "${cover[@]}" --verbose

  step "4. License rollup (real RPM licenses: subject from header in step 3, deps via dnf)"
  if have dnf; then
    opt run license --source "$CACHE" --rpm-licenses --package "$PACKAGE" --arch "$ARCH" --verbose
  else
    printf '   (skipped: needs dnf; the subject license still appears in step 3 from the RPM header)\n'
  fi

  step "5. Vulnerability-applicability report"
  opt run vuln --source "$CACHE" --package "$PACKAGE" --arch "$ARCH" \
    ${sbom_args[@]+"${sbom_args[@]}"} ${errata_args[@]+"${errata_args[@]}"}

  step "6. Real CycloneDX SBOM ingest (from AlmaLinux alma-sbom, no fake data)"
  if [[ -f "$SBOM_FILE" ]]; then
    run import-sbom "$SBOM_FILE" --format json 2>/dev/null \
      | "$PYTHON_BIN" -c 'import sys,json; d=json.load(sys.stdin); print("   imported %d package nodes + %d edges from a real alma-sbom build SBOM" % (len([n for n in d.get("nodes",[]) if n.get("type")=="external_package"]), len(d.get("edges",[]))))' \
      || printf '   (skipped: import failed)\n'
    printf '   source: %s (regenerate: alma-sbom --file-format cyclonedx-json build --build-id %s)\n' "$SBOM_FILE" "$BUILD_ID"
  else
    printf '   (skipped: no SBOM at %s; generate one with alma-sbom)\n' "$SBOM_FILE"
  fi

  step "7. Native dependency resolution (language manifest -> go list / cargo metadata / ...)"
  if [[ -n "$RESOLVE_ECOSYSTEM" && -n "$RESOLVE_MANIFEST" && -f "$RESOLVE_MANIFEST" ]]; then
    opt run resolve --ecosystem "$RESOLVE_ECOSYSTEM" --manifest "$RESOLVE_MANIFEST" \
      --source "$CACHE" --subject "$PACKAGE" --arch "$ARCH" --verbose
  else
    printf '   (skipped: set RESOLVE_ECOSYSTEM=go|cargo|pypi|npm and RESOLVE_MANIFEST=<go.mod|...>;\n'
    printf '            needs the native tool on PATH -- an RPM build carries no language manifest itself)\n'
  fi

  step "8. Checkout the exact ALBS git source commit, then analyze source evidence"
  if have git; then
    opt run checkout-source --build-id "$BUILD_ID" --package "$PACKAGE" \
      --dest "$LIVE_DIR/src-$PACKAGE" --cache "$CACHE"
    opt run source-evidence --build-id "$BUILD_ID" --package "$PACKAGE" \
      --cache "$CACHE" --cache-ttl 86400 --verbose
  else
    printf '   (skipped: needs git + network to checkout the ALBS source commit)\n'
  fi

  step "9. Inspect a local RPM header (rpmfile)"
  if [[ -n "$RPM_FILE" && -f "$RPM_FILE" ]]; then
    opt run inspect-rpm "$RPM_FILE"
  else
    printf '   (skipped: set RPM_FILE=<path/to.rpm> to inspect a local RPM header)\n'
  fi

  step "10. SLSA / in-toto provenance attestation"
  opt run slsa "$PACKAGE" --source "$CACHE" --arch "$ARCH" -o "$OUT_DIR/$PACKAGE.intoto.json"
  [[ -f "$OUT_DIR/$PACKAGE.intoto.json" ]] && printf '   wrote %s\n' "$OUT_DIR/$PACKAGE.intoto.json"

  step "11. Build intelligence: artifact matrix + build/signing/processing timing (verbose analyzer)"
  opt "$PYTHON_BIN" -m albs_graph.cli.demo_verbose \
    --build-id "$BUILD_ID" --rpm "$PACKAGE" --arch "$ARCH" \
    --out-dir "$OUT_DIR" --live-dir "$LIVE_DIR" --cache "$CACHE" --cache-ttl 86400 --verify-git 0

  step "12. Render graphs to SVG (full build, focused trust path, whole-source fan-out)"
  if have dot; then
    opt run fetch --build-id "$BUILD_ID" --cache "$CACHE" --cache-ttl 86400 \
      --format svg -o "$OUT_DIR/build-$BUILD_ID.svg"
    printf '   wrote %s (full build graph)\n' "$OUT_DIR/build-$BUILD_ID.svg"
    opt run trust-path --source "$CACHE" --rpm "$PACKAGE" --arch "$ARCH" \
      --format svg -o "$OUT_DIR/$PACKAGE-$BUILD_ID-trust.svg"
    printf '   wrote %s (focused trust path)\n' "$OUT_DIR/$PACKAGE-$BUILD_ID-trust.svg"
    opt run trust-path --source "$CACHE" --rpm "$PACKAGE" --arch "$ARCH" --whole-source \
      --format svg -o "$OUT_DIR/$PACKAGE-source-build-$BUILD_ID.svg"
    printf '   wrote %s (source build fan-out: one source -> all its RPMs)\n' \
      "$OUT_DIR/$PACKAGE-source-build-$BUILD_ID.svg"
  else
    printf '   (skipped: Graphviz "dot" not on PATH)\n'
  fi

  step "13. Offline synthetic fixture (no network): build, render, inspect"
  opt run fixture "$FIXTURE_PKG" --format json -o "$LIVE_DIR/fixture-$FIXTURE_PKG.json"
  [[ -f "$LIVE_DIR/fixture-$FIXTURE_PKG.json" ]] && \
    printf '   wrote %s (synthetic graph)\n' "$LIVE_DIR/fixture-$FIXTURE_PKG.json"
  if have dot; then
    opt run render-fixture "$FIXTURE_PKG" --format svg -o "$OUT_DIR/fixture-$FIXTURE_PKG.svg"
    [[ -f "$OUT_DIR/fixture-$FIXTURE_PKG.svg" ]] && \
      printf '   wrote %s (synthetic graph SVG)\n' "$OUT_DIR/fixture-$FIXTURE_PKG.svg"
  fi
  opt run inspect-fixture "$FIXTURE_PKG"

  step "14. Dependency universe via 'dnf repograph ${REPO}' (build, persist, traverse)"
  if have dnf; then
    local dot="$LIVE_DIR/$REPO.dot" db="$LIVE_DIR/universe-$REPO.db"
    if dnf repograph --repo "$REPO" > "$dot" 2>/dev/null && [[ -s "$dot" ]]; then
      opt run universe --repograph-dot "$dot" --save "$db"
      local top
      top=$(grep -oE '"[^"]+"' "$dot" | tr -d '"' | grep -vE '[ ]' | sort | uniq -c | sort -rn | head -1 | sed -E 's/^ *[0-9]+ +//')
      if [[ -n "$top" ]]; then
        printf '\n   blast radius -- packages that directly require %s (first 8):\n' "$top"
        run universe --db "$db" --dependents-of "$top" 2>/dev/null | head -9
      fi
      if have dot; then
        opt run universe --db "$db" --dependencies-of "$PACKAGE" --format svg \
          -o "$OUT_DIR/universe-$PACKAGE-deps-$BUILD_ID.svg"
        printf '   wrote %s (%s dependency neighbourhood)\n' \
          "$OUT_DIR/universe-$PACKAGE-deps-$BUILD_ID.svg" "$PACKAGE"
      fi
    else
      printf '   (skipped: dnf repograph --repo %s produced no graph)\n' "$REPO"
    fi
  else
    printf '   (skipped: needs dnf on an AlmaLinux host)\n'
  fi

  printf '\n== Done. Artifacts in %s: console.txt, *.svg, *.json, %s.intoto.json ==\n' "$OUT_DIR" "$PACKAGE"
}

main 2>&1 | tee "$OUT_DIR/console.txt"

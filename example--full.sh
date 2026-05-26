#!/usr/bin/env bash
#
# Fullest single-command demo for one build/package. Exercises (almost) every
# feature end to end and writes README-ready artifacts into OUT_DIR:
#   - console.txt                  : everything printed below (the demo log)
#   - build-<id>.svg               : full build provenance graph (Graphviz)
#   - <pkg>-<id>-trust.svg         : focused source-to-artifact trust path
#   - universe-<pkg>-deps-<id>.svg : <pkg>'s dependency neighbourhood (best effort)
#   - <pkg>.intoto.json            : SLSA / in-toto provenance attestation
#
# Steps: provenance trust path, identify (file -> lineage), five-axis coverage up
# the cost ladder (headers + payload ELF + dnf repoquery + soname->package + GPG
# signatures + CAS), vulnerability + SLSA reports, and the dependency universe
# (dnf repograph -> SQLite -> traverse). Every step is gated and skips gracefully
# when a tool or the network is missing - nothing is fabricated.
#
# Defaults to AlmaLinux 10 build 57810 / nginx-core. Override via env:
#   BUILD_ID PACKAGE ARCH FILE OWNER REPO OUT_DIR
#
# SVG rendering needs Graphviz (dot) on PATH; without it the graphs are skipped.
#
set -uo pipefail

BUILD_ID="${BUILD_ID:-57810}"
PACKAGE="${PACKAGE:-nginx-core}"
ARCH="${ARCH:-x86_64}"
FILE="${FILE:-/usr/sbin/nginx}"
OWNER="${OWNER:-$PACKAGE}"
REPO="${REPO:-appstream}"
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
  printf '== albs-provenance-explorer :: full demo ==\n'
  printf 'build=%s  package=%s  arch=%s  file=%s  repo=%s\n' \
    "$BUILD_ID" "$PACKAGE" "$ARCH" "$FILE" "$REPO"
  printf 'tools: dnf=%s rpmkeys=%s cas=%s dot=%s zstandard=%s\n' \
    "$(have dnf && echo yes || echo no)" "$(have rpmkeys && echo yes || echo no)" \
    "$(have cas && echo yes || echo no)" "$(have dot && echo yes || echo no)" \
    "$("$PYTHON_BIN" -c 'import zstandard' >/dev/null 2>&1 && echo yes || echo no)"

  step "Fetch ALBS build metadata (cached ${CACHE})"
  opt run fetch --build-id "$BUILD_ID" --cache "$CACHE" --cache-ttl 86400 \
    --format json -o "$LIVE_DIR/build-$BUILD_ID.json" --verbose
  if [[ ! -f "$CACHE" ]]; then
    printf 'ERROR: no cached metadata at %s (need network for the first run).\n' "$CACHE"
    return 1
  fi

  step "1. Provenance: source-to-artifact trust path for ${PACKAGE}"
  opt run trust-path --source "$CACHE" --rpm "$PACKAGE" --arch "$ARCH" --verbose

  step "2. Point at a binary file: full lineage of ${FILE}"
  opt run identify "$FILE" --source "$CACHE" --owner "$OWNER" --arch "$ARCH"

  step "3. Five-axis coverage up the cost ladder (verbose)"
  local cover=(--source "$CACHE" --package "$PACKAGE" --arch "$ARCH" --with-rpm-headers)
  "$PYTHON_BIN" -c 'import zstandard' >/dev/null 2>&1 && cover+=(--with-rpm-payloads)
  have dnf && cover+=(--use-dnf --resolve-sonames)
  have rpmkeys && cover+=(--verify-signatures)
  have cas && cover+=(--use-cas)
  opt run coverage "${cover[@]}" --verbose

  step "4. Vulnerability-applicability report"
  opt run vuln --source "$CACHE" --package "$PACKAGE" --arch "$ARCH"

  step "5. SLSA / in-toto provenance attestation"
  opt run slsa "$PACKAGE" --source "$CACHE" --arch "$ARCH" -o "$OUT_DIR/$PACKAGE.intoto.json"
  [[ -f "$OUT_DIR/$PACKAGE.intoto.json" ]] && printf '   wrote %s\n' "$OUT_DIR/$PACKAGE.intoto.json"

  step "6. Render graphs to SVG"
  if have dot; then
    opt run fetch --build-id "$BUILD_ID" --cache "$CACHE" --cache-ttl 86400 \
      --format svg -o "$OUT_DIR/build-$BUILD_ID.svg"
    printf '   wrote %s (full build graph)\n' "$OUT_DIR/build-$BUILD_ID.svg"
    opt run trust-path --source "$CACHE" --rpm "$PACKAGE" --arch "$ARCH" \
      --format svg -o "$OUT_DIR/$PACKAGE-$BUILD_ID-trust.svg"
    printf '   wrote %s (trust path)\n' "$OUT_DIR/$PACKAGE-$BUILD_ID-trust.svg"
  else
    printf '   (skipped: Graphviz "dot" not on PATH)\n'
  fi

  step "7. Dependency universe via 'dnf repograph ${REPO}' (build, persist, traverse)"
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

  printf '\n== Done. Artifacts in %s: console.txt, *.svg, %s.intoto.json ==\n' "$OUT_DIR" "$PACKAGE"
}

main 2>&1 | tee "$OUT_DIR/console.txt"

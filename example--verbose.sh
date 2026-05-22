#!/usr/bin/env bash
set -euo pipefail

BUILD_ID="${BUILD_ID:-17812}"
RPM_NAME="${RPM_NAME:-nginx-core}"
ARCH="${ARCH:-x86_64}"
OUT_DIR="${OUT_DIR:-examples/demo-nginx-core}"
LIVE_DIR="${LIVE_DIR:-examples/live-build-17812}"
CACHE_FILE="${CACHE_FILE:-$LIVE_DIR/build-$BUILD_ID.albs.json}"

mkdir -p "$OUT_DIR" "$LIVE_DIR"

run_albs_graph() {
  if command -v albs-graph >/dev/null 2>&1; then
    albs-graph "$@"
  else
    python -m albs_graph.cli.main "$@"
  fi
}

printf '==> Fetching full ALBS build %s once, then reusing cache for JSON/DOT/SVG
' "$BUILD_ID"
printf '==> Raw ALBS metadata cache: %s
' "$CACHE_FILE"
run_albs_graph fetch --build-id "$BUILD_ID" --cache "$CACHE_FILE" --format json --verbose -o "$LIVE_DIR/build-$BUILD_ID.json"
run_albs_graph fetch --build-id "$BUILD_ID" --cache "$CACHE_FILE" --format dot --verbose -o "$LIVE_DIR/build-$BUILD_ID.dot"
run_albs_graph fetch --build-id "$BUILD_ID" --cache "$CACHE_FILE" --format svg --verbose -o "$LIVE_DIR/build-$BUILD_ID.svg"

printf '==> Copying full build graph into demo directory
'
cp "$LIVE_DIR/build-$BUILD_ID.json" "$OUT_DIR/build-$BUILD_ID-full.json"
cp "$LIVE_DIR/build-$BUILD_ID.svg" "$OUT_DIR/build-$BUILD_ID-full.svg"

printf '==> Showing focused trust-path summary for %s.%s
' "$RPM_NAME" "$ARCH"
run_albs_graph trust-path --build-id "$BUILD_ID" --cache "$CACHE_FILE" --rpm "$RPM_NAME" --arch "$ARCH" --verbose

printf '==> Generating focused trust graph for %s.%s as JSON/DOT/SVG
' "$RPM_NAME" "$ARCH"
run_albs_graph trust-path --build-id "$BUILD_ID" --cache "$CACHE_FILE" --rpm "$RPM_NAME" --arch "$ARCH" --format json --verbose -o "$OUT_DIR/${RPM_NAME}-${ARCH}-trust.json"
run_albs_graph trust-path --build-id "$BUILD_ID" --cache "$CACHE_FILE" --rpm "$RPM_NAME" --arch "$ARCH" --format dot --verbose -o "$OUT_DIR/${RPM_NAME}-${ARCH}-trust.dot"
run_albs_graph trust-path --build-id "$BUILD_ID" --cache "$CACHE_FILE" --rpm "$RPM_NAME" --arch "$ARCH" --format svg --verbose -o "$OUT_DIR/${RPM_NAME}-${ARCH}-trust.svg"

printf '==> Done
'
printf 'Metadata cache: %s
' "$CACHE_FILE"
printf 'Full graph:     %s
' "$OUT_DIR/build-$BUILD_ID-full.svg"
printf 'Focused graph:  %s
' "$OUT_DIR/${RPM_NAME}-${ARCH}-trust.svg"

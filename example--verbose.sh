#!/usr/bin/env bash
set -euo pipefail

BUILD_ID="${BUILD_ID:-17812}"
RPM_NAME="${RPM_NAME:-nginx-core}"
ARCH="${ARCH:-x86_64}"
OUT_DIR="${OUT_DIR:-examples/demo-nginx-core}"
LIVE_DIR="${LIVE_DIR:-examples/live-build-17812}"

mkdir -p "$OUT_DIR" "$LIVE_DIR"

printf '==> Fetching full ALBS build %s as JSON/DOT/SVG with CAS evidence
' "$BUILD_ID"
albs-graph fetch --build-id "$BUILD_ID" --format json --verbose -o "$LIVE_DIR/build-$BUILD_ID.json"
albs-graph fetch --build-id "$BUILD_ID" --format dot --verbose -o "$LIVE_DIR/build-$BUILD_ID.dot"
albs-graph fetch --build-id "$BUILD_ID" --format svg --verbose -o "$LIVE_DIR/build-$BUILD_ID.svg"

printf '==> Copying full build graph into demo directory
'
cp "$LIVE_DIR/build-$BUILD_ID.json" "$OUT_DIR/build-$BUILD_ID-full.json"
cp "$LIVE_DIR/build-$BUILD_ID.svg" "$OUT_DIR/build-$BUILD_ID-full.svg"

printf '==> Generating focused trust graph for %s.%s as JSON/DOT/SVG
' "$RPM_NAME" "$ARCH"
albs-graph trust-path --build-id "$BUILD_ID" --rpm "$RPM_NAME" --arch "$ARCH" --format json --verbose -o "$OUT_DIR/${RPM_NAME}-${ARCH}-trust.json"
albs-graph trust-path --build-id "$BUILD_ID" --rpm "$RPM_NAME" --arch "$ARCH" --format dot --verbose -o "$OUT_DIR/${RPM_NAME}-${ARCH}-trust.dot"
albs-graph trust-path --build-id "$BUILD_ID" --rpm "$RPM_NAME" --arch "$ARCH" --format svg --verbose -o "$OUT_DIR/${RPM_NAME}-${ARCH}-trust.svg"

printf '==> Done
'
printf 'Full graph:    %s
' "$OUT_DIR/build-$BUILD_ID-full.svg"
printf 'Focused graph: %s
' "$OUT_DIR/${RPM_NAME}-${ARCH}-trust.svg"

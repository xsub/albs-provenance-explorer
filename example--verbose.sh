#!/usr/bin/env bash
set -euo pipefail

BUILD_ID="${BUILD_ID:-17812}"
RPM_NAME="${RPM_NAME:-}"
ARCH="${ARCH:-}"
OUT_DIR="${OUT_DIR:-examples/demo-build-$BUILD_ID}"
LIVE_DIR="${LIVE_DIR:-examples/live-build-17812}"
CACHE_FILE="${CACHE_FILE:-$LIVE_DIR/build-$BUILD_ID.albs.json}"
CACHE_TTL="${CACHE_TTL:-300}"
VERIFY_GIT="${VERIFY_GIT:-0}"

python3 -m albs_graph.cli.demo_verbose \
  --build-id "$BUILD_ID" \
  --rpm "$RPM_NAME" \
  --arch "$ARCH" \
  --out-dir "$OUT_DIR" \
  --live-dir "$LIVE_DIR" \
  --cache "$CACHE_FILE" \
  --cache-ttl "$CACHE_TTL" \
  --verify-git "$VERIFY_GIT"

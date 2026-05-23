#!/usr/bin/env bash
set -euo pipefail

BUILD_ID="${BUILD_ID:-17812}"
RPM_NAME="${RPM_NAME:-}"
ARCH="${ARCH:-}"
LIVE_DIR="${LIVE_DIR:-examples/live-build-17812}"
CACHE_FILE="${CACHE_FILE:-$LIVE_DIR/build-$BUILD_ID.albs.json}"
CAS_INSTALL_URL="${CAS_INSTALL_URL:-https://getcas.codenotary.io}"
SIGNER_ID="${SIGNER_ID:-cloud-infra@almalinux.org}"

mkdir -p "$LIVE_DIR"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  printf 'ERROR: python3 or python is required to run this demo.\n' >&2
  exit 1
fi

run_albs_graph() {
  if command -v albs-graph >/dev/null 2>&1; then
    albs-graph "$@"
  else
    "$PYTHON_BIN" -m albs_graph.cli.main "$@"
  fi
}

ensure_cas() {
  if command -v cas >/dev/null 2>&1; then
    printf '==> Found CAS CLI: %s\n' "$(command -v cas)"
    cas --version || true
    return
  fi

  printf 'ERROR: CAS CLI not found in PATH.\n' >&2
  printf 'Install CAS manually, then rerun this script. Suggested first attempt:\n' >&2
  printf '  curl -fsSL %s | sh\n' "$CAS_INSTALL_URL" >&2
  printf '\nIf the upstream installer returns 404, check the current Codenotary CAS install docs/releases and install cas explicitly.\n' >&2
  printf 'This script will not download or run a container image as a fallback.\n' >&2
  exit 1
}

extract_hashes() {
  "$PYTHON_BIN" - "$CACHE_FILE" "$RPM_NAME" "$ARCH" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

from albs_graph.adapters.albs import graph_from_build_metadata, parse_build_metadata
from albs_graph.provenance.trust import find_binary_rpm, select_default_binary_rpm

cache = Path(sys.argv[1])
rpm_name = sys.argv[2]
arch = sys.argv[3] or None
data = json.loads(cache.read_text(encoding="utf-8"))
metadata = parse_build_metadata(data)
graph = graph_from_build_metadata(metadata)

def first_task_hash() -> str:
    for task in data.get("tasks", []):
        value = task.get("alma_commit_cas_hash")
        if value:
            return str(value)
    raise SystemExit("missing alma_commit_cas_hash in ALBS metadata")

def selected_rpm() -> tuple[str, str]:
    if rpm_name:
        node = find_binary_rpm(graph, rpm_name, arch=arch)
    else:
        node = select_default_binary_rpm(graph, arch=arch)
    value = node.metadata.get("cas_hash")
    if not value:
        raise SystemExit(f"missing cas_hash for selected RPM {node.label} in ALBS metadata")
    return node.label, str(value)

artifact_name, artifact_cas_hash = selected_rpm()
print(f"SOURCE_PACKAGE={metadata.package}")
print(f"SOURCE_PACKAGE_SOURCE={metadata.package_source}")
print(f"SOURCE_CAS_HASH={first_task_hash()}")
print(f"ARTIFACT_NAME={artifact_name}")
print(f"ARTIFACT_CAS_HASH={artifact_cas_hash}")
PY
}

cas_authenticate_hash() {
  local label="$1"
  local hash="$2"

  printf '\n==> CAS authenticate: %s\n' "$label"
  printf 'hash: %s\n' "$hash"

  set +e
  if [[ -n "$SIGNER_ID" ]]; then
    cas authenticate --signerID "$SIGNER_ID" --hash "$hash"
  else
    cas authenticate --hash "$hash"
  fi
  local status=$?
  set -e

  if [[ $status -eq 0 ]]; then
    printf '==> CAS verification result for %s: ok\n' "$label"
  else
    printf '==> CAS verification result for %s: failed (exit %s)\n' "$label" "$status"
  fi

  return "$status"
}

printf '==> AlmaLinux CAS verification demo\n'
printf 'build: %s\n' "$BUILD_ID"
if [[ -n "$RPM_NAME" || -n "$ARCH" ]]; then
  printf 'rpm selector: %s%s%s\n' "${RPM_NAME:-<derived>}" "$([[ -n "$ARCH" ]] && printf .)" "$ARCH"
else
  printf 'rpm selector: <derived from ALBS build metadata>\n'
fi
printf 'cache: %s\n' "$CACHE_FILE"
if [[ -n "$SIGNER_ID" ]]; then
  printf 'signer: %s\n' "$SIGNER_ID"
else
  printf 'signer: <not constrained>\n'
fi

ensure_cas

printf '\n==> Fetching ALBS metadata with 5 minute cache freshness\n'
run_albs_graph fetch --build-id "$BUILD_ID" --cache "$CACHE_FILE" --cache-ttl 300 --format json --verbose -o "$LIVE_DIR/build-$BUILD_ID.json"

printf '\n==> Extracting source and artifact CAS hashes from ALBS metadata\n'
eval "$(extract_hashes)"
printf 'source pkg:   %s (%s)\n' "$SOURCE_PACKAGE" "$SOURCE_PACKAGE_SOURCE"
printf 'source CAS:   %s\n' "$SOURCE_CAS_HASH"
printf 'artifact:     %s\n' "$ARTIFACT_NAME"
printf 'artifact CAS: %s\n' "$ARTIFACT_CAS_HASH"

source_status=0
artifact_status=0
cas_authenticate_hash "source commit" "$SOURCE_CAS_HASH" || source_status=$?
cas_authenticate_hash "$ARTIFACT_NAME" "$ARTIFACT_CAS_HASH" || artifact_status=$?

printf '\n==> Summary\n'
printf 'source commit CAS: %s\n' "$([[ $source_status -eq 0 ]] && printf ok || printf failed)"
printf 'artifact CAS:      %s\n' "$([[ $artifact_status -eq 0 ]] && printf ok || printf failed)"

if [[ $source_status -ne 0 || $artifact_status -ne 0 ]]; then
  exit 2
fi

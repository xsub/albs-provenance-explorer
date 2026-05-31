#!/usr/bin/env bash
#
# run.sh -- complete provenance inspection for ONE ALBS build, pulling from every
# source the host can satisfy.  Give it a build id; everything else is automatic.
#
#   ./run.sh 57810
#   BUILD_ID=57810 ./run.sh
#
# It is the parameterised template behind the workbench's "Run Full Inspection"
# action and the narrated example--full.sh demo: fetch the ALBS build metadata,
# then run coverage + vuln + license + slsa with all the source flags the host
# actually supports -- dnf repoquery/whatprovides, RPM header + payload reads,
# GPG signature verification, build-SBOM auto-discovery, the live
# errata.almalinux.org feed, and (optionally) NVD CPE/CVE feeds.
#
# Knobs (env vars, all optional):
#   OUT_DIR=out/build-<id>     where artifacts + the metadata cache are written
#   ARCH=<arch>                pin one architecture (default: x86_64 + noarch)
#   ALL_ARCHS=1                enrich every architecture instead
#   ERRATA_SOURCE=http|dnf|off live errata source (default http = almalinux.org)
#   VERIFY_CPE_URL=<url>       NVD CPE dictionary JSON (verifies identity)
#   CVE_FEED_URL=<url>         live CVE feed JSON (potentially-affected matching)
#
set -euo pipefail

BUILD_ID="${1:-${BUILD_ID:-}}"
if [[ -z "$BUILD_ID" ]]; then
  echo "usage: $0 <build_id>   (or BUILD_ID=<id> $0)" >&2
  exit 2
fi

OUT_DIR="${OUT_DIR:-out/build-${BUILD_ID}}"
CACHE="${CACHE:-${OUT_DIR}/build-${BUILD_ID}.albs.json}"
ARCH="${ARCH:-}"
ALL_ARCHS="${ALL_ARCHS:-0}"
ERRATA_SOURCE="${ERRATA_SOURCE:-http}"
VERIFY_CPE_URL="${VERIFY_CPE_URL:-}"
CVE_FEED_URL="${CVE_FEED_URL:-}"
mkdir -p "$OUT_DIR"

# albs-graph entry point: installed console script, else the module.
g() {
  if command -v albs-graph >/dev/null 2>&1; then albs-graph "$@";
  else "${PYTHON_BIN:-python3}" -m albs_graph.cli.main "$@"; fi
}
have() { command -v "$1" >/dev/null 2>&1; }

# --- assemble the flags the host can actually satisfy ------------------------
cover=(--build-id "$BUILD_ID" --cache "$CACHE" --with-rpm-headers)
"${PYTHON_BIN:-python3}" -c 'import zstandard' >/dev/null 2>&1 && cover+=(--with-rpm-payloads)
have dnf && cover+=(--use-dnf --resolve-sonames)
have rpmkeys && cover+=(--verify-signatures)
if [[ "$ALL_ARCHS" == "1" ]]; then cover+=(--all-archs); elif [[ -n "$ARCH" ]]; then cover+=(--arch "$ARCH"); fi
[[ "$ERRATA_SOURCE" != "off" ]] && cover+=(--errata-source "$ERRATA_SOURCE")
[[ -n "$VERIFY_CPE_URL" ]] && cover+=(--verify-cpe-url "$VERIFY_CPE_URL")

vuln=(--source "$CACHE" --errata-source "$ERRATA_SOURCE")
[[ -n "$VERIFY_CPE_URL" ]] && vuln+=(--verify-cpe-url "$VERIFY_CPE_URL")
[[ -n "$CVE_FEED_URL" ]] && vuln+=(--cve-feed-url "$CVE_FEED_URL")
[[ "$ERRATA_SOURCE" == "off" ]] && vuln=(--source "$CACHE")

echo "== run.sh: full inspection for ALBS build ${BUILD_ID} =="
echo "   tools: dnf=$(have dnf && echo yes || echo no) rpmkeys=$(have rpmkeys && echo yes || echo no) dot=$(have dot && echo yes || echo no)"
echo "   out:   ${OUT_DIR}"

echo "-- coverage (every source rung; prints the report, writes the metadata cache) --"
g coverage "${cover[@]}" --verbose | tee "${OUT_DIR}/coverage.txt"

echo "-- vulnerability report --"
g vuln "${vuln[@]}" --format json | tee "${OUT_DIR}/vuln.json"

echo "-- license rollup --"
g license --source "$CACHE" --format json | tee "${OUT_DIR}/license.json"

echo "-- SLSA / in-toto provenance --"
g slsa --source "$CACHE" --output "${OUT_DIR}/slsa.intoto.json"

echo "== done. artifacts in ${OUT_DIR}: coverage.txt vuln.json license.json slsa.intoto.json =="

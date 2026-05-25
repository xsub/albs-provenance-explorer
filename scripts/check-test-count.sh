#!/usr/bin/env bash
#
# Cross-check every "N tests" figure cited in README.md / docs/*.md against the
# real pytest collection count, so the docs cannot silently go stale.
#
# Used as a pre-commit hook (see CLAUDE.md) and runnable standalone:
#   bash scripts/check-test-count.sh
#
# Convention: a bare "N tests" figure in the docs always means the FULL suite.
# Mention a subset some other way (e.g. "N test cases for X").
#
# Degrades gracefully: if pytest cannot collect (dev env not active), it skips
# rather than blocking. Bypass once with:  SKIP_TESTCOUNT=1 git commit ...
#
set -uo pipefail

[ "${SKIP_TESTCOUNT:-0}" = "1" ] && exit 0

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || exit 0

# Resolve a pytest that can import the package; skip if none is available.
if command -v pytest >/dev/null 2>&1; then
  pytest_cmd() { pytest "$@"; }
elif python3 -c 'import pytest' >/dev/null 2>&1; then
  pytest_cmd() { python3 -m pytest "$@"; }
else
  echo "check-test-count: pytest unavailable; skipping." >&2
  exit 0
fi

# Count collected test node IDs (matches pytest's own "N tests collected").
actual="$(pytest_cmd --collect-only -q 2>/dev/null | grep -cE '::' || true)"
if ! [ "${actual:-0}" -gt 0 ] 2>/dev/null; then
  echo "check-test-count: could not collect tests (dev env not active?); skipping." >&2
  exit 0
fi

rc=0
while IFS= read -r hit; do
  # hit looks like: path:lineno:NNN tests
  num="$(printf '%s\n' "$hit" | grep -oE '[0-9]+ tests' | grep -oE '[0-9]+')"
  file="${hit%%:*}"
  if [ -n "$num" ] && [ "$num" != "$actual" ]; then
    echo "check-test-count: $file cites '$num tests' but the suite has $actual." >&2
    rc=1
  fi
done < <(grep -rnoE '[0-9]+ tests' README.md docs/*.md 2>/dev/null)

if [ "$rc" != "0" ]; then
  echo "check-test-count: update the figure(s) to $actual (or bypass once with SKIP_TESTCOUNT=1)." >&2
fi
exit "$rc"

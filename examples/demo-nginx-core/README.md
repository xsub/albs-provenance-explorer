# nginx-core ALBS Trust Path Demo

This directory contains a compact demo built from public ALBS build `17812`. The full build is an AlmaLinux 9 `nginx` build; the focused graph follows one binary RPM artifact: `nginx-core-1.20.1-16.el9_4.1.x86_64.rpm`.

## Files

- `trust-path-console.png` - terminal screenshot of the verbose single-pass trust-path demo with optional git commit verification.
- `trust-path-console.svg` - rendered terminal capture used by the top-level README.
- `trust-path-console.txt` - text capture of the same demo output.
- `nginx-core-x86_64-trust.svg` - focused source-to-artifact trust graph.
- `nginx-core-x86_64-trust.dot` - Graphviz DOT for the focused graph.
- `nginx-core-x86_64-trust.json` - JSON export for the focused graph.
- `build-17812-full.svg` - full ALBS build graph for comparison.
- `build-17812-full.json` - full ALBS build graph JSON export.
- `build-17812-artifact-inventory.json` - RPM artifact matrix extracted from ALBS build metadata.
- `build-17812-processing-analysis.json` - build task, signing and artifact processing timing analysis.

## Build Matrix And Timing

The focused graph follows `nginx-core.x86_64`, but the source build itself produced artifacts for every ALBS build task architecture present in build `17812`:

- `96` RPM artifact rows are exported from the ALBS metadata.
- inventory rows are keyed by producer `build_arch` and output `artifact_arch`, so repeated SRPM and `noarch` artifacts stay attached to the task that emitted them.
- `x86_64`, `aarch64`, `ppc64le`, `s390x` and `i686` each contribute `19` RPM rows: `16` arch-specific binary RPMs, `2` `noarch` RPMs and `1` SRPM.
- the `src` build task contributes the canonical SRPM row.
- the processing analysis covers `173` raw artifacts total: `96` RPM artifacts and `77` build-log/config artifacts.
- observed wall time was `13.6m`; aggregate build task wall time was `37.7m`; critical task wall time was `8.1m`.
- signing/notarization wall time was `4.3m`, including package signing, CAS notarization, upload and web-server processing.

This keeps the visual graph small enough to review while preserving the full multi-architecture build evidence as JSON.

## Regenerate

```bash
RPM_NAME=nginx-core ARCH=x86_64 OUT_DIR=examples/demo-nginx-core ./example--verbose.sh
```

Lower-level commands for only the focused graph:

```bash
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format json -o examples/demo-nginx-core/nginx-core-x86_64-trust.json
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format dot -o examples/demo-nginx-core/nginx-core-x86_64-trust.dot
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format svg -o examples/demo-nginx-core/nginx-core-x86_64-trust.svg
```

## Focused Graph

![nginx-core focused trust graph](nginx-core-x86_64-trust.svg)

## Console Report

```bash
RPM_NAME=nginx-core ARCH=x86_64 OUT_DIR=examples/demo-nginx-core VERIFY_GIT=1 ./example--verbose.sh
```

![nginx-core trust-path console report](trust-path-console.svg)

See [`trust-path-console.txt`](trust-path-console.txt) for the full text output. The current verbose demo also prints the artifact matrix and processing timeline before the focused trust-path report.

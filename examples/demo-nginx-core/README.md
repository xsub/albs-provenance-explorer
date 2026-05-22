# nginx-core ALBS Trust Path Demo

This directory contains a compact demo built from public ALBS build `17812`. The full build is an AlmaLinux 9 `nginx` build; the focused graph follows one binary RPM artifact: `nginx-core-1.20.1-16.el9_4.1.x86_64.rpm`.

## Files

- `trust-path-console.svg` - current Rich render of the CLI trust-path report.
- `trust-path-console.png` - original terminal screenshot kept as a demo artifact.
- `nginx-core-x86_64-trust.svg` - focused source-to-artifact trust graph.
- `nginx-core-x86_64-trust.dot` - Graphviz DOT for the focused graph.
- `nginx-core-x86_64-trust.json` - JSON export for the focused graph.
- `build-17812-full.svg` - full ALBS build graph for comparison.
- `build-17812-full.json` - full ALBS build graph JSON export.

## Regenerate

```bash
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format json -o examples/demo-nginx-core/nginx-core-x86_64-trust.json
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format dot -o examples/demo-nginx-core/nginx-core-x86_64-trust.dot
albs-graph trust-path --build-id 17812 --rpm nginx-core --arch x86_64 --format svg -o examples/demo-nginx-core/nginx-core-x86_64-trust.svg
albs-graph fetch --build-id 17812 --format svg -o examples/demo-nginx-core/build-17812-full.svg
```

## Focused Graph

![nginx-core focused trust graph](nginx-core-x86_64-trust.svg)

## Console Report

![nginx-core trust-path console report](trust-path-console.svg)

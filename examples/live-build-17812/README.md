# Live ALBS Build 17812 Example

These files were generated from the public ALBS API endpoint:

```text
https://build.almalinux.org/api/v1/builds/17812/
```

Build `17812` is an `nginx` build for AlmaLinux 9. The exported graph preserves the source package, git repository, exact commit, CAS source and artifact evidence, ALBS build task, per-architecture build tasks, build environments, SRPMs, binary RPMs, test tasks, signing task and release linkage.

Regenerate:

```bash
albs-graph fetch --build-id 17812 --format json -o examples/live-build-17812/build-17812.json
albs-graph fetch --build-id 17812 --format dot -o examples/live-build-17812/build-17812.dot
albs-graph fetch --build-id 17812 --format svg -o examples/live-build-17812/build-17812.svg
```

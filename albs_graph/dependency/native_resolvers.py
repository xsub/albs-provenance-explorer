"""Real per-ecosystem resolvers behind the ResolverResult contract (rung 5).

The authoritative tool for each ecosystem is the source of truth (CLAUDE.md), so
these shell out rather than reimplement resolution:

- ``GoResolver``    -> ``go list -m all`` (reads go.mod/go.sum)
- ``CargoResolver`` -> ``cargo metadata --format-version 1`` (reads Cargo.lock)
- ``PypiResolver``  -> ``pip install --dry-run --report - -r REQS`` (pip>=22.2)
- ``MavenResolver`` -> ``mvn -B dependency:list`` (parses ``[INFO]    g:a:p:v:scope``)
- ``NpmResolver``   -> ``npm ls --json --all`` (recursively walk the dep tree)

Each satisfies the ``DependencyResolver`` protocol and returns a
``ResolverResult`` whose ``resolved`` specs carry concrete versions (so they feed
``add_resolver_result`` into the graph and count toward the resolution axis).
The command runner is injectable, so parsing is fully tested offline; an absent
or failing tool yields an UNRESOLVABLE result rather than raising. Ecosystems
without a wired resolver fall back to ``NullResolver``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import replace
from typing import Any, Callable

from .model import DependencyScope, DependencySpec, Ecosystem, PackageIdentity, ResolutionState
from .resolver import DependencyResolver, NullResolver, ResolverRequest, ResolverResult

# A runner takes (argv, cwd) and returns (returncode, stdout).
Runner = Callable[[list[str], str | None], tuple[int, str]]


class GoResolver:
    ecosystem = Ecosystem.GO

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or _default_runner

    def resolve(self, request: ResolverRequest) -> ResolverResult:
        cwd = os.path.dirname(str(request.root_manifest)) or "."
        try:
            returncode, output = self._runner(["go", "list", "-m", "all"], cwd)
        except FileNotFoundError:
            return _unresolved(request, "go", "go not found in PATH")
        if returncode != 0:
            return _unresolved(request, "go", f"go list failed (exit {returncode})")
        resolved: list[DependencySpec] = []
        for index, line in enumerate(output.splitlines()):
            parts = line.split()
            if index == 0 or len(parts) < 2:  # main module (no version) or blank
                continue
            resolved.append(_resolved_spec(Ecosystem.GO, parts[0], parts[1], "go list -m all"))
        return ResolverResult(request, resolved=tuple(resolved), unresolved=(), tool="go")


class CargoResolver:
    ecosystem = Ecosystem.CARGO

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or _default_runner

    def resolve(self, request: ResolverRequest) -> ResolverResult:
        cwd = os.path.dirname(str(request.root_manifest)) or "."
        try:
            returncode, output = self._runner(
                ["cargo", "metadata", "--format-version", "1", "--quiet"], cwd
            )
        except FileNotFoundError:
            return _unresolved(request, "cargo", "cargo not found in PATH")
        if returncode != 0:
            return _unresolved(request, "cargo", f"cargo metadata failed (exit {returncode})")
        try:
            metadata = json.loads(output)
        except (ValueError, TypeError):
            return _unresolved(request, "cargo", "could not parse cargo metadata")
        if not isinstance(metadata, dict):
            return _unresolved(request, "cargo", "could not parse cargo metadata")
        packages = metadata.get("packages", [])
        # `cargo metadata` lists the local crate(s) too; the workspace members are
        # the package being built, not its dependencies, so drop them.
        workspace = set(metadata.get("workspace_members", []))
        resolved = [
            _resolved_spec(Ecosystem.CARGO, pkg["name"], pkg.get("version"), "cargo metadata")
            for pkg in packages
            if isinstance(pkg, dict) and pkg.get("name") and pkg.get("id") not in workspace
        ]
        return ResolverResult(request, resolved=tuple(resolved), unresolved=(), tool="cargo")


class PypiResolver:
    ecosystem = Ecosystem.PYPI

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or _default_runner

    def resolve(self, request: ResolverRequest) -> ResolverResult:
        # ``pip install --dry-run --report -`` (pip >= 22.2) writes a stable
        # JSON document to stdout describing what it *would* install -- without
        # touching the environment. We never invoke install; the dry-run is the
        # whole point of using pip as a resolver here.
        manifest = str(request.root_manifest)
        cwd = os.path.dirname(manifest) or "."
        try:
            returncode, output = self._runner(
                [
                    "pip", "install", "--dry-run", "--quiet", "--no-input",
                    "--report", "-", "-r", manifest,
                ],
                cwd,
            )
        except FileNotFoundError:
            return _unresolved(request, "pip", "pip not found in PATH")
        if returncode != 0:
            return _unresolved(request, "pip", f"pip install --dry-run failed (exit {returncode})")
        try:
            report = json.loads(output)
        except (ValueError, TypeError):
            return _unresolved(request, "pip", "could not parse pip --report JSON")
        if not isinstance(report, dict):
            return _unresolved(request, "pip", "could not parse pip --report JSON")
        installs = report.get("install", []) or []
        resolved: list[DependencySpec] = []
        for entry in installs:
            if not isinstance(entry, dict):
                continue
            meta = entry.get("metadata") or {}
            if not isinstance(meta, dict):
                continue
            name = meta.get("name")
            version = meta.get("version")
            if isinstance(name, str) and name:
                resolved.append(
                    _resolved_spec(Ecosystem.PYPI, name, version, "pip install --dry-run --report")
                )
        return ResolverResult(request, resolved=tuple(resolved), unresolved=(), tool="pip")


# ``[INFO]    com.google.guava:guava:jar:32.1.3-jre:compile`` -- mvn's
# ``dependency:list`` line. Optional classifier between packaging and version:
# ``g:a:p:classifier:v:scope`` is also accepted by Maven. We capture the four
# stable tokens (group, artifact, packaging, scope) and the version (which
# moves position when a classifier is present).
_MAVEN_DEP_LINE = re.compile(
    r"^\[INFO\]\s+"
    r"(?P<group>[A-Za-z0-9_.-]+):"
    r"(?P<artifact>[A-Za-z0-9_.-]+):"
    r"(?P<packaging>[A-Za-z0-9_-]+):"
    r"(?:(?P<classifier>[A-Za-z0-9_.-]+):)?"
    r"(?P<version>[^:\s]+):"
    r"(?P<scope>compile|runtime|provided|test|system|import)"
    r"(?:\s.*)?$"
)


class MavenResolver:
    ecosystem = Ecosystem.MAVEN

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or _default_runner

    def resolve(self, request: ResolverRequest) -> ResolverResult:
        # ``mvn -B dependency:list`` prints one ``[INFO] g:a:p:v:scope`` line
        # per resolved dependency (transitive too). ``-B`` keeps the output
        # batch-friendly; the parser tolerates Maven's optional classifier.
        cwd = os.path.dirname(str(request.root_manifest)) or "."
        try:
            returncode, output = self._runner(
                ["mvn", "-B", "-q", "dependency:list", "-DincludeScope=runtime"], cwd,
            )
        except FileNotFoundError:
            return _unresolved(request, "mvn", "mvn not found in PATH")
        if returncode != 0:
            return _unresolved(request, "mvn", f"mvn dependency:list failed (exit {returncode})")
        resolved: list[DependencySpec] = []
        for line in output.splitlines():
            match = _MAVEN_DEP_LINE.match(line)
            if not match:
                continue
            coord = f"{match.group('group')}:{match.group('artifact')}"
            resolved.append(
                _resolved_spec(
                    Ecosystem.MAVEN, coord, match.group("version"), "mvn dependency:list"
                )
            )
        return ResolverResult(request, resolved=tuple(resolved), unresolved=(), tool="mvn")


class NpmResolver:
    ecosystem = Ecosystem.NPM

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or _default_runner

    def resolve(self, request: ResolverRequest) -> ResolverResult:
        # ``npm ls --json --all`` walks the installed tree. We collect every
        # (name, version) in the dependencies tree, skipping the root package
        # itself. ``--all`` makes npm 7+ recurse into transitive deps; on
        # npm 6 the flag is silently ignored (it still emits the full tree by
        # default), so the resolver is portable across versions.
        manifest = str(request.root_manifest)
        cwd = os.path.dirname(manifest) or "."
        try:
            returncode, output = self._runner(["npm", "ls", "--json", "--all"], cwd)
        except FileNotFoundError:
            return _unresolved(request, "npm", "npm not found in PATH")
        # npm exits non-zero when peer-dep warnings exist *even though* the
        # tree it printed is valid; tolerate non-zero exits if stdout still
        # parses as a tree with packages in it. A truly empty / unparseable
        # output is the only real failure.
        try:
            tree = json.loads(output) if output else None
        except (ValueError, TypeError):
            tree = None
        if not isinstance(tree, dict):
            return _unresolved(request, "npm", f"could not parse npm ls JSON (exit {returncode})")
        resolved: list[DependencySpec] = []
        _collect_npm_deps(tree.get("dependencies"), resolved, seen=set())
        if not resolved and returncode != 0:
            return _unresolved(request, "npm", f"npm ls failed (exit {returncode})")
        return ResolverResult(request, resolved=tuple(resolved), unresolved=(), tool="npm")


def _collect_npm_deps(
    deps: Any, into: list[DependencySpec], *, seen: set[tuple[str, str | None]]
) -> None:
    if not isinstance(deps, dict):
        return
    for name, entry in deps.items():
        if not isinstance(entry, dict) or not isinstance(name, str):
            continue
        version_raw = entry.get("version")
        version = version_raw if isinstance(version_raw, str) else None
        key = (name, version)
        if key in seen:
            # npm 'requires' sub-trees can revisit the same node; record once.
            _collect_npm_deps(entry.get("dependencies"), into, seen=seen)
            continue
        seen.add(key)
        into.append(_resolved_spec(Ecosystem.NPM, name, version, "npm ls --json --all"))
        _collect_npm_deps(entry.get("dependencies"), into, seen=seen)


def resolver_for(ecosystem: Ecosystem, *, runner: Runner | None = None) -> DependencyResolver:
    """Return the wired resolver for an ecosystem, or NullResolver as fallback."""

    if ecosystem == Ecosystem.GO:
        return GoResolver(runner=runner)
    if ecosystem == Ecosystem.CARGO:
        return CargoResolver(runner=runner)
    if ecosystem == Ecosystem.PYPI:
        return PypiResolver(runner=runner)
    if ecosystem == Ecosystem.MAVEN:
        return MavenResolver(runner=runner)
    if ecosystem == Ecosystem.NPM:
        return NpmResolver(runner=runner)
    return NullResolver(ecosystem)


def _resolved_spec(
    ecosystem: Ecosystem, name: str, version: str | None, source: str
) -> DependencySpec:
    return DependencySpec(
        identity=PackageIdentity(ecosystem, name, version=version),
        scope=DependencyScope.RUNTIME,
        resolution_state=ResolutionState.RESOLVED,
        source=source,
    )


def _unresolved(request: ResolverRequest, tool: str, detail: str) -> ResolverResult:
    skipped = tuple(
        replace(spec, resolution_state=ResolutionState.UNRESOLVABLE, resolution_note=detail)
        for spec in request.requested
    )
    return ResolverResult(request, resolved=(), unresolved=skipped, tool=tool)


def _default_runner(args: list[str], cwd: str | None) -> tuple[int, str]:
    process = subprocess.run(args, check=False, text=True, capture_output=True, cwd=cwd)
    return process.returncode, (process.stdout or "")

"""Real per-ecosystem resolvers behind the ResolverResult contract (rung 5).

The authoritative tool for each ecosystem is the source of truth (CLAUDE.md), so
these shell out rather than reimplement resolution:

- ``GoResolver``    -> ``go list -m all`` (reads go.mod/go.sum)
- ``CargoResolver`` -> ``cargo metadata --format-version 1`` (reads Cargo.lock)

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
import subprocess
from dataclasses import replace
from typing import Callable

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


def resolver_for(ecosystem: Ecosystem, *, runner: Runner | None = None) -> DependencyResolver:
    """Return the wired resolver for an ecosystem, or NullResolver as fallback."""

    if ecosystem == Ecosystem.GO:
        return GoResolver(runner=runner)
    if ecosystem == Ecosystem.CARGO:
        return CargoResolver(runner=runner)
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

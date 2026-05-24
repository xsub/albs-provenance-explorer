"""Typed contract for the evidence -> resolution handoff.

This module defines *where* a real ecosystem resolver plugs in, not the
resolution logic itself. The load-bearing design rule from CLAUDE.md is that
each ecosystem's package manager is the source of truth for that ecosystem's
semantics: pip/uv, Maven/Gradle, Cargo, Go modules (MVS) and libsolv (RPM) all
have different and subtly incompatible resolution models. Reimplementing them
is how a unified tool produces answers that look right and are wrong.

So the "unified" part of the system is this contract plus the graph storage,
*not* a shared solver. A concrete resolver shells out to the authoritative
tool, captures its output, and returns :class:`ResolverResult`. The graph layer
(``albs_graph.provenance.reconcile``) turns those results into dependency
claims that can be reconciled against other evidence sources.

No real resolver is shipped here. :class:`NullResolver` resolves nothing and
marks every requested dependency ``RESOLUTION_SKIPPED`` so the boundary is
exercisable and testable offline.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from typing import Any, Protocol, runtime_checkable

from .model import DependencyContext, DependencySpec, Ecosystem, ResolutionState


@dataclass(frozen=True)
class ResolverRequest:
    """A unit of work handed to an ecosystem resolver.

    ``context`` is part of the cache key on purpose: two pip dependencies
    declared under different environment markers, or two Cargo dependencies
    under different feature sets, are not duplicates and must not collapse.
    """

    ecosystem: Ecosystem
    root_manifest: str
    requested: tuple[DependencySpec, ...] = ()
    lockfile: str | None = None
    context: DependencyContext = field(default_factory=DependencyContext)

    def cache_key(self) -> str:
        return cache_key_for(self)


@dataclass(frozen=True)
class ResolverResult:
    """The outcome of running an authoritative resolver for one request.

    ``unresolved`` is a first-class part of the result, never silently dropped.
    A resolver that returns an empty ``unresolved`` is asserting full coverage
    for this request, which downstream consumers are entitled to trust.
    """

    request: ResolverRequest
    resolved: tuple[DependencySpec, ...] = ()
    unresolved: tuple[DependencySpec, ...] = ()
    tool: str = "unknown"
    tool_version: str | None = None

    @property
    def cache_key(self) -> str:
        return self.request.cache_key()

    @property
    def resolved_fraction(self) -> float:
        total = len(self.resolved) + len(self.unresolved)
        if total == 0:
            return 0.0
        return len(self.resolved) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": str(self.request.ecosystem),
            "tool": self.tool,
            "tool_version": self.tool_version,
            "cache_key": self.cache_key,
            "resolved": [spec.to_dict() for spec in self.resolved],
            "unresolved": [spec.to_dict() for spec in self.unresolved],
            "resolved_fraction": self.resolved_fraction,
        }


@runtime_checkable
class DependencyResolver(Protocol):
    """Anything that can turn a :class:`ResolverRequest` into concrete facts.

    Implementations must not invent versions: every input spec ends up in
    exactly one of ``resolved`` / ``unresolved``. Caching is the caller's
    concern, keyed on :meth:`ResolverRequest.cache_key`; invalidation is
    registry-state driven (a yank or deletion), not age-based.
    """

    ecosystem: Ecosystem

    def resolve(self, request: ResolverRequest) -> ResolverResult: ...


class NullResolver:
    """A resolver that resolves nothing.

    Every requested dependency comes back as ``RESOLUTION_SKIPPED`` with an
    explanatory note. Useful as a baseline, for ecosystems with no resolver
    wired up yet, and for testing the contract without network access.
    """

    def __init__(self, ecosystem: Ecosystem = Ecosystem.GENERIC) -> None:
        self.ecosystem = ecosystem

    def resolve(self, request: ResolverRequest) -> ResolverResult:
        skipped = tuple(
            replace(
                spec,
                resolution_state=ResolutionState.RESOLUTION_SKIPPED,
                resolution_note=f"no resolver wired up for ecosystem {request.ecosystem}",
            )
            for spec in request.requested
        )
        return ResolverResult(
            request=request,
            resolved=(),
            unresolved=skipped,
            tool="null-resolver",
            tool_version=None,
        )


def cache_key_for(request: ResolverRequest) -> str:
    """Stable cache key over (ecosystem, manifest, lockfile, context).

    Manifest/lockfile may be paths or inline content; the caller decides. We
    hash whatever is provided so the key is fixed-length and content-sensitive.
    """

    digest = hashlib.sha256()
    digest.update(str(request.ecosystem).encode())
    digest.update(b"\0")
    digest.update(request.root_manifest.encode())
    digest.update(b"\0")
    digest.update((request.lockfile or "").encode())
    digest.update(b"\0")
    for key, value in sorted(request.context.to_dict().items()):
        digest.update(f"{key}={value}".encode())
        digest.update(b"\0")
    return f"{request.ecosystem}:{digest.hexdigest()[:32]}"

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import quote, urlencode

from albs_graph.nevra import RpmNevra


class Ecosystem(StrEnum):
    RPM = "rpm"
    PYPI = "pypi"
    MAVEN = "maven"
    GRADLE = "gradle"
    NPM = "npm"
    CARGO = "cargo"
    GO = "go"
    GENERIC = "generic"


class DependencyScope(StrEnum):
    RUNTIME = "runtime"
    BUILDTIME = "buildtime"
    TEST = "test"
    DEVELOPMENT = "development"
    OPTIONAL = "optional"
    PROVIDED = "provided"
    PLUGIN = "plugin"
    UNKNOWN = "unknown"


class Linkage(StrEnum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    INTERPRETED = "interpreted"
    UNKNOWN = "unknown"


class ResolutionState(StrEnum):
    DECLARED = "declared"
    LOCKED = "locked"
    RESOLVED = "resolved"
    OBSERVED = "observed"
    PROVIDED = "provided"
    # First-class "we could not resolve this" outcomes. A tool that only ever
    # reports success is lying about its coverage; these states let the graph
    # record *why* a concrete version was not produced.
    UNRESOLVABLE = "unresolvable"  # resolver ran, no version satisfies the constraints
    AMBIGUOUS = "ambiguous"  # multiple candidates, no mediation decision was made
    RESOLUTION_SKIPPED = "resolution_skipped"  # evidence-only; resolver never invoked


@dataclass(frozen=True)
class DependencyContext:
    os: str | None = None
    arch: str | None = None
    distro: str | None = None
    distro_version: str | None = None
    language_version: str | None = None
    extras: tuple[str, ...] = ()
    profiles: tuple[str, ...] = ()
    features: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for key, value in (
            ("os", self.os),
            ("arch", self.arch),
            ("distro", self.distro),
            ("distro_version", self.distro_version),
            ("language_version", self.language_version),
        ):
            if value:
                data[key] = value
        if self.extras:
            data["extras"] = list(self.extras)
        if self.profiles:
            data["profiles"] = list(self.profiles)
        if self.features:
            data["features"] = list(self.features)
        return data


@dataclass(frozen=True)
class PackageIdentity:
    ecosystem: Ecosystem
    name: str
    namespace: str | None = None
    version: str | None = None
    purl: str | None = None
    qualifiers: dict[str, str] = field(default_factory=dict)

    def coordinates(self) -> str:
        prefix = f"{self.namespace}/" if self.namespace else ""
        suffix = f"@{self.version}" if self.version else ""
        return f"{self.ecosystem}:{prefix}{self.name}{suffix}"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "ecosystem": str(self.ecosystem),
            "name": self.name,
            "coordinates": self.coordinates(),
        }
        if self.namespace:
            data["namespace"] = self.namespace
        if self.version:
            data["version"] = self.version
        if self.purl:
            data["purl"] = self.purl
        if self.qualifiers:
            data["qualifiers"] = self.qualifiers
        return data


@dataclass(frozen=True)
class ArtifactIdentity:
    """The packaging identity of a built RPM artifact.

    Composes an :class:`RpmNevra` with its repo namespace and distro and renders
    the canonical PURL and :class:`PackageIdentity`. This is the single place RPM
    PURLs are built, so the NEVRA, the PURL and the dependency coordinate cannot
    drift apart (the ALBS adapter used to hand-roll all three inline). The graph
    *node id* is intentionally not derived here: it is ALBS-structural (built
    from the artifact id / filename), not a property of the packaging identity.
    """

    nevra: RpmNevra
    namespace: str = "almalinux"
    distro: str | None = None
    is_srpm: bool = False  # a .src.rpm advertises arch "src" in its PURL

    @property
    def purl_arch(self) -> str | None:
        return "src" if self.is_srpm else self.nevra.arch

    def qualifiers(self) -> dict[str, str]:
        data: dict[str, str] = {}
        if self.purl_arch:
            data["arch"] = self.purl_arch
        if self.nevra.epoch:
            data["epoch"] = self.nevra.epoch
        if self.distro:
            data["distro"] = self.distro
        return data

    def purl(self) -> str:
        # Epoch rides as a qualifier, not in the PURL version (RPM convention).
        name = self.nevra.name or "unknown"
        version = self.nevra.version_release
        purl = f"pkg:rpm/{self.namespace}/{quote(name, safe='')}"
        if version:
            purl += f"@{quote(version, safe='')}"
        qualifiers = self.qualifiers()
        if qualifiers:
            purl += f"?{urlencode(sorted(qualifiers.items()))}"
        return purl

    def package_identity(self) -> PackageIdentity:
        return PackageIdentity(
            ecosystem=Ecosystem.RPM,
            name=self.nevra.name or "unknown",
            namespace=self.namespace,
            version=self.nevra.version_release,
            purl=self.purl(),
            qualifiers=self.qualifiers(),
        )


@dataclass(frozen=True)
class DependencySpec:
    identity: PackageIdentity
    requested: str | None = None
    scope: DependencyScope = DependencyScope.UNKNOWN
    linkage: Linkage = Linkage.UNKNOWN
    resolution_state: ResolutionState = ResolutionState.DECLARED
    context: DependencyContext = field(default_factory=DependencyContext)
    source: str | None = None
    resolution_note: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "identity": self.identity.to_dict(),
            "scope": str(self.scope),
            "linkage": str(self.linkage),
            "resolution_state": str(self.resolution_state),
        }
        if self.requested:
            data["requested"] = self.requested
        context = self.context.to_dict()
        if context:
            data["context"] = context
        if self.source:
            data["source"] = self.source
        if self.resolution_note:
            data["resolution_note"] = self.resolution_note
        if self.raw:
            data["raw"] = self.raw
        return data


def package_identity_from_purl(purl: str, fallback_version: str | None = None) -> PackageIdentity:
    from packageurl import PackageURL

    parsed = PackageURL.from_string(purl)
    ecosystem = _ecosystem_from_purl_type(parsed.type)
    qualifiers = {str(key): str(value) for key, value in (parsed.qualifiers or {}).items()}
    return PackageIdentity(
        ecosystem=ecosystem,
        namespace=parsed.namespace,
        name=parsed.name,
        version=parsed.version or fallback_version,
        purl=purl,
        qualifiers=qualifiers,
    )


def dependency_spec_node_id(spec: DependencySpec) -> str:
    requested = spec.requested or spec.identity.version or "any"
    safe_requested = requested.replace("/", "_").replace(" ", "_")
    return f"dep:{spec.identity.coordinates()}:{spec.scope}:{safe_requested}"


def dependency_node_metadata(spec: DependencySpec) -> dict[str, Any]:
    return {
        "dependency": spec.to_dict(),
        "ecosystem": str(spec.identity.ecosystem),
        "name": spec.identity.name,
        "namespace": spec.identity.namespace,
        "version": spec.identity.version,
        "purl": spec.identity.purl,
        "scope": str(spec.scope),
        "linkage": str(spec.linkage),
        "resolution_state": str(spec.resolution_state),
    }


def dependency_edge_metadata(spec: DependencySpec) -> dict[str, Any]:
    data = {
        "dependency": spec.to_dict(),
        "scope": str(spec.scope),
        "linkage": str(spec.linkage),
        "resolution_state": str(spec.resolution_state),
    }
    if spec.requested:
        data["requested"] = spec.requested
    return data


def _ecosystem_from_purl_type(value: str) -> Ecosystem:
    mapping = {
        "rpm": Ecosystem.RPM,
        "pypi": Ecosystem.PYPI,
        "maven": Ecosystem.MAVEN,
        "gradle": Ecosystem.GRADLE,
        "npm": Ecosystem.NPM,
        "cargo": Ecosystem.CARGO,
        "golang": Ecosystem.GO,
        "go": Ecosystem.GO,
    }
    return mapping.get(value.lower(), Ecosystem.GENERIC)

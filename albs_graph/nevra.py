"""Canonical RPM identity: NEVRA parsing and distro-tag extraction.

NEVRA (name, epoch, version, release, arch) and dist-tag logic used to be
re-implemented in every module that touched an RPM coordinate -- the ALBS
adapter, the remote-header adapter, build analysis, the dnf and rpmgraph
adapters, and the reconciler each had their own near-identical parser. Small
differences between those copies were a source of matching drift (e.g. one
stripping the epoch, another not). This module is the single leaf-level home
for that logic: it depends only on the standard library, so adapters and
provenance code can all route through it without import cycles.

It deliberately does *not* know about graphs, PURLs or CPEs -- those higher
identities (``PackageIdentity``, ``SecurityIdentity``) compose an
:class:`RpmNevra`, they do not duplicate its parsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Canonical RPM arch suffixes: the binary arches AlmaLinux builds plus ``noarch``
# and the ``src`` pseudo-arch. Used to peel a trailing ``.arch`` off a NEVRA or
# capability token (a dnf/rpmgraph label), where the arch is not dot-delimited
# from a following extension the way a filename's is.
ARCH_SUFFIXES: tuple[str, ...] = ("x86_64", "aarch64", "ppc64le", "s390x", "i686", "noarch", "src")

# RPM dist tag inside a release or version-release, e.g. ``.el9`` or ``.el10_2``.
# The leading dot anchors it, so a stray ``elNN`` inside an unrelated version
# token is never mistaken for a dist tag. Group 1 is the generation major, group
# 2 the optional minor (``el9_4`` -> major 9, minor 4).
_DISTRO_RE = re.compile(r"\.el(\d+)(?:_(\d+))?")


def distro_generation(text: str | None) -> str | None:
    """The distro *generation* tag (``el9``, ``el10``) in ``text``, or ``None``.

    Only the generation is returned, so ``el9_2`` and ``el9_4`` both yield
    ``el9`` -- callers comparing build vs dependency distro want a generation
    gap (``el9`` vs ``el10``), not a minor difference.
    """

    if not text:
        return None
    match = _DISTRO_RE.search(text)
    return f"el{match.group(1)}" if match else None


def distro_version(text: str | None) -> str | None:
    """The numeric distro version in ``text`` (``9`` or ``9.4``), or ``None``."""

    if not text:
        return None
    match = _DISTRO_RE.search(text)
    if not match:
        return None
    return f"{match.group(1)}.{match.group(2)}" if match.group(2) else match.group(1)


def rpm_metadata_from_filename(filename: str) -> dict[str, str | None]:
    """The lenient ``{filename, arch, name?, version?, release?}`` dict.

    Best-effort and forgiving: ``arch`` is set whenever the filename has a final
    dot-segment, even if the ``name-version-release`` split then fails (matching
    the long-standing ALBS / build-analysis behaviour these callers rely on).
    Use :meth:`RpmNevra.from_filename` when a structured value or strict parse
    is wanted instead.
    """

    stem = filename.removesuffix(".rpm")
    parts = stem.rsplit(".", 1)
    arch = parts[1] if len(parts) == 2 else None
    nevr = parts[0] if len(parts) == 2 else stem
    metadata: dict[str, str | None] = {"filename": filename, "arch": arch}
    name_version_release = nevr.rsplit("-", 2)
    if len(name_version_release) == 3:
        metadata |= {
            "name": name_version_release[0],
            "version": name_version_release[1],
            "release": name_version_release[2],
        }
    return metadata


def _strip_arch(token: str) -> tuple[str, str | None]:
    """Peel a known ``.arch`` suffix off a NEVRA/capability token."""

    for arch in ARCH_SUFFIXES:
        if token.endswith("." + arch):
            return token[: -(len(arch) + 1)], arch
    return token, None


@dataclass(frozen=True)
class RpmNevra:
    """A parsed RPM coordinate: name, epoch, version, release, arch.

    The two constructors cover the two real-world inputs:

    * :meth:`from_filename` -- a canonical ``name-version-release.arch.rpm``
      filename (no epoch is ever encoded in a filename).
    * :meth:`from_token` -- a dnf/rpmgraph NEVRA label or an RPM capability
      string (``name >= 1:2.3``), which may carry an epoch and a comparison tail.
    """

    name: str
    epoch: str | None = None
    version: str | None = None
    release: str | None = None
    arch: str | None = None

    @property
    def version_release(self) -> str | None:
        """``version-release`` (no epoch), or ``None`` if neither is known."""

        if self.version and self.release:
            return f"{self.version}-{self.release}"
        return self.version or self.release

    @property
    def evr(self) -> str | None:
        """``[epoch:]version-release`` -- the concrete version most tools report."""

        version_release = self.version_release
        if version_release is None:
            return None
        return f"{self.epoch}:{version_release}" if self.epoch else version_release

    @property
    def distro(self) -> str | None:
        """The distro generation (``el9`` / ``el10``) from the release."""

        return distro_generation(self.release) or distro_generation(self.version)

    @property
    def distro_version(self) -> str | None:
        """The numeric distro version (``9`` / ``9.4``) from the release."""

        return distro_version(self.release) or distro_version(self.version)

    @classmethod
    def from_filename(cls, filename: str) -> RpmNevra | None:
        """Parse ``name-version-release.arch.rpm``; ``None`` if not that shape.

        Strict: both the trailing ``.arch`` and the three ``name-version-release``
        components must be present. Filenames are canonical NVRA, so no epoch is
        parsed and no digit heuristic is needed.
        """

        stem = filename.removesuffix(".rpm")
        parts = stem.rsplit(".", 1)
        if len(parts) != 2:
            return None
        nevr, arch = parts
        name_version_release = nevr.rsplit("-", 2)
        if len(name_version_release) != 3:
            return None
        name, version, release = name_version_release
        return cls(name=name, version=version, release=release, arch=arch)

    @classmethod
    def from_token(cls, token: str) -> RpmNevra:
        """Parse a dnf/rpmgraph NEVRA label or an RPM capability token.

        A capability tail (``name >= 1:2.3``) is dropped; a bare name yields just
        the name; an epoch embedded in the version segment (``1:3.0.7``) is split
        out. A token that does not look like ``name-version-release`` (no digit in
        the version slot) is treated as a bare name -- never a partial parse.
        """

        head = token.split()[0] if token.split() else token
        base, arch = _strip_arch(head)
        parts = base.rsplit("-", 2)
        if len(parts) == 3 and any(char.isdigit() for char in parts[1]):
            name, version_segment, release = parts
            if ":" in version_segment:
                epoch, version = version_segment.split(":", 1)
            else:
                epoch, version = None, version_segment
            return cls(name=name, epoch=epoch, version=version, release=release, arch=arch)
        return cls(name=head)

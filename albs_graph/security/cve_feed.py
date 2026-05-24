"""CVE feed matching: verified CPE + version -> potentially-applicable CVEs.

This completes the vulnerability story. A1 verifies a package's CPE; this module
takes a supplied CVE feed (each CVE lists affected `(vendor, product)` configs
with optional `introduced` / `fixed` version bounds, mirroring NVD's
versionStartIncluding / versionEndExcluding) and reports which CVEs' affected
ranges include the package's version.

Version comparison uses an rpmvercmp-style algorithm (the same segment rules
RPM/DNF use), so ranges are evaluated correctly rather than by string equality.

The feed is supplied (offline, testable); pointing it at a real NVD/OSV export
is a drop-in. The `distro_backport` flag from A1 still matters: a backported
package keeps its upstream version, so a range match may be a false positive
(the fix was backported without a version bump) — the report carries that
caveat rather than this module silently trusting the version.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from albs_graph.vercmp import version_compare

__all__ = [
    "CveAffected",
    "CveEntry",
    "CveFeed",
    "version_compare",
]


@dataclass(frozen=True)
class CveAffected:
    vendor: str
    product: str
    introduced: str | None = None  # >= (inclusive)
    fixed: str | None = None  # < (exclusive)

    def matches(self, vendor: str, product: str, version: str) -> bool:
        if self.vendor not in ("*", vendor) or self.product not in ("*", product):
            return False
        if self.introduced is not None and version_compare(version, self.introduced) < 0:
            return False
        if self.fixed is not None and version_compare(version, self.fixed) >= 0:
            return False
        return True


@dataclass(frozen=True)
class CveEntry:
    id: str
    affected: tuple[CveAffected, ...] = ()

    def matches(self, vendor: str, product: str, version: str) -> bool:
        return any(config.matches(vendor, product, version) for config in self.affected)


@dataclass(frozen=True)
class CveFeed:
    entries: tuple[CveEntry, ...] = field(default_factory=tuple)

    @classmethod
    def from_entries(cls, raw: list[dict[str, Any]]) -> CveFeed:
        entries: list[CveEntry] = []
        for item in raw:
            cve_id = str(item.get("id") or item.get("cve") or "")
            if not cve_id:
                continue
            affected = tuple(
                CveAffected(
                    vendor=str(cfg.get("vendor", "*")),
                    product=str(cfg.get("product", "*")),
                    introduced=_opt(cfg.get("introduced")),
                    fixed=_opt(cfg.get("fixed")),
                )
                for cfg in item.get("affected", [])
                if isinstance(cfg, dict)
            )
            entries.append(CveEntry(id=cve_id, affected=affected))
        return cls(entries=tuple(entries))

    @classmethod
    def from_file(cls, path: str | Path) -> CveFeed:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        raw = data.get("cves", data) if isinstance(data, dict) else data
        return cls.from_entries(list(raw))

    def match(self, vendor: str, product: str, version: str) -> list[str]:
        return sorted(
            entry.id for entry in self.entries if entry.matches(vendor, product, version)
        )


def _opt(value: Any) -> str | None:
    return str(value) if value else None

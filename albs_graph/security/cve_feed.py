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


def version_compare(left: str, right: str) -> int:
    """Compare two version strings rpmvercmp-style. Returns -1, 0, or 1."""

    if left == right:
        return 0
    i = j = 0
    n, m = len(left), len(right)
    while i < n and j < m:
        while i < n and not (left[i].isalnum() or left[i] == "~"):
            i += 1
        while j < m and not (right[j].isalnum() or right[j] == "~"):
            j += 1
        # tilde sorts before everything (pre-release marker).
        left_tilde = i < n and left[i] == "~"
        right_tilde = j < m and right[j] == "~"
        if left_tilde or right_tilde:
            if not left_tilde:
                return 1
            if not right_tilde:
                return -1
            i += 1
            j += 1
            continue
        if i >= n or j >= m:
            break
        if left[i].isdigit():
            if not right[j].isdigit():
                return 1  # numeric segment outranks alphabetic
            i, j, result = _compare_run(left, right, i, j, str.isdigit, numeric=True)
        else:
            if right[j].isdigit():
                return -1
            i, j, result = _compare_run(left, right, i, j, str.isalpha, numeric=False)
        if result != 0:
            return result
    # whatever still has an alnum segment left is the greater (unless it is ~).
    while i < n and not (left[i].isalnum() or left[i] == "~"):
        i += 1
    while j < m and not (right[j].isalnum() or right[j] == "~"):
        j += 1
    if i < n and j >= m:
        return -1 if left[i] == "~" else 1
    if j < m and i >= n:
        return 1 if right[j] == "~" else -1
    return 0


def _compare_run(
    left: str,
    right: str,
    i: int,
    j: int,
    predicate: Any,
    *,
    numeric: bool,
) -> tuple[int, int, int]:
    i2, j2 = i, j
    while i2 < len(left) and predicate(left[i2]):
        i2 += 1
    while j2 < len(right) and predicate(right[j2]):
        j2 += 1
    seg_left, seg_right = left[i:i2], right[j:j2]
    if numeric:
        seg_left = seg_left.lstrip("0") or "0"
        seg_right = seg_right.lstrip("0") or "0"
        if len(seg_left) != len(seg_right):
            return i2, j2, 1 if len(seg_left) > len(seg_right) else -1
    if seg_left != seg_right:
        return i2, j2, 1 if seg_left > seg_right else -1
    return i2, j2, 0


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

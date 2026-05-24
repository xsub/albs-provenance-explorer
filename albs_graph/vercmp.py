"""rpmvercmp-style version comparison — a neutral, dependency-free utility.

Lives at the package root (depends on nothing) so both the security layer
(CVE range matching) and the provenance layer (reconciler drift/range checks)
can use it without odd cross-layer imports.

The algorithm follows RPM's rpmvercmp segment rules: a version is split into
maximal runs of digits or letters; digit runs compare numerically (leading
zeros stripped, longer run wins), letter runs compare lexically, a digit run
outranks a letter run, and ``~`` marks a pre-release that sorts *before*
everything (so ``1.0~rc1 < 1.0``).
"""

from __future__ import annotations

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

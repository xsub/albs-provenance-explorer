"""CPE verification against a CPE dictionary (the `identity` coverage axis).

The graph stores `cpe: null` plus unverified `cpe_candidates` and must never
assert an official CPE without a verification step (CLAUDE.md). This module is
that step: given a CPE dictionary (the set of official `(vendor, product)`
pairs, e.g. from the NVD CPE dictionary), it confirms a candidate's product,
resolves the official vendor, and flips the candidate to `verified=True` /
populates `cpe`. Only then does a package count toward the `identity` axis.

It also records a **distro-backport** flag: an AlmaLinux release like
`16.el9_4.1` ships upstream version `1.20.1` with backported patches, so naive
version-vs-CVE matching is misleading. The flag is consumed by the
vulnerability-applicability report.

The dictionary is supplied (a JSON file or an explicit set), so verification is
fully offline and testable; pointing it at a real NVD CPE export is a drop-in.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from albs_graph.model import Node, NodeType, ProvenanceGraph

_BACKPORT_RELEASE = re.compile(r"\.el\d")
NodeSelector = Callable[[Node], bool]


@dataclass(frozen=True)
class CpeDictionary:
    """Official `(vendor, product)` entries, indexed product -> sorted vendors."""

    products: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_cpe23(cls, cpe23_entries: list[str]) -> CpeDictionary:
        products: dict[str, set[str]] = {}
        for entry in cpe23_entries:
            parts = entry.split(":")
            if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
                continue
            vendor, product = parts[3], parts[4]
            if vendor and product and vendor != "*" and product != "*":
                products.setdefault(product, set()).add(vendor)
        return cls(products={product: sorted(vendors) for product, vendors in products.items()})

    @classmethod
    def from_file(cls, path: str | Path) -> CpeDictionary:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = data.get("cpes", data) if isinstance(data, dict) else data
        return cls.from_cpe23([str(item) for item in entries])

    def vendors_for(self, product: str) -> list[str]:
        return self.products.get(product, [])


@dataclass(frozen=True)
class CpeVerificationResult:
    binaries: int
    verified: int
    ambiguous: int
    unmatched: int
    backported: int

    def to_dict(self) -> dict[str, int]:
        return {
            "binaries": self.binaries,
            "verified": self.verified,
            "ambiguous": self.ambiguous,
            "unmatched": self.unmatched,
            "backported": self.backported,
        }


def verify_security_identity(identity: dict[str, Any], dictionary: CpeDictionary) -> str:
    """Verify a security_identity dict in place. Returns the resulting cpe_status.

    Status is one of: ``verified`` (one vendor matched, ``cpe`` set),
    ``ambiguous_vendor`` (several vendors), or the prior ``candidate_only``.
    """

    candidates = identity.get("cpe_candidates")
    if not isinstance(candidates, list):
        return str(identity.get("cpe_status", "unresolved"))
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        product = str(candidate.get("product") or "")
        vendors = dictionary.vendors_for(product)
        if not vendors:
            continue
        if len(vendors) == 1:
            vendor = vendors[0]
            version = str(candidate.get("version") or "*")
            cpe23 = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
            candidate["verified"] = True
            candidate["vendor"] = vendor
            candidate["cpe23"] = cpe23
            candidate["source"] = "nvd_cpe_dictionary"
            identity["cpe"] = cpe23
            identity["cpe_status"] = "verified"
            identity["cpe_source"] = "nvd_cpe_dictionary"
            return "verified"
        identity["cpe_status"] = "ambiguous_vendor"
        identity["cpe_vendor_candidates"] = vendors
    return str(identity.get("cpe_status", "candidate_only"))


def verify_graph_cpe(
    graph: ProvenanceGraph,
    dictionary: CpeDictionary,
    *,
    node_selector: NodeSelector | None = None,
) -> CpeVerificationResult:
    """Verify CPE candidates on binary RPM nodes; flag distro backports."""

    binaries = verified = ambiguous = unmatched = backported = 0
    for node in graph.find_by_type(NodeType.BINARY_RPM):
        if node_selector and not node_selector(node):
            continue
        original = node.metadata.get("security_identity")
        if not isinstance(original, dict):
            continue
        binaries += 1
        # Mutate a *deep* copy and route the final state through update_metadata.
        # Two reasons (both real regressions, reviewed):
        #   1. dry-run isolation -- a dry_run wrapping ``graph.copy()`` only works
        #      if every adapter writes through the graph's mutation API; an
        #      in-place mutation of ``identity`` (or a nested candidate dict) on
        #      a shallowly-shared object leaks back into the source graph.
        #   2. EvidencePatch capture -- ``RecordingGraph`` records writes only
        #      when an adapter calls ``add_node`` / ``add_edge`` / ``update_metadata``;
        #      in-place dict mutation bypasses all three, so the CPE change went
        #      missing from the patch.
        identity = deepcopy(original)
        release = str(node.metadata.get("release") or "")
        if _BACKPORT_RELEASE.search(release):
            identity["distro_backport"] = True
            backported += 1
        status = verify_security_identity(identity, dictionary)
        if status == "verified":
            verified += 1
        elif status == "ambiguous_vendor":
            ambiguous += 1
        else:
            unmatched += 1
        graph.update_metadata(node.id, {"security_identity": identity})
    return CpeVerificationResult(binaries, verified, ambiguous, unmatched, backported)

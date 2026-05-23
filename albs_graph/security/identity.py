from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CpeCandidate:
    cpe23: str
    part: str = "a"
    vendor: str = "*"
    product: str = "*"
    version: str = "*"
    source: str = "rpm_name_version_candidate"
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpe23": self.cpe23,
            "part": self.part,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "source": self.source,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class SecurityIdentity:
    purl: str | None = None
    cpe: str | None = None
    cpe_candidates: tuple[CpeCandidate, ...] = field(default_factory=tuple)
    cpe_status: str = "unresolved"
    cpe_source: str = "not_mapped_to_official_dictionary"
    identity_source: str = "purl_with_cpe_candidates"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "cpe": self.cpe,
            "cpe_candidates": [candidate.to_dict() for candidate in self.cpe_candidates],
            "cpe_status": self.cpe_status,
            "cpe_source": self.cpe_source,
            "identity_source": self.identity_source,
        }
        if self.purl:
            data["purl"] = self.purl
        return data


def cpe_security_identity(
    name: str | None,
    version: str | None,
    *,
    purl: str | None = None,
) -> dict[str, Any]:
    if not name:
        return SecurityIdentity(
            purl=purl,
            cpe_status="unresolved",
            cpe_source="missing_package_name",
        ).to_dict()

    product = _cpe_token(name)
    candidate = CpeCandidate(
        cpe23=_candidate_cpe23(name, version),
        product=product,
        version=_cpe_token(version) if version else "*",
    )
    return SecurityIdentity(
        purl=purl,
        cpe_candidates=(candidate,),
        cpe_status="candidate_only",
    ).to_dict()


def _candidate_cpe23(name: str, version: str | None) -> str:
    product = _cpe_token(name)
    version_token = _cpe_token(version) if version else "*"
    return f"cpe:2.3:a:*:{product}:{version_token}:*:*:*:*:*:*:*"


def _cpe_token(value: str | None) -> str:
    if not value:
        return "*"
    normalized = value.strip().lower()
    normalized = re.sub(r"[^a-z0-9._-]+", "_", normalized)
    return normalized or "*"

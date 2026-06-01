"""Offline tests for on-demand CVE details (D134): the pure NVD/OSV parsers and
the NVD-first / OSV-fallback fetch through an injected fetcher (no network)."""

from __future__ import annotations

import json

from albs_graph.security.cve_details import (
    fetch_cve_details,
    parse_nvd_cve,
    parse_osv_vuln,
)

_NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1234",
                "published": "2024-02-01T00:00:00",
                "descriptions": [
                    {"lang": "es", "value": "uno"},
                    {"lang": "en", "value": "A buffer overflow in foo."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L",
                            }
                        }
                    ]
                },
                "references": [{"url": "https://example.test/advisory"}],
            }
        }
    ]
}

_OSV = {
    "id": "CVE-2024-1234",
    "summary": "short",
    "details": "OSV details for foo.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
    "references": [{"url": "https://osv.dev/vulnerability/CVE-2024-1234"}],
}


def test_parse_nvd_cve_extracts_english_description_and_cvss() -> None:
    details = parse_nvd_cve(_NVD, "CVE-2024-1234")
    assert details is not None
    assert details.description == "A buffer overflow in foo."  # English, not Spanish
    assert details.cvss_score == 7.5
    assert details.severity == "HIGH"
    assert details.source == "nvd"
    assert "https://example.test/advisory" in details.references


def test_parse_osv_vuln_uses_details_and_cvss_vector() -> None:
    details = parse_osv_vuln(_OSV, "CVE-2024-1234")
    assert details is not None
    assert details.description == "OSV details for foo."
    assert details.cvss_vector == "CVSS:3.1/AV:N/AC:L"
    assert details.source == "osv"


def test_fetch_cve_details_prefers_nvd_and_appends_canonical_links() -> None:
    def fetcher(url: str) -> bytes:
        assert "nvd.nist.gov" in url  # NVD is tried first
        return json.dumps(_NVD).encode()

    details = fetch_cve_details("CVE-2024-1234", fetcher=fetcher)
    assert details.source == "nvd"
    assert details.description == "A buffer overflow in foo."
    assert any("nvd.nist.gov/vuln/detail" in url for url in details.references)
    assert any("access.redhat.com/security/cve" in url for url in details.references)  # upstream
    assert any("errata.almalinux.org" in url for url in details.references)


def test_fetch_cve_details_falls_back_to_osv_when_nvd_empty() -> None:
    def fetcher(url: str) -> bytes:
        if "nvd.nist.gov" in url:
            return json.dumps({"vulnerabilities": []}).encode()  # NVD knows nothing
        return json.dumps(_OSV).encode()

    details = fetch_cve_details("CVE-2024-1234", fetcher=fetcher)
    assert details.source == "osv"
    assert details.description == "OSV details for foo."


def test_fetch_cve_details_degrades_gracefully_when_offline() -> None:
    def fetcher(_url: str) -> bytes:
        raise OSError("offline")

    details = fetch_cve_details("CVE-2024-1234", fetcher=fetcher)
    assert not details.has_content  # nothing reachable
    assert details.id == "CVE-2024-1234"
    # still hands the user canonical links to follow
    assert any("nvd.nist.gov" in url for url in details.references)
    assert any("errata.almalinux.org" in url for url in details.references)

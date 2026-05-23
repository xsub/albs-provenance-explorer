from __future__ import annotations

from albs_graph.security import cpe_security_identity


def test_cpe_security_identity_keeps_candidates_unverified() -> None:
    identity = cpe_security_identity(
        "OpenSSL-libs",
        "3.2.1",
        purl="pkg:rpm/almalinux/openssl-libs@3.2.1-1.el10?arch=x86_64",
    )

    assert identity["purl"] == "pkg:rpm/almalinux/openssl-libs@3.2.1-1.el10?arch=x86_64"
    assert identity["cpe"] is None
    assert identity["cpe_status"] == "candidate_only"
    assert identity["cpe_source"] == "not_mapped_to_official_dictionary"
    assert identity["cpe_candidates"] == [
        {
            "cpe23": "cpe:2.3:a:*:openssl-libs:3.2.1:*:*:*:*:*:*:*",
            "part": "a",
            "vendor": "*",
            "product": "openssl-libs",
            "version": "3.2.1",
            "source": "rpm_name_version_candidate",
            "verified": False,
        }
    ]


def test_cpe_security_identity_records_missing_package_name() -> None:
    identity = cpe_security_identity(None, None, purl="pkg:rpm/almalinux/unknown")

    assert identity["purl"] == "pkg:rpm/almalinux/unknown"
    assert identity["cpe_candidates"] == []
    assert identity["cpe_status"] == "unresolved"
    assert identity["cpe_source"] == "missing_package_name"

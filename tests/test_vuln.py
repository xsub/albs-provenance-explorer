from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.provenance import vulnerability_report
from albs_graph.security.cve_feed import CveFeed


def _graph() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:nginx-core",
            NodeType.BINARY_RPM,
            "nginx-core",
            {
                "name": "nginx-core",
                "arch": "x86_64",
                "release": "16.el9_4.1",
                "security_identity": {
                    "cpe": "cpe:2.3:a:nginx:nginx-core:1.20.1:*:*:*:*:*:*:*",
                    "cpe_status": "verified",
                    "distro_backport": True,
                    "cpe_candidates": [],
                },
                "elf_analysis": {"dlopen": ["./usr/sbin/nginx"], "static": []},
            },
        )
    )
    graph.add_node(Node("errata:ALSA-2026-1", NodeType.ERRATA, "ALSA-2026-1", {}))
    graph.add_edge("rpm:nginx-core", "errata:ALSA-2026-1", Relation.FIXES)
    graph.add_node(Node("cve:CVE-2026-1", NodeType.CVE, "CVE-2026-1", {}))
    graph.add_edge("errata:ALSA-2026-1", "cve:CVE-2026-1", Relation.FIXES)
    # a package with no CVEs / no identity / no linkage
    graph.add_node(Node("rpm:zlib", NodeType.BINARY_RPM, "zlib", {"name": "zlib", "arch": "x86_64"}))
    return graph


def test_report_combines_cve_identity_and_linkage() -> None:
    report = vulnerability_report(_graph())
    by_package = {pkg.package: pkg for pkg in report.packages}

    nginx = by_package["nginx-core"]
    assert nginx.addressed_cves == ["CVE-2026-1"]
    assert nginx.errata == ["ALSA-2026-1"]
    # NVD-verified identity satisfies *both* axes (established AND externally
    # verified). The old single ``identity_verified`` flag conflated them.
    assert nginx.identity_established is True
    assert nginx.identity_externally_verified is True
    assert nginx.distro_backport is True
    assert nginx.version_match_reliable is False  # backported -> version match unreliable
    assert nginx.dlopen is True
    assert report.addressed_cve_count == 1
    assert "zlib" in by_package  # included when not filtering


def test_vendor_asserted_cpe_is_distinct_from_nvd_verified() -> None:
    # A vendor (alma-sbom) CPE establishes identity but is NOT NVD-verified; the
    # report must keep the two evidence strengths distinct, not blur them.
    graph = ProvenanceGraph()
    graph.add_node(
        Node(
            "rpm:bootupd",
            NodeType.BINARY_RPM,
            "bootupd",
            {
                "name": "bootupd",
                "arch": "x86_64",
                "security_identity": {
                    "cpe": "cpe:2.3:a:almalinux:bootupd:0.2.32:*:*:*:*:*:*:*",
                    "cpe_status": "vendor_asserted",
                    "cpe_source": "almalinux_sbom",
                    "cpe_candidates": [],
                },
            },
        )
    )

    pkg = {p.package: p for p in vulnerability_report(graph).packages}["bootupd"]

    assert pkg.cpe == "cpe:2.3:a:almalinux:bootupd:0.2.32:*:*:*:*:*:*:*"  # usable for triage
    assert pkg.cpe_status == "vendor_asserted"
    # Identity IS established (a CPE is set, usable for CVE matching) but is
    # NOT externally verified -- the asserter is the vendor, not NVD.
    assert pkg.identity_established is True
    assert pkg.identity_externally_verified is False


def test_only_with_cves_filters() -> None:
    report = vulnerability_report(_graph(), only_with_cves=True)
    assert {pkg.package for pkg in report.packages} == {"nginx-core"}


def test_feed_match_reports_potentially_affected_excluding_addressed() -> None:
    feed = CveFeed.from_entries(
        [
            # already addressed by errata -> must NOT appear as potentially-affected
            {"id": "CVE-2026-1", "affected": [{"vendor": "nginx", "product": "nginx-core", "fixed": "2.0"}]},
            # not addressed, affected range includes 1.20.1 -> potentially-affected
            {"id": "CVE-2026-9", "affected": [{"vendor": "nginx", "product": "nginx-core", "fixed": "2.0"}]},
        ]
    )
    report = vulnerability_report(_graph(), cve_feed=feed)
    nginx = {pkg.package: pkg for pkg in report.packages}["nginx-core"]

    assert nginx.potentially_affected_cves == ["CVE-2026-9"]
    assert "CVE-2026-1" not in nginx.potentially_affected_cves  # addressed -> excluded
    assert report.potentially_affected_count == 1

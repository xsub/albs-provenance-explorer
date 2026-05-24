from albs_graph.security.cve_feed import CveFeed, version_compare


def test_version_compare_ordering() -> None:
    assert version_compare("1.20.1", "1.21.0") < 0
    assert version_compare("1.21.0", "1.20.1") > 0
    assert version_compare("1.20.1", "1.20.1") == 0
    assert version_compare("1.2.11", "1.2.3") > 0  # 11 > 3 numerically
    assert version_compare("1.0", "1.0.1") < 0  # longer tail is greater
    assert version_compare("1.0.1", "1.0") > 0
    assert version_compare("2.0", "10.0") < 0  # numeric, not lexical


def test_version_compare_tilde_is_prerelease() -> None:
    assert version_compare("1.0~rc1", "1.0") < 0  # ~ sorts before release
    assert version_compare("1.0", "1.0~rc1") > 0


_FEED = CveFeed.from_entries(
    [
        {"id": "CVE-A", "affected": [{"vendor": "nginx", "product": "nginx", "fixed": "1.21.0"}]},
        {
            "id": "CVE-B",
            "affected": [
                {"vendor": "nginx", "product": "nginx", "introduced": "1.20.0", "fixed": "1.20.1"}
            ],
        },
        {"id": "CVE-C", "affected": [{"vendor": "*", "product": "nginx"}]},  # any version/vendor
    ]
)


def test_feed_match_respects_ranges_and_wildcards() -> None:
    # 1.20.1: < 1.21.0 (A), == fixed of B so excluded, C matches everything.
    assert _FEED.match("nginx", "nginx", "1.20.1") == ["CVE-A", "CVE-C"]
    # 1.21.0: A fixed (excluded), B no, C yes.
    assert _FEED.match("nginx", "nginx", "1.21.0") == ["CVE-C"]
    # wrong vendor: only the "*"-vendor entry matches.
    assert _FEED.match("other", "nginx", "1.20.1") == ["CVE-C"]
    # wrong product: nothing.
    assert _FEED.match("nginx", "openssl", "1.20.1") == []

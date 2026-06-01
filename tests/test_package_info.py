"""Offline tests for on-demand package info (D140): the ``dnf --info`` parser and
the dnf-first / RPM-header-fallback fetch via an injected runner + a monkeypatched
header path (no network, no shelling out)."""

from __future__ import annotations

import pytest

from albs_graph.adapters import package_info as pi
from albs_graph.adapters.package_info import fetch_package_info, parse_dnf_info
from albs_graph.adapters.rpm_header import RpmHeader

_DNF_INFO = """\
Name        : nginx-core
Version     : 1.26.3
Release     : 6.el10_2.3
Architecture: x86_64
Summary     : nginx HTTP and proxy server core files
URL         : https://nginx.org/
License     : BSD-2-Clause
Description : The nginx-core package contains the core files
            : required to run the nginx web server.
"""


def test_parse_dnf_info_reads_fields_and_wrapped_description() -> None:
    fields = parse_dnf_info(_DNF_INFO)
    assert fields["summary"] == "nginx HTTP and proxy server core files"
    assert fields["url"] == "https://nginx.org/"  # value keeps its own colon
    assert fields["license"] == "BSD-2-Clause"
    assert fields["description"].startswith("The nginx-core package contains the core files")
    assert "run the nginx web server." in fields["description"]  # continuation joined


def test_fetch_package_info_prefers_dnf() -> None:
    def runner(args: list[str]) -> tuple[int, str]:
        assert "repoquery" in args and "--info" in args
        return 0, _DNF_INFO

    info = fetch_package_info("nginx-core", dnf_runner=runner)
    assert info.source == "dnf"
    assert info.summary == "nginx HTTP and proxy server core files"
    assert info.license == "BSD-2-Clause"


def test_fetch_package_info_falls_back_to_rpm_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pi, "dnf_available", lambda: False)  # no host dnf
    monkeypatch.setattr(pi, "vault_candidate_urls", lambda _f: ["https://mirror/x.rpm"])
    header = RpmHeader(
        name="nginx-core",
        version="1.26.3",
        release="6.el10_2.3",
        arch="x86_64",
        sourcerpm=None,
        requires=(),
        provides=(),
        header_bytes=0,
        summary="nginx core files",
        description="The core files.",
        url="https://nginx.org/",
        license="BSD-2-Clause",
    )
    monkeypatch.setattr(pi, "fetch_rpm_header", lambda _url, _fetch: header)
    info = fetch_package_info(
        "nginx-core",
        rpm_filename="nginx-core-1.26.3-6.el10_2.3.x86_64.rpm",
        range_fetcher=lambda _u, _s, _e: b"",
    )
    assert info.source.startswith("rpm header")
    assert info.summary == "nginx core files"
    assert info.url == "https://nginx.org/"


def test_fetch_package_info_degrades_when_nothing_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pi, "dnf_available", lambda: False)
    info = fetch_package_info("nginx-core")  # no dnf, no rpm filename
    assert not info.has_content
    assert info.name == "nginx-core"

"""Live errata source + three-state errata status (D79).

No network: HTTP feed is read from an injected fetcher / a temp file; the dnf
source uses an injected runner. The three-state outcome (advisory_present /
confirmed_clean / not_checked) is asserted both on the source result and
through the graph's trust_path_report.
"""

from __future__ import annotations

import json
from pathlib import Path

from albs_graph.adapters._http_cache import HttpCache
from albs_graph.adapters.errata_source import (
    DnfErrataSource,
    ErrataAdvisory,
    HttpErrataSource,
    almalinux_errata_feed_url,
    almalinux_major_version,
    attach_errata_cross_checked,
    attach_errata_from_source,
    errata_source_for,
)
from albs_graph.model import Node, NodeType, ProvenanceGraph, Relation
from albs_graph.nevra import RpmNevra
from albs_graph.pipeline import EnrichmentContext, ErrataSourceStep, RunSpec


def _el_graph(*releases: str) -> ProvenanceGraph:
    graph = ProvenanceGraph()
    for index, release in enumerate(releases):
        graph.add_node(
            Node(
                f"rpm:{index}",
                NodeType.BINARY_RPM,
                f"pkg{index}",
                {"name": f"pkg{index}", "release": release, "arch": "x86_64"},
            )
        )
    return graph


def test_almalinux_major_version_picks_the_dominant_el_token() -> None:
    graph = _el_graph("16.el9_4.1", "14.el9_2", "3.el9", "1.el8")  # el9 dominates
    assert almalinux_major_version(graph) == "9"
    assert almalinux_major_version(ProvenanceGraph()) is None  # nothing to infer


def test_almalinux_errata_feed_url_is_the_canonical_feed() -> None:
    assert almalinux_errata_feed_url("9") == "https://errata.almalinux.org/9/errata.full.json"
    assert almalinux_errata_feed_url(10) == "https://errata.almalinux.org/10/errata.full.json"


def test_errata_step_defaults_http_feed_to_almalinux(monkeypatch) -> None:
    # "http" with no feed/URL must default to the official AlmaLinux feed for the
    # build's own distro version, derived from the RPM releases.
    captured: dict[str, object] = {}

    def _recorder(kind, *, feed_file, url, ttl_seconds, on_progress):
        captured["kind"] = kind
        captured["url"] = url
        return None  # short-circuit: the step logs "skipping" and returns

    monkeypatch.setattr("albs_graph.pipeline.errata_source_for", _recorder)
    graph = _el_graph("16.el9_4.1", "14.el9_2")
    ctx = EnrichmentContext(
        graph=graph,
        spec=RunSpec(errata_source="http"),
        selector=lambda _node: True,
        on_progress=None,
    )

    ErrataSourceStep().run(ctx)

    assert captured["kind"] == "http"
    assert captured["url"] == "https://errata.almalinux.org/9/errata.full.json"

_FEED = {
    "data": [
        {
            "id": "ALSA-2026:0001",
            "type": "security",
            "severity": "Important",
            "references": [
                {"id": "CVE-2026-1111", "type": "cve"},
                {"id": "RHSA-1", "type": "self"},  # non-cve ref -> ignored
            ],
            "packages": [
                {"name": "nginx-core", "version": "1.20.1", "release": "16.el9_4", "arch": "x86_64"}
            ],
        },
        {
            "id": "ALSA-2026:0002",
            "type": "bugfix",
            "packages": [
                {"name": "zlib", "version": "1.2.11", "release": "40.el9", "arch": "x86_64"}
            ],
            "cves": ["CVE-2026-2222"],  # flat cves list form
        },
    ]
}


def _feed_bytes() -> bytes:
    return json.dumps(_FEED).encode()


# ---- HttpErrataSource --------------------------------------------------------


def test_http_source_matches_exact_nevra_and_extracts_cve(tmp_path: Path) -> None:
    feed = tmp_path / "errata.json"
    feed.write_bytes(_feed_bytes())
    source = HttpErrataSource(feed_file=feed)

    assert source.consulted is True
    advisories = source.advisories_for(
        RpmNevra(name="nginx-core", version="1.20.1", release="16.el9_4", arch="x86_64")
    )
    assert len(advisories) == 1
    assert advisories[0].id == "ALSA-2026:0001"
    assert advisories[0].type == "security"
    assert advisories[0].severity == "Important"
    assert advisories[0].cves == ("CVE-2026-1111",)  # non-cve reference filtered out


def test_http_source_flat_cves_list_is_read(tmp_path: Path) -> None:
    feed = tmp_path / "errata.json"
    feed.write_bytes(_feed_bytes())
    source = HttpErrataSource(feed_file=feed)
    advisories = source.advisories_for(
        RpmNevra(name="zlib", version="1.2.11", release="40.el9", arch="x86_64")
    )
    assert advisories[0].cves == ("CVE-2026-2222",)


def test_http_source_does_not_match_a_different_version(tmp_path: Path) -> None:
    # Same name, different release -> NOT this advisory's build (the advisory
    # ships a specific NEVRA; an older/newer build is not it).
    feed = tmp_path / "errata.json"
    feed.write_bytes(_feed_bytes())
    source = HttpErrataSource(feed_file=feed)
    assert source.advisories_for(
        RpmNevra(name="nginx-core", version="1.20.1", release="1.el9_0", arch="x86_64")
    ) == []


def test_http_source_tolerates_top_level_list_and_errata_key() -> None:
    # The feed may be a bare list or {"errata": [...]}, not only {"data": [...]}.
    bare = json.dumps(_FEED["data"]).encode()
    src_bare = HttpErrataSource(feed_file=None, url="x", fetcher=lambda _u: bare,
                                cache=HttpCache(enabled=False))
    assert src_bare.consulted
    assert src_bare.advisories_for(
        RpmNevra(name="zlib", version="1.2.11", release="40.el9", arch="x86_64")
    )

    keyed = json.dumps({"errata": _FEED["data"]}).encode()
    src_keyed = HttpErrataSource(feed_file=None, url="x", fetcher=lambda _u: keyed,
                                 cache=HttpCache(enabled=False))
    assert src_keyed.advisories_for(
        RpmNevra(name="nginx-core", version="1.20.1", release="16.el9_4", arch="x86_64")
    )


def test_http_source_via_url_through_injected_fetcher(tmp_path: Path) -> None:
    cache = HttpCache(root=tmp_path / "c", enabled=True)
    source = HttpErrataSource(url="https://example.invalid/errata.json",
                              fetcher=lambda _u: _feed_bytes(), cache=cache)
    assert source.consulted
    assert source.advisories_for(
        RpmNevra(name="zlib", version="1.2.11", release="40.el9", arch="x86_64")
    )


def test_http_source_network_failure_is_not_consulted(tmp_path: Path) -> None:
    def _boom(_url: str) -> bytes:
        raise OSError("connection refused")

    source = HttpErrataSource(url="https://example.invalid/errata.json", fetcher=_boom,
                              cache=HttpCache(root=tmp_path / "c", enabled=True))
    # Unreachable feed -> not consulted, so the graph stays "not_checked".
    assert source.consulted is False
    assert source.advisories_for(RpmNevra(name="nginx-core")) == []


# ---- DnfErrataSource ---------------------------------------------------------


_DNF_OUTPUT = """\
ALSA-2026:0001 Important/Sec.  nginx-core-1:1.20.1-16.el9_4.x86_64
ALSA-2026:0002 bugfix          zlib-1.2.11-40.el9.x86_64
"""


def test_dnf_source_parses_updateinfo_columns() -> None:
    source = DnfErrataSource(runner=lambda _args: (0, _DNF_OUTPUT))
    assert source.consulted is True

    nginx = source.advisories_for(
        RpmNevra(name="nginx-core", version="1.20.1", release="16.el9_4", arch="x86_64")
    )
    assert len(nginx) == 1
    assert nginx[0].id == "ALSA-2026:0001"
    assert nginx[0].type == "security"
    assert nginx[0].severity == "Important"

    zlib = source.advisories_for(
        RpmNevra(name="zlib", version="1.2.11", release="40.el9", arch="x86_64")
    )
    assert zlib[0].type == "bugfix"
    assert zlib[0].severity is None


def test_dnf_source_missing_tool_is_not_consulted() -> None:
    # An injected runner that raises FileNotFoundError mimics dnf being absent.
    def _missing(_args: list[str]) -> tuple[int, str]:
        raise FileNotFoundError("dnf")

    source = DnfErrataSource(runner=_missing)
    assert source.consulted is False


def test_dnf_source_nonzero_exit_is_not_consulted() -> None:
    source = DnfErrataSource(runner=lambda _a: (1, "error"))
    assert source.consulted is False


# ---- factory -----------------------------------------------------------------


def test_factory_routes_kinds_and_feed_file_implies_http(tmp_path: Path) -> None:
    feed = tmp_path / "errata.json"
    feed.write_bytes(_feed_bytes())

    assert isinstance(errata_source_for("http", feed_file=feed), HttpErrataSource)
    assert isinstance(errata_source_for("dnf", runner=lambda _a: (0, "")), DnfErrataSource)
    # feed_file with no explicit kind still builds the HTTP source.
    assert isinstance(errata_source_for(None, feed_file=feed), HttpErrataSource)
    # No kind, no feed -> None (nothing requested).
    assert errata_source_for(None) is None


# ---- attach + three-state ----------------------------------------------------


def _rpm(node_id: str, name: str, version: str, release: str, arch: str = "x86_64") -> Node:
    return Node(
        node_id,
        NodeType.BINARY_RPM,
        f"{name}-{version}-{release}.{arch}.rpm",
        {"name": name, "version": version, "release": release, "arch": arch},
    )


def _graph_two_rpms() -> ProvenanceGraph:
    graph = ProvenanceGraph()
    graph.add_node(_rpm("rpm:nginx", "nginx-core", "1.20.1", "16.el9_4"))
    graph.add_node(_rpm("rpm:bash", "bash", "5.1.8", "9.el9"))  # not in the feed
    return graph


def test_attach_records_advisory_present_and_confirmed_clean(tmp_path: Path) -> None:
    feed = tmp_path / "errata.json"
    feed.write_bytes(_feed_bytes())
    graph = _graph_two_rpms()

    result = attach_errata_from_source(graph, HttpErrataSource(feed_file=feed))

    assert result.consulted is True
    assert result.queried == 2
    assert result.with_advisory == 1   # nginx-core
    assert result.clean == 1           # bash (consulted, no advisory)
    assert result.advisories_added == 1

    # nginx-core got a real errata node + FIXES edge + the CVE.
    assert any(
        e.relation == Relation.FIXES and e.source == "rpm:nginx" for e in graph.edges
    )
    assert "errata:ALSA-2026:0001" in graph.nodes
    assert "cve:CVE-2026-1111" in graph.nodes
    # bash got the confirmed_clean marker, no errata node.
    assert graph.nodes["rpm:bash"].metadata["errata_status"] == "confirmed_clean"


def test_three_state_in_trust_path_report(tmp_path: Path) -> None:
    feed = tmp_path / "errata.json"
    feed.write_bytes(_feed_bytes())
    graph = _graph_two_rpms()

    # Before consulting any source: both are not_checked.
    assert graph.trust_path_report("rpm:nginx").errata_status == "not_checked"
    assert graph.trust_path_report("rpm:bash").errata_status == "not_checked"

    attach_errata_from_source(graph, HttpErrataSource(feed_file=feed))

    nginx = graph.trust_path_report("rpm:nginx")
    bash = graph.trust_path_report("rpm:bash")
    assert nginx.errata_status == "advisory_present"
    assert bash.errata_status == "confirmed_clean"
    # Both now satisfy has_errata_link (a clean package is NOT 'missing').
    assert nginx.security_context_checks["has_errata_link"] is True
    assert bash.security_context_checks["has_errata_link"] is True
    # has_errata_link no longer appears in the missing list for the clean pkg.
    assert "has_errata_link" not in bash.missing_security_context


def test_not_consulted_source_leaves_nodes_not_checked() -> None:
    # A source that could not be reached must not mark anything clean -- that
    # would be a lie ("we checked") when nothing was queried.
    def _boom(_url: str) -> bytes:
        raise OSError("down")

    graph = _graph_two_rpms()
    source = HttpErrataSource(url="x", fetcher=_boom, cache=HttpCache(enabled=False))
    result = attach_errata_from_source(graph, source)

    assert result.consulted is False
    assert result.queried == 0
    assert graph.trust_path_report("rpm:bash").errata_status == "not_checked"
    assert "errata_status" not in graph.nodes["rpm:bash"].metadata


def test_confirmed_clean_plus_sbom_completes_security_context(tmp_path: Path) -> None:
    # The headline of D79: a clean package WITH an SBOM is security-context
    # complete -- it is not penalised for lacking an advisory it should not have.
    feed = tmp_path / "errata.json"
    feed.write_bytes(_feed_bytes())
    graph = ProvenanceGraph()
    graph.add_node(_rpm("rpm:bash", "bash", "5.1.8", "9.el9"))
    graph.add_node(Node("sbom:bash", NodeType.SBOM, "bash.cdx.json", {}))
    graph.add_edge("rpm:bash", "sbom:bash", Relation.DESCRIBED_BY)

    # Before: has SBOM but errata not checked -> incomplete.
    assert graph.trust_path_report("rpm:bash").security_context_complete is False

    attach_errata_from_source(graph, HttpErrataSource(feed_file=feed))

    # After: confirmed clean + SBOM -> complete.
    assert graph.trust_path_report("rpm:bash").security_context_complete is True


def test_advisory_dataclass_shape() -> None:
    adv = ErrataAdvisory(id="ALSA-1", type="security", severity="Low", cves=("CVE-1",))
    assert adv.id == "ALSA-1" and adv.cves == ("CVE-1",)


def test_advisory_to_cve_edge_is_not_duplicated_across_rpms() -> None:
    # One advisory covering several RPMs is the same advisory->CVE fact: the
    # CVE node must accrue ONE "fixes" edge, not one per RPM (the bug that made a
    # CVE node sprout dozens of identical edges).
    graph = _el_graph("1.el9", "1.el9")  # rpm:0/pkg0, rpm:1/pkg1
    advisory = ErrataAdvisory(id="ALSA-9", cves=("CVE-1",))
    source = _FakeErrataSource("almalinux-errata-feed", {"pkg0": [advisory], "pkg1": [advisory]})

    attach_errata_from_source(graph, source)

    cve_edges = [e for e in graph.outgoing("errata:ALSA-9") if e.target == "cve:CVE-1"]
    assert len(cve_edges) == 1  # one advisory -> CVE edge, not one per RPM
    rpm_edges = [e for e in graph.incoming("errata:ALSA-9") if e.relation == Relation.FIXES]
    assert len(rpm_edges) == 2  # each RPM still links to the advisory (legitimate)


class _FakeErrataSource:
    """A minimal in-memory ErrataSource for cross-check tests (no I/O)."""

    def __init__(
        self,
        name: str,
        advisories: dict[str, list[ErrataAdvisory]],
        consulted: bool = True,
    ) -> None:
        self.name = name
        self._advisories = advisories
        self._consulted = consulted

    @property
    def consulted(self) -> bool:
        return self._consulted

    def advisories_for(self, nevra: RpmNevra) -> list[ErrataAdvisory]:
        return list(self._advisories.get(nevra.name, []))


def _fixes_edge_to(
    graph: ProvenanceGraph, rpm_id: str, errata_id: str
) -> dict[str, object] | None:
    for edge in graph.outgoing(rpm_id):
        if edge.target == errata_id and edge.relation == Relation.FIXES:
            return edge.metadata
    return None


def test_cross_check_marks_agreement_and_flags_single_source() -> None:
    # pkg0 carries ALSA-1 (both sources agree -> cross-checked) and ALSA-2
    # (only the web feed -> a single-source discrepancy).
    graph = _el_graph("1.el9")  # one rpm: rpm:0 / pkg0
    alsa1 = ErrataAdvisory(id="ALSA-1", type="security", cves=("CVE-1",))
    alsa2 = ErrataAdvisory(id="ALSA-2", type="bugfix")
    web = _FakeErrataSource("almalinux-errata-feed", {"pkg0": [alsa1, alsa2]})
    dnf = _FakeErrataSource("dnf-updateinfo", {"pkg0": [alsa1]})

    result = attach_errata_cross_checked(graph, [web, dnf])

    assert result.consulted and result.queried == 1 and result.with_advisory == 1
    assert result.corroborated == 1 and result.single_source == 1
    # ALSA-1: both agreed -> cross_checked on the node *and* the per-RPM edge.
    assert graph.nodes["errata:ALSA-1"].metadata["cross_checked"] is True
    assert graph.nodes["errata:ALSA-1"].metadata["sources"] == [
        "almalinux-errata-feed",
        "dnf-updateinfo",
    ]
    assert _fixes_edge_to(graph, "rpm:0", "errata:ALSA-1")["cross_checked"] is True
    # ALSA-2: one source only -> not cross-checked.
    assert graph.nodes["errata:ALSA-2"].metadata["cross_checked"] is False
    assert _fixes_edge_to(graph, "rpm:0", "errata:ALSA-2")["cross_checked"] is False
    # The RPM is not fully cross-checked because one advisory is single-source.
    assert graph.nodes["rpm:0"].metadata["errata_cross_checked"] is False


def test_cross_check_confirmed_clean_when_both_agree_clean() -> None:
    # Neither source ships pkg0 -> both agree it is advisory-free: confirmed_clean
    # with errata_cross_checked True (a corroborated clean result).
    graph = _el_graph("1.el9")
    web = _FakeErrataSource("almalinux-errata-feed", {})
    dnf = _FakeErrataSource("dnf-updateinfo", {})

    result = attach_errata_cross_checked(graph, [web, dnf])

    assert result.clean == 1 and result.with_advisory == 0
    meta = graph.nodes["rpm:0"].metadata
    assert meta["errata_status"] == "confirmed_clean"
    assert meta["errata_cross_checked"] is True
    assert graph.trust_path_report("rpm:0").errata_status == "confirmed_clean"


def test_cross_check_degrades_to_single_consulted_source() -> None:
    # dnf unreachable (not consulted) -> the cross-check runs on the web feed
    # alone; its advisory is recorded but not marked corroborated.
    graph = _el_graph("1.el9")
    web = _FakeErrataSource("almalinux-errata-feed", {"pkg0": [ErrataAdvisory(id="ALSA-9")]})
    dnf = _FakeErrataSource("dnf-updateinfo", {}, consulted=False)  # e.g. dnf absent

    result = attach_errata_cross_checked(graph, [web, dnf])

    assert result.sources == ["almalinux-errata-feed"]  # only the consulted source
    assert result.corroborated == 0 and result.single_source == 1
    assert graph.nodes["errata:ALSA-9"].metadata["cross_checked"] is False


def test_errata_step_both_routes_to_cross_check(monkeypatch) -> None:
    # errata_source="both" consults web + dnf and returns a cross-check result.
    web = _FakeErrataSource("almalinux-errata-feed", {"pkg0": [ErrataAdvisory(id="ALSA-1")]})
    dnf = _FakeErrataSource("dnf-updateinfo", {"pkg0": [ErrataAdvisory(id="ALSA-1")]})

    def _factory(kind, **_kwargs):
        return {"http": web, "dnf": dnf}.get(kind)

    monkeypatch.setattr("albs_graph.pipeline.errata_source_for", _factory)
    graph = _el_graph("1.el9")  # rpm:0 / pkg0
    ctx = EnrichmentContext(
        graph=graph,
        spec=RunSpec(errata_source="both"),
        selector=lambda _node: True,
        on_progress=None,
    )

    result = ErrataSourceStep().run(ctx)

    assert result.corroborated == 1  # both sources agreed on ALSA-1
    assert graph.nodes["errata:ALSA-1"].metadata["cross_checked"] is True

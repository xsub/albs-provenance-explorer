"""Live arch builder: enumerate repos + repograph each + merge (D77).

Tests inject a fake repo runner so they never touch the network or dnf;
each test controls the dot text returned per repo (and which repos fail).
"""

from __future__ import annotations

from pathlib import Path

from albs_graph.adapters.arch_builder import (
    DEFAULT_REPOS,
    ArchUniverseResult,
    RepoFetch,
    build_arch_universe_live,
)
from albs_graph.adapters.rpmgraph import RpmgraphUnavailable
from albs_graph.store import load_graph, save_graph

# Two repos worth of repograph dots: appstream's nginx-core -> openssl-libs;
# baseos's openssl-libs -> glibc. Merging stitches them through openssl-libs
# (so the universe walks nginx-core -> openssl-libs -> glibc).
_APPSTREAM_DOT = """\
digraph appstream {
"nginx-core" -> "openssl-libs"
"nginx-core" -> "glibc"
}
"""
_BASEOS_DOT = """\
digraph baseos {
"openssl-libs" -> "glibc"
"bash" -> "glibc"
}
"""


def _runner(mapping: dict[str, str]) -> "callable[[str], str]":
    def _run(repo: str) -> str:
        if repo not in mapping:
            raise RpmgraphUnavailable(f"no dot for {repo}")
        return mapping[repo]

    return _run


def test_default_repos_match_well_known_almalinux_release_lists() -> None:
    # The default registry is the documented per-release repo set; the test
    # locks the keys/values in so an accidental drop is caught.
    assert DEFAULT_REPOS["9"] == ("baseos", "appstream", "crb", "extras", "plus")
    assert DEFAULT_REPOS["10"] == ("baseos", "appstream", "crb", "extras")


def test_release_picks_default_repo_list_when_no_explicit_repos() -> None:
    runner = _runner({"baseos": _BASEOS_DOT, "appstream": _APPSTREAM_DOT})

    # AlmaLinux 10's default list is (baseos, appstream, crb, extras). We
    # only supply dots for two of them; the other two skip with the
    # "no dot" message. The build still finishes and the merged universe
    # contains the two repos that worked.
    result = build_arch_universe_live(release="10", runner=runner)

    repos_seen = [fetch.repo for fetch in result.repos]
    assert repos_seen == ["baseos", "appstream", "crb", "extras"]
    assert result.succeeded == 2
    assert result.failed == 2


def test_explicit_repos_override_release_default() -> None:
    runner = _runner({"baseos": _BASEOS_DOT, "appstream": _APPSTREAM_DOT})
    result = build_arch_universe_live(
        release="10",  # should be ignored
        repos=("baseos", "appstream"),
        runner=runner,
    )
    assert [fetch.repo for fetch in result.repos] == ["baseos", "appstream"]


def test_merged_universe_links_across_repos() -> None:
    # The merge stitches nodes by id, so a cross-repo chain becomes walkable.
    # nginx-core (appstream) -> openssl-libs (shared id) -> glibc (baseos).
    runner = _runner({"baseos": _BASEOS_DOT, "appstream": _APPSTREAM_DOT})
    result = build_arch_universe_live(
        repos=("baseos", "appstream"), runner=runner
    )
    # Both binaries reachable through the merged graph.
    labels = {node.label for node in result.universe.nodes.values()}
    assert {"nginx-core", "openssl-libs", "glibc", "bash"} <= labels
    # The connecting edge (nginx-core -> openssl-libs) survived the merge.
    edge_pairs = {(e.source, e.target) for e in result.universe.edges}
    assert ("pkg:nginx-core", "pkg:openssl-libs") in edge_pairs
    assert ("pkg:openssl-libs", "pkg:glibc") in edge_pairs


def test_repo_failure_records_error_and_does_not_crash() -> None:
    def _runner(repo: str) -> str:
        if repo == "baseos":
            return _BASEOS_DOT
        raise RpmgraphUnavailable(f"dnf failed for {repo}")

    result = build_arch_universe_live(repos=("baseos", "appstream"), runner=_runner)
    assert result.succeeded == 1
    assert result.failed == 1
    failure = next(fetch for fetch in result.repos if fetch.repo == "appstream")
    assert failure.error is not None
    assert "appstream" in failure.error
    # baseos still contributed nodes.
    assert any(n.label == "glibc" for n in result.universe.nodes.values())


def test_unexpected_runner_error_is_caught_not_propagated() -> None:
    # Any exception from the runner (not just RpmgraphUnavailable) must
    # degrade to a failed fetch -- otherwise a one-repo glitch crashes the
    # whole build, defeating the "never fatal" rule.
    def _runner(_repo: str) -> str:
        raise RuntimeError("filesystem full")

    result = build_arch_universe_live(repos=("baseos",), runner=_runner)
    assert result.failed == 1
    failure = result.repos[0]
    assert failure.error is not None
    assert "filesystem full" in failure.error


def test_no_repos_no_release_yields_empty_universe_no_runner_calls() -> None:
    # Bare invocation: nothing to fetch -> empty universe + empty repo list.
    # The runner must never be called.
    calls = {"n": 0}

    def _runner(_repo: str) -> str:
        calls["n"] += 1
        return ""

    result = build_arch_universe_live(runner=_runner)
    assert calls["n"] == 0
    assert result.repos == []
    assert len(result.universe.nodes) == 0


def test_arch_filter_is_passed_through_to_universe_from_dot() -> None:
    # universe_from_dot accepts arch=...; the builder must forward it so an
    # arch-restricted call drops non-matching nodes. The simple dot here has
    # no arch suffix in the tokens, so arch=x86_64 should still let it
    # through (universe_from_dot's filter only fires on tokens that *carry*
    # an arch suffix); record the arch on the result for downstream use.
    runner = _runner({"baseos": _BASEOS_DOT})
    result = build_arch_universe_live(arch="x86_64", repos=("baseos",), runner=runner)
    assert result.arch == "x86_64"


def test_round_trip_through_sqlite_store(tmp_path: Path) -> None:
    # Save the merged universe to the SQLite backend and read it back.
    # This is the wiring D77 promises: build live, persist with D74's store.
    runner = _runner({"baseos": _BASEOS_DOT, "appstream": _APPSTREAM_DOT})
    result = build_arch_universe_live(
        repos=("baseos", "appstream"), runner=runner
    )
    db = tmp_path / "u.db"
    save_graph(result.universe, db)
    loaded = load_graph(db)
    assert set(loaded.nodes) == set(result.universe.nodes)
    assert len(loaded.edges) == len(result.universe.edges)


def test_result_to_dict_carries_all_fields() -> None:
    runner = _runner({"baseos": _BASEOS_DOT})
    result = build_arch_universe_live(
        arch="x86_64", release="10", repos=("baseos", "appstream"), runner=runner
    )
    data = result.to_dict()
    assert data["arch"] == "x86_64"
    assert data["release"] == "10"
    assert data["succeeded"] == 1
    assert data["failed"] == 1
    # Per-repo dict carries repo name, edge count, error (None on success).
    repos = {entry["repo"]: entry for entry in data["repos"]}
    assert repos["baseos"]["error"] is None
    assert repos["baseos"]["edges"] > 0
    assert repos["appstream"]["error"] is not None


def test_result_is_a_dataclass_with_universe_attribute() -> None:
    # Sanity: ArchUniverseResult is the public dataclass; tests check shape.
    result = ArchUniverseResult(arch=None, release=None, universe=load_graph_placeholder())
    assert isinstance(result.repos, list)
    assert result.succeeded == 0 and result.failed == 0


def load_graph_placeholder() -> "object":
    from albs_graph.model import ProvenanceGraph

    return ProvenanceGraph()


def test_repo_fetch_dataclass_fields() -> None:
    # RepoFetch is exposed so callers can iterate failures programmatically.
    fetch = RepoFetch(repo="baseos", edges=42)
    assert fetch.repo == "baseos" and fetch.edges == 42 and fetch.error is None
    failed = RepoFetch(repo="crb", edges=0, error="dnf missing")
    assert failed.error == "dnf missing"

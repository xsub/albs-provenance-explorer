"""Live arch builder: enumerate repos for an arch + repograph each + merge.

The single primitives are old news -- ``dnf repograph --repo X`` (D32+) emits
one repo's dependency graph; ``universe_from_dot`` parses it; ``merge_graphs``
unions many; ``store.save_graph(.., mode="merge")`` (D74) persists. This
module is the *wiring*: for a given (release, arch), run repograph against
every known repo, merge the dots into one ProvenanceGraph, and hand it back
for rendering / persistence.

Repo enumeration is intentionally a small constant per release rather than
``dnf repolist`` parsing, for predictability: the well-known AlmaLinux
release repos are stable and documented. A caller can always override with
their own list.

Tools are optional: a missing or failing ``dnf`` for one repo records a
failure in :class:`ArchUniverseResult` and the build proceeds with the rest
(matches the cas/dnf/rpmkeys "degrade, never fatal" pattern). With every
repo failing the result still returns -- with an empty graph and the full
failure list -- so the caller can decide whether to render an empty universe
or surface the errors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from albs_graph.model import ProvenanceGraph
from albs_graph.provenance.universe import merge_graphs, universe_from_dot

from .rpmgraph import RpmgraphUnavailable, run_repograph

Progress = Callable[[str], None] | None
# A repograph runner takes a repo name and returns its dot text (or raises
# RpmgraphUnavailable). The default delegates to ``run_repograph``.
RepoRunner = Callable[[str], str]


# Well-known AlmaLinux release repos. The list is intentionally small and
# documented (rather than parsed from `dnf repolist`) so a caller without a
# live dnf host can still target the right enumeration. Order follows the
# upstream documentation's listing.
DEFAULT_REPOS: dict[str, tuple[str, ...]] = {
    "9": ("baseos", "appstream", "crb", "extras", "plus"),
    "10": ("baseos", "appstream", "crb", "extras"),
}


@dataclass(frozen=True)
class RepoFetch:
    repo: str
    edges: int
    error: str | None = None  # None == success; str == reason for skip


@dataclass
class ArchUniverseResult:
    arch: str | None
    release: str | None
    universe: ProvenanceGraph
    repos: list[RepoFetch] = field(default_factory=list)

    @property
    def succeeded(self) -> int:
        return sum(1 for f in self.repos if f.error is None)

    @property
    def failed(self) -> int:
        return sum(1 for f in self.repos if f.error is not None)

    def to_dict(self) -> dict[str, object]:
        return {
            "arch": self.arch,
            "release": self.release,
            "nodes": len(self.universe.nodes),
            "edges": len(self.universe.edges),
            "succeeded": self.succeeded,
            "failed": self.failed,
            "repos": [
                {"repo": fetch.repo, "edges": fetch.edges, "error": fetch.error}
                for fetch in self.repos
            ],
        }


def build_arch_universe_live(
    *,
    arch: str | None = None,
    release: str | None = None,
    repos: tuple[str, ...] | None = None,
    runner: RepoRunner | None = None,
    on_progress: Progress = None,
) -> ArchUniverseResult:
    """Run ``dnf repograph --repo X`` for every repo + merge into one universe.

    Repo selection: explicit ``repos`` wins; otherwise ``DEFAULT_REPOS[release]``;
    otherwise an empty list (the caller didn't tell us what to fetch and we
    can't guess). ``runner`` is injectable so tests run offline.
    """

    resolved_repos = _resolve_repos(repos, release)
    do_run = runner or _default_runner
    universe = ProvenanceGraph()
    component_graphs: list[ProvenanceGraph] = []
    fetches: list[RepoFetch] = []
    for repo in resolved_repos:
        if on_progress:
            on_progress(f"Fetching {repo} dependency graph (dnf repograph --repo {repo})")
        try:
            dot = do_run(repo)
        except RpmgraphUnavailable as exc:
            fetches.append(RepoFetch(repo=repo, edges=0, error=str(exc)))
            continue
        except Exception as exc:  # noqa: BLE001 -- live tool failure must not crash
            fetches.append(RepoFetch(repo=repo, edges=0, error=f"unexpected: {exc}"))
            continue
        component = universe_from_dot(dot, arch=arch)
        component_graphs.append(component)
        fetches.append(RepoFetch(repo=repo, edges=len(component.edges)))
    if component_graphs:
        universe = merge_graphs(component_graphs)
    return ArchUniverseResult(
        arch=arch, release=release, universe=universe, repos=fetches
    )


def _resolve_repos(
    repos: tuple[str, ...] | None, release: str | None
) -> tuple[str, ...]:
    if repos:
        return repos
    if release and release in DEFAULT_REPOS:
        return DEFAULT_REPOS[release]
    return ()


def _default_runner(repo: str) -> str:
    return run_repograph(repo)

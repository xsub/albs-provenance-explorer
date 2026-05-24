from albs_graph.dependency import (
    DependencyContext,
    DependencySpec,
    Ecosystem,
    NullResolver,
    PackageIdentity,
    ResolutionState,
    ResolverRequest,
    cache_key_for,
)


def _spec(name: str, version: str | None = None) -> DependencySpec:
    return DependencySpec(identity=PackageIdentity(Ecosystem.PYPI, name, version=version))


def test_null_resolver_marks_everything_resolution_skipped() -> None:
    request = ResolverRequest(
        ecosystem=Ecosystem.PYPI,
        root_manifest="pyproject.toml",
        requested=(_spec("requests"), _spec("urllib3")),
    )

    result = NullResolver(Ecosystem.PYPI).resolve(request)

    assert result.resolved == ()
    assert len(result.unresolved) == 2
    assert all(
        spec.resolution_state == ResolutionState.RESOLUTION_SKIPPED for spec in result.unresolved
    )
    assert all(spec.resolution_note for spec in result.unresolved)
    # A null resolver claims zero coverage, never a false 100%.
    assert result.resolved_fraction == 0.0


def test_cache_key_is_context_sensitive() -> None:
    base = ResolverRequest(
        ecosystem=Ecosystem.PYPI,
        root_manifest="pyproject.toml",
        lockfile="poetry.lock",
        context=DependencyContext(os="linux", extras=("gpu",)),
    )
    same = ResolverRequest(
        ecosystem=Ecosystem.PYPI,
        root_manifest="pyproject.toml",
        lockfile="poetry.lock",
        context=DependencyContext(os="linux", extras=("gpu",)),
    )
    different_context = ResolverRequest(
        ecosystem=Ecosystem.PYPI,
        root_manifest="pyproject.toml",
        lockfile="poetry.lock",
        context=DependencyContext(os="linux", extras=("cpu",)),
    )

    assert cache_key_for(base) == cache_key_for(same)
    # Two deps under different markers/extras must not share a cache entry.
    assert cache_key_for(base) != cache_key_for(different_context)
    assert base.cache_key().startswith("pypi:")


def test_resolver_result_serializes_resolved_and_unresolved() -> None:
    request = ResolverRequest(ecosystem=Ecosystem.CARGO, root_manifest="Cargo.toml")
    result = NullResolver(Ecosystem.CARGO).resolve(
        ResolverRequest(
            ecosystem=Ecosystem.CARGO,
            root_manifest="Cargo.toml",
            requested=(_spec("serde", "1.0.0"),),
        )
    )

    data = result.to_dict()

    assert data["ecosystem"] == "cargo"
    assert data["tool"] == "null-resolver"
    assert data["cache_key"] == request.cache_key()
    assert len(data["unresolved"]) == 1

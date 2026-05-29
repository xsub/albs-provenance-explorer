"""SBOM auto-discovery (D78): file-convention fallback when --build-sbom is absent.

ALBS metadata (build.json) does not carry an SBOM URL: the SBOM is produced
separately by ``alma-sbom`` and dropped near the cache by convention. These
tests pin the discovery rules: sibling of --cache wins, then one level up,
then ``examples/``. No cas, no network -- just file lookup.
"""

from __future__ import annotations

from pathlib import Path

from albs_graph.adapters.sbom import discover_build_sbom


def test_discover_finds_sbom_in_cache_sibling_directory(tmp_path: Path) -> None:
    # The example--full.sh layout: cache at examples/live-build-N/build-N.albs.json,
    # SBOM at examples/live-build-N/build-N.cyclonedx.json (sibling of the cache).
    cache_dir = tmp_path / "live-build-42"
    cache_dir.mkdir()
    cache = cache_dir / "build-42.albs.json"
    cache.write_text("{}", encoding="utf-8")
    sbom = cache_dir / "build-42.cyclonedx.json"
    sbom.write_text("{}", encoding="utf-8")

    assert discover_build_sbom(42, cache_path=cache) == sbom


def test_discover_finds_sbom_one_level_up_from_cache(tmp_path: Path) -> None:
    # The other example--full.sh layout: cache at examples/live-build-N/build-N.albs.json,
    # SBOM at examples/build-N.cyclonedx.json (parent of the cache directory).
    cache_dir = tmp_path / "live-build-42"
    cache_dir.mkdir()
    cache = cache_dir / "build-42.albs.json"
    cache.write_text("{}", encoding="utf-8")
    sbom = tmp_path / "build-42.cyclonedx.json"
    sbom.write_text("{}", encoding="utf-8")

    assert discover_build_sbom(42, cache_path=cache) == sbom


def test_discover_prefers_cache_sibling_over_parent(tmp_path: Path) -> None:
    # Both layouts exist simultaneously; the sibling wins (it is the more
    # specific co-location, and matches what example--full.sh writes first).
    cache_dir = tmp_path / "live-build-42"
    cache_dir.mkdir()
    cache = cache_dir / "build-42.albs.json"
    cache.write_text("{}", encoding="utf-8")
    sibling = cache_dir / "build-42.cyclonedx.json"
    sibling.write_text("{}", encoding="utf-8")
    parent = tmp_path / "build-42.cyclonedx.json"
    parent.write_text("{}", encoding="utf-8")

    assert discover_build_sbom(42, cache_path=cache) == sibling


def test_discover_falls_back_to_search_dirs_when_cache_neighbours_empty(
    tmp_path: Path,
) -> None:
    # The default search path is ``examples/`` (relative); a caller can pass
    # alternate dirs. The SBOM lives there, not next to the cache.
    cache_dir = tmp_path / "live-build-42"
    cache_dir.mkdir()
    cache = cache_dir / "build-42.albs.json"
    cache.write_text("{}", encoding="utf-8")
    examples_dir = tmp_path / "examples"
    examples_dir.mkdir()
    sbom = examples_dir / "build-42.cyclonedx.json"
    sbom.write_text("{}", encoding="utf-8")

    found = discover_build_sbom(
        42, cache_path=cache, search_dirs=(examples_dir,)
    )
    assert found == sbom


def test_discover_returns_none_when_no_sbom_anywhere(tmp_path: Path) -> None:
    # The user simply does not have an SBOM -- the function returns None (the
    # CLI then runs without the SBOM, exactly like --build-sbom was omitted).
    cache_dir = tmp_path / "live-build-42"
    cache_dir.mkdir()
    cache = cache_dir / "build-42.albs.json"
    cache.write_text("{}", encoding="utf-8")

    assert discover_build_sbom(42, cache_path=cache, search_dirs=()) is None


def test_discover_returns_none_without_cache_when_search_dirs_have_no_sbom(
    tmp_path: Path,
) -> None:
    # No --cache path is given. Discovery checks only the explicit search_dirs,
    # finds nothing, and returns None -- no crash, no exception.
    assert discover_build_sbom(42, cache_path=None, search_dirs=(tmp_path,)) is None


def test_discover_filename_includes_build_id_so_runs_dont_collide(tmp_path: Path) -> None:
    # Two builds caching to the same directory must not see each other's
    # SBOMs: the filename is keyed on build_id (build-N.cyclonedx.json).
    cache = tmp_path / "build-100.albs.json"
    cache.write_text("{}", encoding="utf-8")
    (tmp_path / "build-100.cyclonedx.json").write_text("{}", encoding="utf-8")
    (tmp_path / "build-200.cyclonedx.json").write_text("{}", encoding="utf-8")

    # Asking for 100 picks 100's SBOM; asking for 999 finds nothing.
    assert discover_build_sbom(100, cache_path=cache) == tmp_path / "build-100.cyclonedx.json"
    assert discover_build_sbom(999, cache_path=cache) is None


def test_discover_ignores_directories_with_matching_name(tmp_path: Path) -> None:
    # A directory named build-42.cyclonedx.json (not a file) must not be
    # picked up -- the helper checks ``is_file()``.
    cache = tmp_path / "build-42.albs.json"
    cache.write_text("{}", encoding="utf-8")
    bogus = tmp_path / "build-42.cyclonedx.json"
    bogus.mkdir()  # a directory, not the SBOM file

    assert discover_build_sbom(42, cache_path=cache, search_dirs=()) is None


def test_cli_helper_explicit_flag_wins_over_discovery(tmp_path: Path) -> None:
    # When --build-sbom FILE is given explicitly, the helper must not look at
    # the cache directory at all -- the user said "use this file", period.
    from albs_graph.cli.main import _resolve_build_sbom

    cache_dir = tmp_path / "live-build-42"
    cache_dir.mkdir()
    cache = cache_dir / "build-42.albs.json"
    cache.write_text("{}", encoding="utf-8")
    # An SBOM exists at the conventional location AND the user passed a different one.
    (cache_dir / "build-42.cyclonedx.json").write_text("{}", encoding="utf-8")
    explicit = tmp_path / "user-supplied.cyclonedx.json"
    explicit.write_text("{}", encoding="utf-8")

    result = _resolve_build_sbom(
        explicit, 42, cache=cache, auto=True, verbose=False
    )
    assert result == explicit  # explicit wins; discovery never ran


def test_cli_helper_no_auto_sbom_disables_discovery(tmp_path: Path) -> None:
    # --no-auto-sbom returns None even when a discoverable SBOM exists; the
    # user explicitly opted out of the convention.
    from albs_graph.cli.main import _resolve_build_sbom

    cache_dir = tmp_path / "live-build-42"
    cache_dir.mkdir()
    cache = cache_dir / "build-42.albs.json"
    cache.write_text("{}", encoding="utf-8")
    (cache_dir / "build-42.cyclonedx.json").write_text("{}", encoding="utf-8")

    assert _resolve_build_sbom(None, 42, cache=cache, auto=False, verbose=False) is None


def test_cli_helper_returns_none_when_build_id_is_absent(tmp_path: Path) -> None:
    # --source-only invocations (no --build-id) have nothing to key the
    # discovery on; the helper returns None and the command runs without an
    # SBOM.
    from albs_graph.cli.main import _resolve_build_sbom

    assert _resolve_build_sbom(None, None, cache=None, auto=True, verbose=False) is None

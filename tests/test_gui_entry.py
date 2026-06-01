from __future__ import annotations

from pathlib import Path

from albs_graph.gui.entry import build_parser, default_source_path


def test_default_workbench_source_exists() -> None:
    assert default_source_path().exists()


def test_workbench_parser_accepts_source_build_id_and_build_sbom() -> None:
    parser = build_parser()

    source_args = parser.parse_args(["--source", "fixture.json"])
    build_args = parser.parse_args(
        [
            "--build-id",
            "57810",
            "--build-sbom",
            "build-57810.cyclonedx.json",
            "--base-url",
            "https://example.test",
        ]
    )

    assert source_args.source == Path("fixture.json")
    assert build_args.build_id == 57810
    assert build_args.build_sbom == Path("build-57810.cyclonedx.json")
    assert build_args.base_url == "https://example.test"


def test_name_macos_app_is_a_safe_noop_without_pyobjc() -> None:
    # Renaming the macOS app menu is a no-op off macOS / when pyobjc (the `macos`
    # extra) is absent -- it must never raise (D142).
    from albs_graph.gui.entry import _name_macos_app

    _name_macos_app("ALBS Workbench")
